package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// PolicyEngine interface for accessing policy names from policy engine
type PolicyEngine interface {
	GetPolicyNames() []string
}

// PolicyStore interface for accessing policy names from policy store
type PolicyStore interface {
	GetPolicyNames() []string
}

// sessionCacheEntry represents a cached user session
type sessionCacheEntry struct {
	userInfo  *UserInfo
	expiresAt time.Time
}

// Authenticator handles OIDC authentication
type Authenticator struct {
	userinfoURL     string
	rolesClaim      string
	userClaim       string
	emailClaim      string
	sessionCacheTTL time.Duration
	logger          *logrus.Logger
	policyEngine    PolicyEngine
	policyStore     PolicyStore
	adminUsers      []string
	sessionCache    map[string]*sessionCacheEntry // token -> cached session
	cacheMutex      sync.RWMutex
}

// UserInfo contains authenticated user information
type UserInfo struct {
	Subject       string
	Email         string
	Roles         []string // Effective roles (includes all policies for admin users)
	OriginalRoles []string // Original OIDC roles (before policy expansion)
	Claims        map[string]interface{}
}

// NewOIDCAuthenticator creates a new OIDC authenticator
func NewOIDCAuthenticator(cfg config.OIDCConfig, logger *logrus.Logger, policyEngine PolicyEngine, policyStore PolicyStore, adminUsers []string) (*Authenticator, error) {
	ctx := context.Background()

	// Discover userinfo endpoint from OIDC discovery document
	userinfoURL, err := discoverUserinfoEndpoint(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover userinfo endpoint: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"userinfo_endpoint": userinfoURL,
		"session_cache_ttl": cfg.SessionCacheTTL,
	}).Info("OIDC authenticator initialized with session caching")

	return &Authenticator{
		userinfoURL:     userinfoURL,
		rolesClaim:      cfg.RolesClaim,
		userClaim:       cfg.UserClaim,
		emailClaim:      cfg.EmailClaim,
		sessionCacheTTL: cfg.SessionCacheTTL,
		logger:          logger,
		policyEngine:    policyEngine,
		policyStore:     policyStore,
		adminUsers:      adminUsers,
		sessionCache:    make(map[string]*sessionCacheEntry),
	}, nil
}

// discoverUserinfoEndpoint discovers the userinfo endpoint from OIDC discovery document
func discoverUserinfoEndpoint(ctx context.Context, issuer string) (string, error) {
	// Construct discovery document URL
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	// Make HTTP GET request to discovery document
	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() // Error ignored - best effort cleanup
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	// Parse discovery document
	var discovery struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if discovery.UserinfoEndpoint == "" {
		return "", fmt.Errorf("userinfo_endpoint not found in discovery document")
	}

	// Ensure endpoint uses HTTPS if issuer is HTTPS
	if strings.HasPrefix(issuer, "https://") && strings.HasPrefix(discovery.UserinfoEndpoint, "http://") {
		discovery.UserinfoEndpoint = strings.Replace(discovery.UserinfoEndpoint, "http://", "https://", 1)
	}

	return discovery.UserinfoEndpoint, nil
}

// VerifyAccessToken validates an access token by calling the /userinfo endpoint
// This is the standard OAuth2 pattern - access tokens are validated by the resource server
// Session caching is used to reduce calls to the userinfo endpoint
func (a *Authenticator) VerifyAccessToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	// Check session cache first
	if userInfo := a.getCachedSession(tokenString); userInfo != nil {
		a.logger.WithFields(logrus.Fields{
			"subject":      userInfo.Subject,
			"email":        userInfo.Email,
			"cache_hit":    true,
			"token_prefix": tokenString[:min(20, len(tokenString))],
		}).Debug("Using cached session, skipping userinfo call")
		return userInfo, nil
	}

	a.logger.WithFields(logrus.Fields{
		"token_length": len(tokenString),
		"token_prefix": tokenString[:min(20, len(tokenString))],
		"cache_hit":    false,
	}).Info("Session not cached or expired, validating access token via /userinfo endpoint")

	// Fetch user info from /userinfo endpoint - this validates the token
	userinfoClaims, err := a.fetchUserInfo(ctx, tokenString)
	if err != nil {
		// Remove from cache on authentication failure
		a.invalidateSession(tokenString)
		return nil, fmt.Errorf("failed to validate access token via /userinfo: %w", err)
	}

	a.logger.WithFields(logrus.Fields{
		"userinfo_claims": userinfoClaims,
	}).Info("Access token validated successfully, user info retrieved from /userinfo")

	// Extract user info from userinfo claims
	userInfo := a.extractUserInfoFromClaims(userinfoClaims)

	// Cache the session
	a.cacheSession(tokenString, userInfo)

	return userInfo, nil
}

// getCachedSession retrieves a cached session if it exists and is not expired
func (a *Authenticator) getCachedSession(token string) *UserInfo {
	a.cacheMutex.RLock()
	defer a.cacheMutex.RUnlock()

	entry, exists := a.sessionCache[token]
	if !exists {
		return nil
	}

	// Check if session has expired
	if time.Now().After(entry.expiresAt) {
		a.logger.WithField("token_prefix", token[:min(20, len(token))]).Debug("Cached session expired")
		return nil
	}

	return entry.userInfo
}

// cacheSession stores a user session in the cache with expiration
func (a *Authenticator) cacheSession(token string, userInfo *UserInfo) {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	expiresAt := time.Now().Add(a.sessionCacheTTL)
	a.sessionCache[token] = &sessionCacheEntry{
		userInfo:  userInfo,
		expiresAt: expiresAt,
	}

	a.logger.WithFields(logrus.Fields{
		"subject":      userInfo.Subject,
		"email":        userInfo.Email,
		"expires_at":   expiresAt,
		"cache_ttl":    a.sessionCacheTTL,
		"token_prefix": token[:min(20, len(token))],
	}).Debug("Session cached")
}

// invalidateSession removes a session from the cache
func (a *Authenticator) invalidateSession(token string) {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	delete(a.sessionCache, token)
	a.logger.WithField("token_prefix", token[:min(20, len(token))]).Debug("Session invalidated")
}

// CleanupExpiredSessions removes expired sessions from the cache
// Should be called periodically (e.g., in a background goroutine)
func (a *Authenticator) CleanupExpiredSessions() {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	now := time.Now()
	count := 0
	for token, entry := range a.sessionCache {
		if now.After(entry.expiresAt) {
			delete(a.sessionCache, token)
			count++
		}
	}

	if count > 0 {
		a.logger.WithFields(logrus.Fields{
			"cleaned_count":   count,
			"remaining_count": len(a.sessionCache),
		}).Debug("Cleaned up expired sessions")
	}
}

// StartSessionCleanup starts a background goroutine that periodically cleans up expired sessions
// Call this once after creating the authenticator
func (a *Authenticator) StartSessionCleanup(ctx context.Context) {
	// Run cleanup every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.CleanupExpiredSessions()
			case <-ctx.Done():
				a.logger.Info("Session cleanup goroutine stopped")
				return
			}
		}
	}()
	a.logger.Info("Session cleanup goroutine started")
}

// fetchUserInfo fetches claims from the OIDC provider's /userinfo endpoint
func (a *Authenticator) fetchUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	// Use the userinfo endpoint URL from initialization
	a.logger.WithField("userinfo_endpoint", a.userinfoURL).Info("Using userinfo endpoint from discovery")

	// Make direct HTTP request to userinfo endpoint with Bearer token
	req, err := http.NewRequestWithContext(ctx, "GET", a.userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	a.logger.WithFields(logrus.Fields{
		"url":          a.userinfoURL,
		"token_prefix": accessToken[:min(20, len(accessToken))],
		"token_length": len(accessToken),
	}).Info("Making userinfo request")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			a.logger.WithError(err).Warn("Failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		// Read the error body for more details
		bodyBytes, _ := json.Marshal(resp.Body)
		a.logger.WithFields(logrus.Fields{
			"status":      resp.StatusCode,
			"status_text": resp.Status,
			"body":        string(bodyBytes),
		}).Warn("Userinfo endpoint returned non-200 status")
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	// Parse response
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	a.logger.WithFields(logrus.Fields{
		"claims_count": len(claims),
	}).Info("Successfully fetched userinfo claims")

	return claims, nil
}

// extractUserInfoFromClaims extracts user information from claims map
func (a *Authenticator) extractUserInfoFromClaims(claims map[string]interface{}) *UserInfo {
	userInfo := &UserInfo{
		Claims: claims,
	}

	// Extract subject - always use 'sub' claim (OIDC standard)
	if sub, ok := claims["sub"].(string); ok {
		userInfo.Subject = sub
	}

	// Extract email from configured email claim
	if email, ok := claims[a.emailClaim].(string); ok {
		userInfo.Email = email
	}

	// If email is still empty and userClaim is different from sub, try userClaim
	if userInfo.Email == "" && a.userClaim != "sub" {
		if userValue, ok := claims[a.userClaim].(string); ok {
			userInfo.Email = userValue
		}
	}

	// Extract roles
	userInfo.Roles = a.extractRoles(claims)
	userInfo.OriginalRoles = make([]string, len(userInfo.Roles))
	copy(userInfo.OriginalRoles, userInfo.Roles)

	// For admin users, add all policy names from BOTH sources to their roles
	if a.isAdminUser(userInfo.Subject, userInfo.Email) {
		// Build a set to avoid duplicates
		roleMap := make(map[string]bool)
		for _, role := range userInfo.Roles {
			roleMap[role] = true
		}

		// Add policy engine policies (from policies/ directory)
		var enginePolicies []string
		if a.policyEngine != nil {
			enginePolicies = a.policyEngine.GetPolicyNames()
			for _, policyName := range enginePolicies {
				if !roleMap[policyName] {
					userInfo.Roles = append(userInfo.Roles, policyName)
					roleMap[policyName] = true
				}
			}
		}

		// Add policy store policies (from ./data/policies/ directory)
		var storePolicies []string
		if a.policyStore != nil {
			storePolicies = a.policyStore.GetPolicyNames()
			for _, policyName := range storePolicies {
				if !roleMap[policyName] {
					userInfo.Roles = append(userInfo.Roles, policyName)
					roleMap[policyName] = true
				}
			}
		}

		a.logger.WithFields(logrus.Fields{
			"subject":         userInfo.Subject,
			"email":           userInfo.Email,
			"original_roles":  a.extractRoles(claims),
			"engine_policies": enginePolicies,
			"store_policies":  storePolicies,
			"final_roles":     userInfo.Roles,
		}).Info("Admin user - added all policy names from both sources to roles")
	}

	a.logger.WithFields(logrus.Fields{
		"subject":     userInfo.Subject,
		"email":       userInfo.Email,
		"roles":       userInfo.Roles,
		"user_claim":  a.userClaim,
		"email_claim": a.emailClaim,
		"roles_claim": a.rolesClaim,
	}).Info("User info extracted from claims")

	return userInfo
}

// extractRoles extracts roles from claims
func (a *Authenticator) extractRoles(claims map[string]interface{}) []string {
	roles := []string{}

	// Try to get roles from the configured claim
	if rolesValue, ok := claims[a.rolesClaim]; ok {
		switch v := rolesValue.(type) {
		case []interface{}:
			// Roles as array
			for _, role := range v {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
		case []string:
			// Roles as string array
			roles = v
		case string:
			// Single role as string
			roles = append(roles, v)
		}
	}

	// Fallback: try common role claim names
	if len(roles) == 0 {
		for _, claimName := range []string{"roles", "groups", "role", "group"} {
			if rolesValue, ok := claims[claimName]; ok {
				switch v := rolesValue.(type) {
				case []interface{}:
					for _, role := range v {
						if roleStr, ok := role.(string); ok {
							roles = append(roles, roleStr)
						}
					}
				case []string:
					roles = v
				case string:
					roles = append(roles, v)
				}
				if len(roles) > 0 {
					break
				}
			}
		}
	}

	// If still no roles found, assign default admin role
	if len(roles) == 0 {
		roles = []string{"admin"}
		a.logger.WithField("subject", claims["sub"]).Info("No roles found in token, assigning default admin role")
	}

	return roles
}

// isAdminUser checks if a user is an admin based on subject or email
func (a *Authenticator) isAdminUser(subject, email string) bool {
	for _, adminUser := range a.adminUsers {
		if adminUser == subject || adminUser == email {
			return true
		}
	}
	return false
}
