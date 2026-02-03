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

// UserStore interface for accessing SCIM user data
type UserStore interface {
	IsUserActive(userName string) bool
	GetUserGroups(userName string) []string
}

// sessionCacheEntry represents a cached user session
type sessionCacheEntry struct {
	userInfo  *UserInfo
	expiresAt time.Time
}

// Authenticator handles OIDC authentication
type Authenticator struct {
	userinfoURL     string
	groupsClaim     string
	userClaim       string
	emailClaim      string
	sessionCacheTTL time.Duration
	logger          *logrus.Logger
	policyEngine    PolicyEngine
	policyStore     PolicyStore
	userStore       UserStore
	adminUsers      []string
	sessionCache    map[string]*sessionCacheEntry // token -> cached session
	cacheMutex      sync.RWMutex
}

// UserInfo contains authenticated user information
type UserInfo struct {
	Subject        string
	Email          string
	Groups         []string // Effective groups (includes all policies for admin users)
	OriginalGroups []string // Original OIDC groups (before policy expansion)
	IsAdmin        bool     // True if user is an admin
	Claims         map[string]interface{}
}

// NewOIDCAuthenticator creates a new OIDC authenticator
func NewOIDCAuthenticator(cfg config.OIDCConfig, logger *logrus.Logger, policyEngine PolicyEngine, policyStore PolicyStore, userStore UserStore, adminUsers []string) (*Authenticator, error) {
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
		groupsClaim:     cfg.GroupsClaim,
		userClaim:       cfg.UserClaim,
		emailClaim:      cfg.EmailClaim,
		sessionCacheTTL: cfg.SessionCacheTTL,
		logger:          logger,
		policyEngine:    policyEngine,
		policyStore:     policyStore,
		userStore:       userStore,
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
		"claims":       claims, // Log all claims for debugging
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

	// Extract groups from OIDC claims (OIDC takes precedence)
	oidcGroups := a.extractGroups(claims)

	// If OIDC provides groups, use them; otherwise fall back to SCIM
	if len(oidcGroups) > 0 {
		// OIDC claims take precedence
		userInfo.Groups = oidcGroups
		userInfo.OriginalGroups = make([]string, len(oidcGroups))
		copy(userInfo.OriginalGroups, oidcGroups)
	} else if a.userStore != nil {
		// No OIDC groups, check SCIM as fallback
		userName := userInfo.Email // Assume email is the userName
		if a.userStore.IsUserActive(userName) {
			// User exists and is active in SCIM, get groups from SCIM
			userInfo.Groups = a.userStore.GetUserGroups(userName)
			userInfo.OriginalGroups = make([]string, len(userInfo.Groups))
			copy(userInfo.OriginalGroups, userInfo.Groups)
		}
	}

	// If still no groups, ensure empty arrays are initialized
	if userInfo.Groups == nil {
		userInfo.Groups = []string{}
	}
	if userInfo.OriginalGroups == nil {
		userInfo.OriginalGroups = []string{}
	}

	// For admin users, add all policy names from BOTH sources to their groups
	if a.isAdminUser(userInfo.Subject, userInfo.Email) {
		userInfo.IsAdmin = true
		// Build a set to avoid duplicates
		groupMap := make(map[string]bool)
		for _, group := range userInfo.Groups {
			groupMap[group] = true
		}

		// Add policy engine groups (from policies/ directory)
		var enginePolicies []string
		if a.policyEngine != nil {
			enginePolicies = a.policyEngine.GetPolicyNames()
			for _, policyName := range enginePolicies {
				if !groupMap[policyName] {
					userInfo.Groups = append(userInfo.Groups, policyName)
					groupMap[policyName] = true
				}
			}
		}

		// Add policy store policies (from ./data/policies/ directory)
		var storePolicies []string
		if a.policyStore != nil {
			storePolicies = a.policyStore.GetPolicyNames()
			for _, policyName := range storePolicies {
				if !groupMap[policyName] {
					userInfo.Groups = append(userInfo.Groups, policyName)
					groupMap[policyName] = true
				}
			}
		}

		a.logger.WithFields(logrus.Fields{
			"subject":         userInfo.Subject,
			"email":           userInfo.Email,
			"original_groups": a.extractGroups(claims),
			"engine_policies": enginePolicies,
			"store_policies":  storePolicies,
			"final_groups":    userInfo.Groups,
		}).Info("Admin user - added all policy names from both sources to groups")
	}

	a.logger.WithFields(logrus.Fields{
		"subject":      userInfo.Subject,
		"email":        userInfo.Email,
		"groups":       userInfo.Groups,
		"user_claim":   a.userClaim,
		"email_claim":  a.emailClaim,
		"groups_claim": a.groupsClaim,
	}).Info("User info extracted from claims")

	return userInfo
}

// extractGroups extracts groups from claims
func (a *Authenticator) extractGroups(claims map[string]interface{}) []string {
	groups := []string{}

	a.logger.WithFields(logrus.Fields{
		"groups_claim": a.groupsClaim,
		"claims":       claims,
	}).Debug("Extracting groups from claims")

	// Try to get groups from the configured claim
	if groupsValue, ok := claims[a.groupsClaim]; ok {
		a.logger.WithFields(logrus.Fields{
			"groups_claim": a.groupsClaim,
			"groups_value": groupsValue,
			"value_type":   fmt.Sprintf("%T", groupsValue),
		}).Info("Found groups in configured claim")

		switch v := groupsValue.(type) {
		case []interface{}:
			// Groups as array
			for _, group := range v {
				if groupStr, ok := group.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		case []string:
			// Groups as string array
			groups = v
		case string:
			// Single group as string
			groups = append(groups, v)
		}
	}

	// Fallback: try common group claim names
	if len(groups) == 0 {
		for _, claimName := range []string{"groups", "roles", "group", "role"} {
			if groupsValue, ok := claims[claimName]; ok {
				switch v := groupsValue.(type) {
				case []interface{}:
					for _, group := range v {
						if groupStr, ok := group.(string); ok {
							groups = append(groups, groupStr)
						}
					}
				case []string:
					groups = v
				case string:
					groups = append(groups, v)
				}
				if len(groups) > 0 {
					break
				}
			}
		}
	}

	// Log the final result
	a.logger.WithFields(logrus.Fields{
		"groups_claim":     a.groupsClaim,
		"extracted_groups": groups,
		"groups_count":     len(groups),
	}).Info("Groups extraction completed")

	// If no groups found, user has no access
	if len(groups) == 0 {
		a.logger.WithField("subject", claims["sub"]).Warn("No groups found in token - user will have no access")
	}

	return groups
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
