package handler

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/backend"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// CredentialHandler handles credential management endpoints
type CredentialHandler struct {
	store         *store.CredentialStore
	roleStore     *store.RoleStore
	policyStore   *store.PolicyStore
	iamClient     *s3client.IAMClient
	adminClient   backend.AdminClient
	adminUsername string
	roleManager   interface{} // RoleManager for backend operations
	logger        *logrus.Logger
}

// NewCredentialHandler creates a new credential handler
func NewCredentialHandler(credStore *store.CredentialStore, roleStore *store.RoleStore, policyStore *store.PolicyStore, iamClient *s3client.IAMClient, adminClient backend.AdminClient, adminUsername string, roleManager interface{}, logger *logrus.Logger) *CredentialHandler {
	return &CredentialHandler{
		store:         credStore,
		roleStore:     roleStore,
		policyStore:   policyStore,
		iamClient:     iamClient,
		adminClient:   adminClient,
		adminUsername: adminUsername,
		roleManager:   roleManager,
		logger:        logger,
	}
}

// CreateCredentialRequest represents a request to create a credential
type CreateCredentialRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Roles       []string `json:"roles" binding:"required"`
}

// CredentialResponse represents a credential in API responses
type CredentialResponse struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	AccessKey     string   `json:"access_key"`
	SecretKey     string   `json:"secret_key,omitempty"`    // Only included on creation
	SessionToken  string   `json:"session_token,omitempty"` // Only included on creation for temporary credentials
	Roles         []string `json:"roles,omitempty"`
	CreatedAt     string   `json:"created_at"`
	LastUsedAt    string   `json:"last_used_at,omitempty"`
	Description   string   `json:"description,omitempty"`
	BackendStatus string   `json:"backend_status"` // "OK", "Missing", "Unknown"
}

// ListCredentials lists all credentials for the authenticated user
func (h *CredentialHandler) ListCredentials(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	credentials, err := h.store.ListByUser(userInfo.Email)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list credentials")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list credentials"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user_id":    userInfo.Subject,
		"cred_count": len(credentials),
		"access_keys": func() []string {
			keys := make([]string, len(credentials))
			for i, c := range credentials {
				keys[i] = c.AccessKey
			}
			return keys
		}(),
	}).Info("Listing credentials for user")

	// Convert to response format (hide secret keys)
	responses := make([]CredentialResponse, 0, len(credentials))

	// Get backend access keys for this user if IAM client is available and backend is configured
	var backendAccessKeys []string
	var backendKeyMetadata []s3client.AccessKeyInfo
	if h.iamClient != nil && h.adminClient != nil {
		var err error
		h.logger.WithField("username", userInfo.Email).Debug("Checking IAM access keys for user")
		backendAccessKeys, _ = h.iamClient.ListAccessKeys(c.Request.Context(), userInfo.Email)
		backendKeyMetadata, err = h.iamClient.ListAccessKeyMetadata(c.Request.Context(), userInfo.Email)
		if err != nil {
			h.logger.WithError(err).WithField("username", userInfo.Email).Warn("Failed to get access key metadata from IAM")
		} else {
			h.logger.WithFields(logrus.Fields{
				"username":  userInfo.Email,
				"key_count": len(backendKeyMetadata),
			}).Debug("Retrieved access key metadata from IAM")
		}
	}

	for _, cred := range credentials {
		status := "Unknown"

		// For credentials created via adminClient (permanent IAM keys), show "OK"
		// These have no session token but are backed by real IAM resources
		if cred.SessionToken == "" && h.adminClient != nil {
			status = "OK"
		} else if cred.SessionToken == "" {
			// True local credentials (no backend configured)
			status = "Local"
		} else if len(backendKeyMetadata) > 0 {
			// Find the status for this credential's access key
			for _, keyInfo := range backendKeyMetadata {
				if keyInfo.AccessKeyId == cred.AccessKey {
					status = keyInfo.Status
					break
				}
			}
		} else if len(backendAccessKeys) > 0 {
			// Fallback to old logic if metadata not available
			existsInBackend := false
			for _, backendKey := range backendAccessKeys {
				if backendKey == cred.AccessKey {
					existsInBackend = true
					break
				}
			}

			if existsInBackend {
				status = "OK"
			} else {
				status = "Missing"
			}
		}

		responses = append(responses, CredentialResponse{
			ID:            cred.ID,
			Name:          cred.Name,
			AccessKey:     cred.AccessKey,
			Roles:         cred.Roles,
			CreatedAt:     cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastUsedAt:    formatTime(cred.LastUsedAt),
			Description:   cred.Description,
			BackendStatus: status,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials": responses,
		"count":       len(responses),
		"user_roles":  userInfo.OriginalRoles,
		"is_admin":    h.adminUsername != "" && userInfo.Email == h.adminUsername,
		"user_info": gin.H{
			"subject": userInfo.Subject,
			"email":   userInfo.Email,
		},
	})
}

// CreateCredential creates a new credential for the authenticated user
func (h *CredentialHandler) CreateCredential(c *gin.Context) {
	h.logger.Info("CreateCredential handler called")

	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	h.logger.WithField("email", userInfo.Email).Info("Processing credential creation")

	var req CreateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"email": userInfo.Email,
		"roles": req.Roles,
	}).Info("Credential creation request validated")

	// Resolve roles to policies and get policy documents
	policyNames := h.roleStore.GetPoliciesForRoles(req.Roles)
	if len(policyNames) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No policies found for the specified roles"})
		return
	}

	var policyDocuments []map[string]interface{}
	// Get actual policy documents
	for _, policyName := range policyNames {
		policyDoc, err := h.policyStore.Get(policyName)
		if err != nil {
			h.logger.WithError(err).WithField("policy", policyName).Error("Failed to get policy document")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve policy documents"})
			return
		}
		policyDocuments = append(policyDocuments, policyDoc.Policy)
	}

	h.logger.WithFields(logrus.Fields{
		"roles":        req.Roles,
		"policy_names": policyNames,
		"policy_count": len(policyDocuments),
	}).Debug("Resolved roles to policy documents")

	// Check if user is admin - admins can assign any policies
	if !h.isAdmin(userInfo) {
		// Validate that requested policies are allowed by user's roles
		userAllowedPolicies := h.roleStore.GetPoliciesForRoles(userInfo.Roles)
		if !h.validatePolicies(policyNames, userAllowedPolicies) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":            "Cannot assign policies beyond your privileges",
				"your_roles":       userInfo.Roles,
				"allowed_policies": userAllowedPolicies,
				"requested":        policyNames,
			})
			return
		}
	}

	var accessKey, secretKey, sessionToken string
	var roleName string
	var err error
	var credInfo backend.CredentialInfo

	// Combine all policy documents into a single policy
	combinedPolicy := combinePolicies(policyDocuments)

	// Use backend admin client if configured
	if h.adminClient != nil {
		// Create user in backend if needed
		if err := h.adminClient.CreateUser(userInfo.Email, userInfo.Email); err != nil {
			h.logger.WithError(err).WithField("email", userInfo.Email).Warn("Failed to ensure backend user exists")
			// Continue anyway - user might already exist
		}

		// Create credential with combined policy
		credInfo, err := h.adminClient.CreateCredential(userInfo.Email, req.Name, combinedPolicy)
		if err != nil {
			h.logger.WithError(err).WithField("email", userInfo.Email).Error("Failed to create backend credential")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
			return
		}

		if credInfo.AccessKey == "" {
			h.logger.WithField("backend", h.adminClient.GetBackendType()).Error("Backend CreateCredential returned empty access key")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
			return
		}

		accessKey = credInfo.AccessKey
		secretKey = credInfo.SecretKey
		sessionToken := credInfo.SessionToken

		roleName = ""
		if rn, ok := credInfo.BackendData["role_name"].(string); ok {
			roleName = rn
		}

		h.logger.WithFields(logrus.Fields{
			"user_email":   userInfo.Email,
			"credential":   req.Name,
			"policy_count": len(policyDocuments),
			"access_key":   accessKey,
		}).Info("Backend credential created with combined policy")

		// Store credential metadata locally
		backendData := credInfo.BackendData
		if backendData == nil {
			backendData = make(map[string]interface{})
		}

		userID := userInfo.Email

		cred, err := h.store.CreateWithKeys(userID, req.Name, req.Description, req.Roles, accessKey, secretKey, sessionToken, roleName, backendData)
		if err != nil {
			h.logger.WithError(err).Error("Failed to store credential")
			// Try to clean up the backend credential
			if backendData == nil {
				backendData = make(map[string]interface{})
			}
			_ = h.adminClient.DeleteCredential(userInfo.Email, req.Name, backendData)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store credential"})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"user_id":    userInfo.Subject,
			"user_email": userInfo.Email,
			"cred_name":  req.Name,
			"access_key": accessKey,
		}).Info("Credential created")

		// Return credential with secret key (only shown once)
		c.JSON(http.StatusCreated, gin.H{
			"credential": CredentialResponse{
				ID:           cred.ID,
				Name:         cred.Name,
				AccessKey:    cred.AccessKey,
				SecretKey:    cred.SecretKey,
				SessionToken: cred.SessionToken,
				CreatedAt:    cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Description:  cred.Description,
			},
			"message": "Credential created successfully. Save the secret key securely - it won't be shown again.",
		})
		return
	} else if h.iamClient != nil {
		// Use STS AssumeRole to create temporary credentials instead of permanent access keys
		username := userInfo.Email

		// Validate that roles are specified
		if len(req.Roles) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "At least one role must be specified for STS credentials"})
			return
		}

		// For multiple roles, we need to combine them. For single role, use existing role.
		var roleName string
		var roleArn string

		if len(req.Roles) == 1 {
			// Single role - use existing role directly
			roleName = req.Roles[0]
		} else {
			// Multiple roles - create a deterministic combined role name based on sorted roles
			// This allows reuse of the same combination across different credentials
			sortedRoles := make([]string, len(req.Roles))
			copy(sortedRoles, req.Roles)
			sort.Strings(sortedRoles)

			roleName = fmt.Sprintf("combined-%s", strings.Join(sortedRoles, "-"))
		}

		// Get account ID for ARN construction
		accountID, err := h.iamClient.GetAccountID(c.Request.Context())
		if err != nil {
			h.logger.WithError(err).WithField("username", username).Error("Failed to get account ID for role ARN")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get account information"})
			return
		}

		// Construct role ARN
		roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)

		// For combined roles, ensure the role exists with combined policy
		if len(req.Roles) > 1 && h.roleManager != nil {
			if rm, ok := h.roleManager.(*awscli.RoleManager); ok {
				// Check if combined role exists
				roles, err := rm.ListRoles(c.Request.Context())
				if err != nil {
					h.logger.WithError(err).Error("Failed to list roles")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing roles"})
					return
				}

				roleExists := false
				for _, existingRole := range roles {
					if existingRole == roleName {
						roleExists = true
						break
					}
				}

				if !roleExists {
					// Create the combined role
					err = rm.CreateRole(c.Request.Context(), roleName, combinedPolicy)
					if err != nil {
						h.logger.WithError(err).WithField("role_name", roleName).Error("Failed to create combined role")
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create combined role"})
						return
					}
					h.logger.WithField("role_name", roleName).Info("Created combined role")
				}
			}
		}

		// Assume the role to get temporary credentials
		tempAccessKey, tempSecretKey, tempSessionToken, err := h.iamClient.AssumeRole(c.Request.Context(), roleArn, fmt.Sprintf("%s-session-%s", username, req.Name), 3600) // 1 hour duration
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"username":  username,
				"role_arn":  roleArn,
				"role_name": roleName,
			}).Error("Failed to assume role for temporary credentials")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temporary credentials"})
			return
		}

		accessKey = tempAccessKey
		secretKey = tempSecretKey
		sessionToken = tempSessionToken

		// For IAM, we don't have backend-specific data to store
		credInfo = backend.CredentialInfo{
			AccessKey:    tempAccessKey,
			SecretKey:    tempSecretKey,
			SessionToken: tempSessionToken,
		}

		h.logger.WithFields(logrus.Fields{
			"username":       username,
			"role_arn":       roleArn,
			"role_name":      roleName,
			"selected_roles": req.Roles,
			"access_key":     accessKey,
		}).Info("Temporary credentials created via STS AssumeRole")

		// Store credential metadata locally
		backendData := credInfo.BackendData
		if backendData == nil {
			backendData = make(map[string]interface{})
		}

		userID := userInfo.Email

		cred, err := h.store.CreateWithKeys(userID, req.Name, req.Description, req.Roles, accessKey, secretKey, sessionToken, roleName, backendData)
		if err != nil {
			h.logger.WithError(err).Error("Failed to store credential")
			// Try to clean up the backend credential
			username := userInfo.Email
			_ = h.iamClient.DeleteAccessKey(c.Request.Context(), username, accessKey)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store credential"})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"user_id":    userInfo.Subject,
			"user_email": userInfo.Email,
			"cred_name":  req.Name,
			"access_key": accessKey,
		}).Info("Credential created")

		// Return credential with secret key (only shown once)
		c.JSON(http.StatusCreated, gin.H{
			"credential": CredentialResponse{
				ID:           cred.ID,
				Name:         cred.Name,
				AccessKey:    cred.AccessKey,
				SecretKey:    cred.SecretKey,
				SessionToken: cred.SessionToken,
				CreatedAt:    cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Description:  cred.Description,
			},
			"message": "Credential created successfully. Save the secret key securely - it won't be shown again.",
		})
		return
	} else {
		// No backend configured - generate local keys only (for testing)
		h.logger.Warn("No CEPH or IAM backend configured, generating local keys only")
		cred, err := h.store.Create(userInfo.Email, req.Name, req.Description, req.Roles)
		if err != nil {
			h.logger.WithError(err).Error("Failed to create credential")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"credential": CredentialResponse{
				ID:          cred.ID,
				Name:        cred.Name,
				AccessKey:   cred.AccessKey,
				SecretKey:   cred.SecretKey,
				Roles:       cred.Roles,
				CreatedAt:   cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Description: cred.Description,
			},
			"warning": "No backend configured - credentials are local only",
		})
		return
	}

	// Store credential metadata locally
	backendData := credInfo.BackendData
	if backendData == nil {
		backendData = make(map[string]interface{})
	}

	userID := userInfo.Email

	cred, err := h.store.CreateWithKeys(userID, req.Name, req.Description, req.Roles, accessKey, secretKey, credInfo.SessionToken, roleName, backendData)
	if err != nil {
		h.logger.WithError(err).Error("Failed to store credential")
		// Try to clean up the backend credential
		if h.adminClient != nil {
			backendData := credInfo.BackendData
			if backendData == nil {
				backendData = make(map[string]interface{})
			}
			_ = h.adminClient.DeleteCredential(userInfo.Email, req.Name, backendData)
		} else if h.iamClient != nil {
			username := userInfo.Email
			_ = h.iamClient.DeleteAccessKey(c.Request.Context(), username, accessKey)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store credential"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user_id":    userInfo.Subject,
		"user_email": userInfo.Email,
		"cred_name":  req.Name,
		"access_key": accessKey,
	}).Info("Credential created")

	// Return credential with secret key (only shown once)
	c.JSON(http.StatusCreated, gin.H{
		"credential": CredentialResponse{
			ID:           cred.ID,
			Name:         cred.Name,
			AccessKey:    cred.AccessKey,
			SecretKey:    cred.SecretKey,
			SessionToken: cred.SessionToken,
			CreatedAt:    cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Description:  cred.Description,
		},
		"message": "Credential created successfully. Save the secret key securely - it won't be shown again.",
	})
}

// DeleteCredential deletes a credential
func (h *CredentialHandler) DeleteCredential(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	accessKey := c.Param("accessKey")
	if accessKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Access key is required"})
		return
	}

	// Get credential before deleting to extract sub-user name
	cred, err := h.store.Get(accessKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	// Verify ownership
	if cred.UserID != userInfo.Email {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	// Delete from backend if configured
	if h.adminClient != nil {
		backendData := cred.BackendData
		if backendData == nil {
			backendData = make(map[string]interface{})
		}
		if err := h.adminClient.DeleteCredential(userInfo.Email, cred.Name, backendData); err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"user_email": userInfo.Email,
				"backend":    h.adminClient.GetBackendType(),
				"credential": cred.Name,
			}).Warn("Failed to delete backend credential (continuing anyway)")
			// Continue with local deletion even if backend deletion fails
		} else {
			h.logger.WithFields(logrus.Fields{
				"backend":    h.adminClient.GetBackendType(),
				"credential": cred.Name,
			}).Info("Backend credential deleted")
		}
	}

	// Delete IAM access key if using IAM (fallback)
	if h.iamClient != nil && h.adminClient == nil {
		if err := h.iamClient.DeleteAccessKey(c.Request.Context(), userInfo.Email, accessKey); err != nil {
			h.logger.WithError(err).Warn("Failed to delete IAM access key (continuing anyway)")
		}
	}

	// Delete temporary role if this was an STS-based credential with combined roles
	if h.iamClient != nil && cred.SessionToken != "" && cred.RoleName != "" {
		// Only delete roles that start with "combined-" (shared combined roles)
		// Don't delete individual existing roles
		if strings.HasPrefix(cred.RoleName, "combined-") {
			if err := h.iamClient.DeleteRole(c.Request.Context(), cred.RoleName); err != nil {
				h.logger.WithError(err).WithField("role_name", cred.RoleName).Warn("Failed to delete combined role (continuing anyway)")
			} else {
				h.logger.WithField("role_name", cred.RoleName).Info("Deleted combined role for credential")
			}
		}
	}

	// Delete credential from local store
	if err := h.store.Delete(accessKey, userInfo.Subject); err != nil {
		h.logger.WithError(err).Error("Failed to delete credential from store")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete credential"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user_id":    userInfo.Subject,
		"user_email": userInfo.Email,
		"access_key": accessKey,
	}).Info("Credential deleted")

	c.JSON(http.StatusOK, gin.H{"message": "Credential deleted successfully"})
}

// GetCredential gets a specific credential (without secret key)
func (h *CredentialHandler) GetCredential(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	accessKey := c.Param("accessKey")
	if accessKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Access key is required"})
		return
	}

	cred, err := h.store.Get(accessKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	// Verify ownership
	if cred.UserID != userInfo.Email {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"credential": CredentialResponse{
			ID:          cred.ID,
			Name:        cred.Name,
			AccessKey:   cred.AccessKey,
			SecretKey:   cred.SecretKey, // Include secret key for user's own credentials
			Roles:       cred.Roles,
			CreatedAt:   cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastUsedAt:  formatTime(cred.LastUsedAt),
			Description: cred.Description,
		},
	})
}

// getUserInfo extracts user info from context
func (h *CredentialHandler) getUserInfo(c *gin.Context) *auth.UserInfo {
	userInfoValue, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil
	}

	userInfo, ok := userInfoValue.(*auth.UserInfo)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user info"})
		return nil
	}

	return userInfo
}

// validatePolicies checks if requested policies are a subset of allowed policies
func (h *CredentialHandler) validatePolicies(requested, allowed []string) bool {
	allowedSet := make(map[string]bool)
	for _, policy := range allowed {
		allowedSet[policy] = true
	}

	for _, policy := range requested {
		if !allowedSet[policy] {
			return false
		}
	}

	return true
}

// formatTime formats a time or returns empty string if zero
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}

// combinePolicies merges multiple IAM policy documents into a single policy
func combinePolicies(policies []map[string]interface{}) map[string]interface{} {
	if len(policies) == 0 {
		// Return a minimal deny-all policy
		return map[string]interface{}{
			"Version": "2012-10-17",
			"Statement": []interface{}{
				map[string]interface{}{
					"Effect":   "Deny",
					"Action":   []string{"s3:*"},
					"Resource": []string{"*"},
				},
			},
		}
	}

	if len(policies) == 1 {
		return policies[0]
	}

	// Combine all statements from all policies
	var allStatements []interface{}
	for _, policy := range policies {
		if statements, ok := policy["Statement"].([]interface{}); ok {
			allStatements = append(allStatements, statements...)
		}
	}

	return map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": allStatements,
	}
}

// UpdateCredentials updates all existing credentials affected by policy/role changes
// This is an admin-only operation that should be called after modifying policies or role mappings
func (h *CredentialHandler) UpdateCredentials(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	// Only admin can update credentials
	if h.adminUsername != "" && userInfo.Email != h.adminUsername {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	// Get all existing roles
	allRoles := h.roleStore.GetRoleNames()
	roleSet := make(map[string]bool)
	for _, role := range allRoles {
		roleSet[role] = true
	}

	// Get all credentials
	allCredentials, err := h.store.ListAll()
	if err != nil {
		h.logger.WithError(err).Error("Failed to list all credentials for update")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list credentials"})
		return
	}

	if len(allCredentials) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No credentials found to update",
			"count":   0,
		})
		return
	}

	var updatedCount int
	var roleUpdatedCount int
	var errors []string

	for _, cred := range allCredentials {
		userID := cred.UserID
		originalRoles := make([]string, len(cred.Roles))
		copy(originalRoles, cred.Roles)

		// Filter out roles that no longer exist
		var validRoles []string
		var removedRoles []string
		for _, role := range cred.Roles {
			if roleSet[role] {
				validRoles = append(validRoles, role)
			} else {
				removedRoles = append(removedRoles, role)
			}
		}

		// If roles were removed, update the credential in the store
		if len(removedRoles) > 0 {
			h.logger.WithFields(logrus.Fields{
				"credential": cred.Name,
				"user":       userID,
				"removed":    removedRoles,
				"remaining":  validRoles,
			}).Info("Removing non-existent roles from credential")

			err := h.store.UpdateRoles(cred.AccessKey, validRoles)
			if err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"credential": cred.Name,
					"user":       userID,
				}).Error("Failed to update credential roles in store")
				errors = append(errors, fmt.Sprintf("Failed to update roles for credential %s: %v", cred.Name, err))
				continue
			}
			roleUpdatedCount++

			// Update the credential object for further processing
			cred.Roles = validRoles
		}

		// Resolve roles to policies
		policyNames := h.roleStore.GetPoliciesForRoles(cred.Roles)
		if len(policyNames) == 0 {
			h.logger.WithFields(logrus.Fields{
				"credential": cred.Name,
				"user":       userID,
				"roles":      cred.Roles,
			}).Warn("No policies found for credential roles, skipping backend update")
			continue
		}

		// Get policy documents
		var policyDocuments []map[string]interface{}
		for _, policyName := range policyNames {
			policyDoc, err := h.policyStore.Get(policyName)
			if err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"credential": cred.Name,
					"policy":     policyName,
				}).Error("Failed to get policy document for credential update")
				errors = append(errors, fmt.Sprintf("Failed to get policy %s for credential %s: %v", policyName, cred.Name, err))
				continue
			}
			policyDocuments = append(policyDocuments, policyDoc.Policy)
		}

		if len(policyDocuments) == 0 {
			continue
		}

		// Combine policies
		combinedPolicy := combinePolicies(policyDocuments)

		// Update the credential in the backend
		if h.adminClient != nil {
			// Skip credentials that don't have backend data (created with different backend or before backend was configured)
			if len(cred.BackendData) == 0 {
				h.logger.WithFields(logrus.Fields{
					"credential": cred.Name,
					"user":       userID,
					"backend":    h.adminClient.GetBackendType(),
				}).Info("Skipping credential update - no backend data (credential created with different backend)")
				continue
			}

			// Ensure user exists in backend
			if err := h.adminClient.CreateUser(userID, userID); err != nil {
				h.logger.WithError(err).WithField("user", userID).Warn("Failed to ensure backend user exists for update")
				// Continue anyway - user might already exist
			}

			updatedBackendData, err := h.adminClient.UpdateCredential(userID, cred.Name, combinedPolicy, cred.BackendData)
			if err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"credential": cred.Name,
					"user":       userID,
					"backend":    h.adminClient.GetBackendType(),
				}).Error("Failed to update credential in backend")
				errors = append(errors, fmt.Sprintf("Failed to update credential %s: %v", cred.Name, err))
				continue
			}

			// Update the credential's backend data in the store
			if updatedBackendData != nil {
				// Save the updated credential to persist the backend data
				if err := h.store.UpdateBackendData(cred.AccessKey, updatedBackendData); err != nil {
					h.logger.WithError(err).WithFields(logrus.Fields{
						"credential": cred.Name,
						"user":       userID,
					}).Warn("Failed to save updated backend data to store")
				}
			}
		} else if h.iamClient != nil && cred.SessionToken != "" {
			// Update STS-based credential by updating the role policy
			roleName := fmt.Sprintf("%s-%s-cred", userID, cred.Name)
			if h.roleManager != nil {
				if rm, ok := h.roleManager.(*awscli.RoleManager); ok {
					err := rm.UpdateRole(c.Request.Context(), roleName, combinedPolicy)
					if err != nil {
						h.logger.WithError(err).WithFields(logrus.Fields{
							"credential": cred.Name,
							"user":       userID,
							"role_name":  roleName,
						}).Error("Failed to update STS role policy")
						errors = append(errors, fmt.Sprintf("Failed to update STS role for credential %s: %v", cred.Name, err))
						continue
					}
					h.logger.WithFields(logrus.Fields{
						"credential": cred.Name,
						"user":       userID,
						"role_name":  roleName,
					}).Info("Updated STS role policy")
				}
			}
		}

		updatedCount++
		h.logger.WithFields(logrus.Fields{
			"credential": cred.Name,
			"user":       userID,
			"policies":   policyNames,
		}).Info("Updated credential with new policy")
	}

	response := gin.H{
		"message":             "Credential update completed",
		"total_count":         len(allCredentials),
		"updated_count":       updatedCount,
		"roles_updated_count": roleUpdatedCount,
	}

	if len(errors) > 0 {
		response["errors"] = errors
		response["error_count"] = len(errors)
	}

	status := http.StatusOK
	if len(errors) > 0 {
		status = http.StatusPartialContent // 206 - partial success
	}

	c.JSON(status, response)
}

// isAdmin checks if the user has admin role
func (h *CredentialHandler) isAdmin(userInfo *auth.UserInfo) bool {
	for _, role := range userInfo.Roles {
		if role == "admin" {
			return true
		}
	}
	return false
}
