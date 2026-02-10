package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/backend"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// CredentialHandler handles credential management endpoints
type CredentialHandler struct {
	store         *store.CredentialStore
	groupStore    *store.GroupStore
	userStore     *store.UserStore
	policyStore   *store.PolicyStore
	iamClient     *s3client.IAMClient
	adminClient   backend.AdminClient
	adminUsername string
	groupManager  interface{}           // GroupManager for backend operations
	s3Config      config.S3GlobalConfig // S3 configuration for profile creation
	tenantAdmins  []string              // List of tenant admins for this tenant
	logger        *logrus.Logger
}

// NewCredentialHandler creates a new credential handler
func NewCredentialHandler(credStore *store.CredentialStore, groupStore *store.GroupStore, userStore *store.UserStore, policyStore *store.PolicyStore, iamClient *s3client.IAMClient, adminClient backend.AdminClient, adminUsername string, groupManager interface{}, s3Config config.S3GlobalConfig, tenantAdmins []string, logger *logrus.Logger) *CredentialHandler {
	return &CredentialHandler{
		store:         credStore,
		groupStore:    groupStore,
		userStore:     userStore,
		policyStore:   policyStore,
		iamClient:     iamClient,
		adminClient:   adminClient,
		adminUsername: adminUsername,
		groupManager:  groupManager,
		s3Config:      s3Config,
		tenantAdmins:  tenantAdmins,
		logger:        logger,
	}
}

// CreateCredentialRequest represents a request to create a credential
type CreateCredentialRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Groups      []string `json:"groups" binding:"required"`
}

// CredentialResponse represents a credential in API responses
type CredentialResponse struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	AccessKey     string   `json:"access_key"`
	SecretKey     string   `json:"secret_key,omitempty"`    // Only included on creation
	SessionToken  string   `json:"session_token,omitempty"` // Only included on creation for temporary credentials
	Groups        []string `json:"groups,omitempty"`
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

	// Create a map of access keys that are already in the local store
	localAccessKeys := make(map[string]bool)
	for _, cred := range credentials {
		localAccessKeys[cred.AccessKey] = true
	}

	// Add orphaned IAM access keys (exist in IAM but not in local store)
	for _, keyInfo := range backendKeyMetadata {
		if !localAccessKeys[keyInfo.AccessKeyId] {
			h.logger.WithFields(logrus.Fields{
				"username":   userInfo.Email,
				"access_key": keyInfo.AccessKeyId,
				"status":     keyInfo.Status,
			}).Info("Found orphaned IAM access key not in local store")

			responses = append(responses, CredentialResponse{
				ID:            "",                                                  // No local ID for orphaned keys
				Name:          fmt.Sprintf("orphaned-%s", keyInfo.AccessKeyId[:8]), // Generate a name
				AccessKey:     keyInfo.AccessKeyId,
				Groups:        []string{},         // Unknown groups for orphaned keys
				CreatedAt:     keyInfo.CreateDate, // Already a formatted string
				LastUsedAt:    "",                 // No last used date available for orphaned keys
				Description:   "Orphaned IAM access key (created outside this interface)",
				BackendStatus: keyInfo.Status,
			})
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
			Groups:        cred.Groups,
			CreatedAt:     cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastUsedAt:    formatTime(cred.LastUsedAt),
			Description:   cred.Description,
			BackendStatus: status,
		})
	}

	// Check if user is a tenant admin for THIS specific tenant
	isTenantAdmin := false
	for _, admin := range h.tenantAdmins {
		if admin == userInfo.Email {
			isTenantAdmin = true
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials":     responses,
		"count":           len(responses),
		"user_groups":     userInfo.OriginalGroups,
		"is_admin":        userInfo.Role == auth.UserRoleGlobalAdmin || isTenantAdmin,
		"is_global_admin": userInfo.Role == auth.UserRoleGlobalAdmin,
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

	// Validate credential name
	if err := validateCredentialName(req.Name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check for duplicate credential names for this user
	if h.store.CredentialExists(userInfo.Email, req.Name) {
		c.JSON(http.StatusConflict, gin.H{"error": "A credential with this name already exists"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"email":  userInfo.Email,
		"groups": req.Groups,
	}).Info("Credential creation request validated")

	// Check if user is admin (global admin or tenant admin)
	isAdmin := userInfo.Role == auth.UserRoleGlobalAdmin || userInfo.Role == auth.UserRoleTenantAdmin

	// For non-admin users, validate that they can only create credentials for groups they are members of
	if !isAdmin {
		userGroups := userInfo.OriginalGroups
		if len(userGroups) == 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "You are not a member of any groups. Contact your administrator.",
			})
			return
		}

		// Check that all requested groups are in the user's group membership
		for _, requestedGroup := range req.Groups {
			found := false
			for _, userGroup := range userGroups {
				if requestedGroup == userGroup {
					found = true
					break
				}
			}
			if !found {
				h.logger.WithFields(logrus.Fields{
					"user_email":      userInfo.Email,
					"requested_group": requestedGroup,
					"user_groups":     userGroups,
				}).Warn("User attempted to create credential for group they don't belong to")
				c.JSON(http.StatusForbidden, gin.H{
					"error":         "You can only create credentials for groups you are a member of",
					"your_groups":   userGroups,
					"invalid_group": requestedGroup,
				})
				return
			}
		}

		h.logger.WithFields(logrus.Fields{
			"user_email":  userInfo.Email,
			"user_groups": userGroups,
			"req_groups":  req.Groups,
		}).Info("User group membership validated for credential creation")
	} else {
		h.logger.WithFields(logrus.Fields{
			"user_email": userInfo.Email,
			"req_groups": req.Groups,
		}).Info("Admin user - skipping group membership validation")
	}

	// Resolve groups to policies and get policy documents
	policyNames := h.groupStore.GetPoliciesForGroups(req.Groups)
	if len(policyNames) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No policies found for the specified groups"})
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
		"groups":       req.Groups,
		"policy_names": policyNames,
		"policy_count": len(policyDocuments),
	}).Debug("Resolved groups to policy documents")

	// Check if user is admin - admins can assign any policies
	if !h.isAdmin(userInfo) {
		// Validate that requested policies are allowed by user's groups
		userAllowedPolicies := h.groupStore.GetPoliciesForGroups(userInfo.Groups)
		if !h.validatePolicies(policyNames, userAllowedPolicies) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":            "Cannot assign policies beyond your privileges",
				"your_groups":      userInfo.Groups,
				"allowed_policies": userAllowedPolicies,
				"requested":        policyNames,
			})
			return
		}
	}

	var accessKey, secretKey, sessionToken string
	var roleName string
	var credInfo backend.CredentialInfo

	// Combine all policy documents into a single policy
	combinedPolicy := combinePolicies(policyDocuments)

	// Use backend admin client if configured
	if h.adminClient != nil {
		// Track what resources we've created for cleanup on failure
		createdUser := false
		createdAccessKey := false
		accessKeyID := ""

		// Create user in backend if needed
		if err := h.adminClient.CreateUser(userInfo.Email, userInfo.Email); err != nil {
			h.logger.WithError(err).WithField("email", userInfo.Email).Warn("Failed to ensure backend user exists")
			// Continue anyway - user might already exist
		} else {
			createdUser = true
		}

		// Create credential with combined policy
		credInfo, err := h.adminClient.CreateCredential(userInfo.Email, req.Name, combinedPolicy)
		if err != nil {
			h.logger.WithError(err).WithField("email", userInfo.Email).Error("Failed to create backend credential")
			// Cleanup any partial resources
			h.cleanupPartialCredential(c.Request.Context(), userInfo.Email, req.Name, createdUser, createdAccessKey, accessKeyID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
			return
		}

		if credInfo.AccessKey == "" {
			h.logger.WithField("backend", h.adminClient.GetBackendType()).Error("Backend CreateCredential returned empty access key")
			// Cleanup any partial resources
			h.cleanupPartialCredential(c.Request.Context(), userInfo.Email, req.Name, createdUser, createdAccessKey, accessKeyID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
			return
		}

		accessKeyID = credInfo.AccessKey
		createdAccessKey = true
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

		cred, err := h.store.CreateWithKeys(userID, req.Name, req.Description, req.Groups, accessKey, secretKey, sessionToken, roleName, backendData)
		if err != nil {
			h.logger.WithError(err).Error("Failed to store credential")
			// Cleanup any partial resources
			h.cleanupPartialCredential(c.Request.Context(), userInfo.Email, req.Name, createdUser, createdAccessKey, accessKeyID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store credential"})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"user_id":    userInfo.Subject,
			"user_email": userInfo.Email,
			"cred_name":  req.Name,
			"access_key": accessKey,
		}).Info("Credential created")

		// Create AWS profile for the user credential
		if awsCliClient, ok := h.adminClient.(*awscli.Client); ok {
			if err := awsCliClient.CreateUserProfile(userInfo.Email, req.Name, accessKey, secretKey, sessionToken, h.s3Config.Region, h.s3Config.Endpoint); err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"user_email": userInfo.Email,
					"cred_name":  req.Name,
				}).Warn("Failed to create AWS profile for user credential")
				// Don't fail the credential creation if profile creation fails
			} else {
				h.logger.WithFields(logrus.Fields{
					"user_email": userInfo.Email,
					"cred_name":  req.Name,
				}).Info("AWS profile created for user credential")
			}
		}

		// Return credential with secret key (only shown once)
		c.JSON(http.StatusCreated, gin.H{
			"credential": CredentialResponse{
				ID:           cred.ID,
				Name:         cred.Name,
				AccessKey:    cred.AccessKey,
				SecretKey:    cred.SecretKey,
				SessionToken: cred.SessionToken,
				Groups:       cred.Groups,
				CreatedAt:    cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Description:  cred.Description,
			},
			"message": "Credential created successfully. Save the secret key securely - it won't be shown again.",
		})
		return
	} else if h.iamClient != nil {
		// Track what resources we've created for cleanup on failure
		createdUser := false
		createdAccessKey := false
		accessKeyID := ""

		// Use STS AssumeRole to create temporary credentials instead of permanent access keys
		username := userInfo.Email

		// Validate that groups are specified
		if len(req.Groups) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "At least one group must be specified for STS credentials"})
			return
		}

		// For STS, we use the first group to create a role
		if len(req.Groups) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "At least one group must be specified for STS credentials"})
			return
		}

		groupName := req.Groups[0] // Use first group for STS
		roleName := fmt.Sprintf("sts-%s", groupName)

		// Find SCIM group ID for this display name
		var scimGroupId string
		if scimGroup, exists := h.userStore.GetGroupByDisplayName(groupName); exists {
			scimGroupId = scimGroup.ID
		}

		if scimGroupId == "" {
			h.logger.WithField("group", groupName).Error("Group not found in SCIM")
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}

		// Get group policy
		group, err := h.groupStore.Get(scimGroupId)
		if err != nil {
			h.logger.WithError(err).WithField("scimGroupId", scimGroupId).Error("Group not found in store")
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}

		combinedPolicy, err := h.combineGroupPolicies(group.Policies)
		if err != nil {
			h.logger.WithError(err).WithField("group", groupName).Error("Failed to combine group policies")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to combine group policies"})
			return
		}

		// Create or update the STS role
		if err := h.iamClient.CreateRole(c.Request.Context(), roleName, combinedPolicy); err != nil {
			h.logger.WithError(err).WithField("role_name", roleName).Error("Failed to create STS role")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create STS role"})
			return
		}

		// Construct role ARN
		accountID, err := h.iamClient.GetAccountID(c.Request.Context())
		if err != nil {
			h.logger.WithError(err).WithField("username", username).Error("Failed to get account ID for role ARN")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get account information"})
			return
		}

		roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)

		// Assume the role to get temporary credentials
		tempAccessKey, tempSecretKey, tempSessionToken, err := h.iamClient.AssumeRole(c.Request.Context(), roleArn, fmt.Sprintf("%s-session-%s", username, req.Name), 3600) // 1 hour duration
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"username":   username,
				"role_arn":   roleArn,
				"group_name": groupName,
			}).Error("Failed to assume role for temporary credentials")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temporary credentials"})
			return
		}

		accessKey = tempAccessKey
		secretKey = tempSecretKey
		sessionToken = tempSessionToken
		accessKeyID = tempAccessKey

		// For IAM, we don't have backend-specific data to store
		credInfo = backend.CredentialInfo{
			AccessKey:    tempAccessKey,
			SecretKey:    tempSecretKey,
			SessionToken: tempSessionToken,
		}

		h.logger.WithFields(logrus.Fields{
			"username":        username,
			"role_arn":        roleArn,
			"group_name":      groupName,
			"selected_groups": req.Groups,
			"access_key":      accessKey,
		}).Info("Temporary credentials created via STS AssumeRole")

		// Store credential metadata locally
		backendData := credInfo.BackendData
		if backendData == nil {
			backendData = make(map[string]interface{})
		}

		userID := userInfo.Email

		cred, err := h.store.CreateWithKeys(userID, req.Name, req.Description, req.Groups, accessKey, secretKey, sessionToken, roleName, backendData)
		if err != nil {
			h.logger.WithError(err).Error("Failed to store credential")
			// Cleanup any partial resources
			h.cleanupPartialCredential(c.Request.Context(), userInfo.Email, req.Name, createdUser, createdAccessKey, accessKeyID)
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
		cred, err := h.store.Create(userInfo.Email, req.Name, req.Description, req.Groups)
		if err != nil {
			h.logger.WithError(err).Error("Failed to create credential")
			// For local credentials, no backend cleanup needed, but remove from store if it was partially created
			if err := h.store.DeleteCredential(req.Name); err != nil {
				h.logger.WithError(err).WithField("credential", req.Name).Error("Failed to cleanup local credential during creation failure")
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create credential"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"credential": CredentialResponse{
				ID:          cred.ID,
				Name:        cred.Name,
				AccessKey:   cred.AccessKey,
				SecretKey:   cred.SecretKey,
				Groups:      cred.Groups,
				CreatedAt:   cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Description: cred.Description,
			},
			"warning": "No backend configured - credentials are local only",
		})
		return
	}
}
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

	// First try to get credential from local store
	cred, err := h.store.Get(accessKey)
	if err != nil {
		// If not found locally, check if it's an orphaned IAM credential
		if h.iamClient != nil {
			keyMetadata, err := h.iamClient.ListAccessKeyMetadata(c.Request.Context(), userInfo.Email)
			if err == nil {
				found := false
				for _, keyInfo := range keyMetadata {
					if keyInfo.AccessKeyId == accessKey {
						found = true
						break
					}
				}
				if found {
					// Delete orphaned credential directly from IAM
					if err := h.iamClient.DeleteAccessKey(c.Request.Context(), userInfo.Email, accessKey); err != nil {
						h.logger.WithError(err).WithFields(logrus.Fields{
							"user_email": userInfo.Email,
							"access_key": accessKey,
						}).Error("Failed to delete orphaned IAM access key")
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete orphaned credential"})
						return
					}
					h.logger.WithFields(logrus.Fields{
						"user_email": userInfo.Email,
						"access_key": accessKey,
					}).Info("Orphaned IAM access key deleted")
					c.JSON(http.StatusOK, gin.H{"message": "Orphaned credential deleted successfully"})
					return
				}
			}
		}
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

	// Remove AWS profile for the user credential
	if awsCliClient, ok := h.adminClient.(*awscli.Client); ok {
		if err := awsCliClient.RemoveUserProfile(userInfo.Email, cred.Name); err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"user_email": userInfo.Email,
				"cred_name":  cred.Name,
			}).Warn("Failed to remove AWS profile for user credential")
			// Don't fail the credential deletion if profile removal fails
		} else {
			h.logger.WithFields(logrus.Fields{
				"user_email": userInfo.Email,
				"cred_name":  cred.Name,
			}).Info("AWS profile removed for user credential")
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

	// First try to get from local store
	cred, err := h.store.Get(accessKey)
	if err != nil {
		// If not found locally, check if it's an orphaned IAM credential
		if h.iamClient != nil {
			keyMetadata, err := h.iamClient.ListAccessKeyMetadata(c.Request.Context(), userInfo.Email)
			if err == nil {
				for _, keyInfo := range keyMetadata {
					if keyInfo.AccessKeyId == accessKey {
						// Found orphaned credential
						c.JSON(http.StatusOK, gin.H{
							"credential": CredentialResponse{
								ID:            "", // No local ID
								Name:          fmt.Sprintf("orphaned-%s", accessKey[:8]),
								AccessKey:     accessKey,
								Groups:        []string{}, // Unknown groups
								CreatedAt:     keyInfo.CreateDate,
								LastUsedAt:    "", // No last used date available
								Description:   "Orphaned IAM access key (created outside this interface)",
								BackendStatus: keyInfo.Status,
							},
						})
						return
					}
				}
			}
		}
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
			Groups:      cred.Groups,
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

// validateCredentialName validates credential name format and constraints
func validateCredentialName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("credential name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("credential name cannot exceed 64 characters")
	}
	if strings.Contains(name, " ") {
		return fmt.Errorf("credential name cannot contain spaces")
	}
	// Allow alphanumeric, hyphens, and underscores
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("credential name can only contain letters, numbers, hyphens, and underscores")
		}
	}
	return nil
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

	// Deduplicate identical statements
	uniqueStatements := deduplicateStatements(allStatements)

	return map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": uniqueStatements,
	}
}

// deduplicateStatements removes duplicate policy statements
func deduplicateStatements(statements []interface{}) []interface{} {
	seen := make(map[string]bool)
	var unique []interface{}

	for _, stmt := range statements {
		// Convert statement to JSON string for comparison
		stmtJSON, err := json.Marshal(stmt)
		if err != nil {
			// If we can't marshal, include it anyway
			unique = append(unique, stmt)
			continue
		}

		stmtKey := string(stmtJSON)
		if !seen[stmtKey] {
			seen[stmtKey] = true
			unique = append(unique, stmt)
		}
	}

	return unique
}

// UpdateCredentials updates all existing credentials affected by policy/role changes
// This is an admin-only operation that should be called after modifying policies or role mappings
func (h *CredentialHandler) UpdateCredentials(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	// Only admin can update credentials (global admin or tenant admin)
	if userInfo.Role != auth.UserRoleGlobalAdmin && userInfo.Role != auth.UserRoleTenantAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	// Get all existing groups
	allGroups := h.groupStore.GetGroupNames()
	groupSet := make(map[string]bool)
	for _, group := range allGroups {
		groupSet[group] = true
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
	var groupUpdatedCount int
	var errors []string

	for _, cred := range allCredentials {
		userID := cred.UserID
		originalGroups := make([]string, len(cred.Groups))
		copy(originalGroups, cred.Groups)

		// Filter out groups that no longer exist
		var validGroups []string
		var removedGroups []string
		for _, group := range cred.Groups {
			if groupSet[group] {
				validGroups = append(validGroups, group)
			} else {
				removedGroups = append(removedGroups, group)
			}
		}

		// If groups were removed, update the credential in the store
		if len(removedGroups) > 0 {
			h.logger.WithFields(logrus.Fields{
				"credential": cred.Name,
				"user":       userID,
				"removed":    removedGroups,
				"remaining":  validGroups,
			}).Info("Removing non-existent groups from credential")

			err := h.store.UpdateGroups(cred.AccessKey, validGroups)
			if err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"credential": cred.Name,
					"user":       userID,
				}).Error("Failed to update credential groups in store")
				errors = append(errors, fmt.Sprintf("Failed to update groups for credential %s: %v", cred.Name, err))
				continue
			}
			groupUpdatedCount++

			// Update the credential object for further processing
			cred.Groups = validGroups
		}

		// Resolve groups to policies
		policyNames := h.groupStore.GetPoliciesForGroups(cred.Groups)
		if len(policyNames) == 0 {
			h.logger.WithFields(logrus.Fields{
				"credential": cred.Name,
				"user":       userID,
				"groups":     cred.Groups,
			}).Warn("No policies found for credential groups, skipping backend update")
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
			// Update STS-based credential by updating the group policy
			groupName := cred.Groups[0] // Assume first group for simplicity
			if h.groupManager != nil {
				if gm, ok := h.groupManager.(*awscli.GroupManager); ok {
					policyName := fmt.Sprintf("%s-policy", groupName)
					err := gm.PutGroupPolicy(c.Request.Context(), groupName, policyName, combinedPolicy)
					if err != nil {
						h.logger.WithError(err).WithFields(logrus.Fields{
							"credential": cred.Name,
							"user":       userID,
							"group_name": groupName,
						}).Error("Failed to update STS group policy")
						errors = append(errors, fmt.Sprintf("Failed to update STS group for credential %s: %v", cred.Name, err))
						continue
					}
					h.logger.WithFields(logrus.Fields{
						"credential": cred.Name,
						"user":       userID,
						"group_name": groupName,
					}).Info("Updated STS group policy")
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
		"message":              "Credential update completed",
		"total_count":          len(allCredentials),
		"updated_count":        updatedCount,
		"groups_updated_count": groupUpdatedCount,
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

// combineGroupPolicies combines policy documents from multiple policies into one
func (h *CredentialHandler) combineGroupPolicies(policyNames []string) (map[string]interface{}, error) {
	combinedStatements := []map[string]interface{}{}

	for _, policyName := range policyNames {
		policy, err := h.policyStore.Get(policyName)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy %s: %w", policyName, err)
		}

		if statements, ok := policy.Policy["Statement"].([]interface{}); ok {
			for _, stmt := range statements {
				if stmtMap, ok := stmt.(map[string]interface{}); ok {
					combinedStatements = append(combinedStatements, stmtMap)
				}
			}
		}
	}

	combinedDoc := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": combinedStatements,
	}

	return combinedDoc, nil
}

// isAdmin checks if the user has admin group
func (h *CredentialHandler) isAdmin(userInfo *auth.UserInfo) bool {
	for _, group := range userInfo.Groups {
		if group == "admin" {
			return true
		}
	}
	return false
}

// cleanupPartialCredential removes any partially created resources if credential creation fails
func (h *CredentialHandler) cleanupPartialCredential(ctx context.Context, userName, credentialName string, createdUser bool, createdAccessKey bool, accessKeyID string) {
	if createdAccessKey && accessKeyID != "" {
		// Delete the access key if it was created
		if h.adminClient != nil {
			// For adminClient backend, we need to delete the credential
			backendData := make(map[string]interface{})
			if err := h.adminClient.DeleteCredential(userName, credentialName, backendData); err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"user":       userName,
					"credential": credentialName,
				}).Error("Failed to cleanup access key during credential creation failure")
			}
		} else if h.iamClient != nil {
			// For IAM client, delete the access key directly
			if err := h.iamClient.DeleteAccessKey(ctx, userName, accessKeyID); err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"user":        userName,
					"accessKeyID": accessKeyID,
				}).Error("Failed to cleanup access key during credential creation failure")
			}
		}
	}

	// Note: We don't delete the IAM user during cleanup as users are typically created once
	// and shared across multiple credentials

	// Remove the credential from store if it exists
	if err := h.store.DeleteCredential(credentialName); err != nil {
		h.logger.WithError(err).WithField("credential", credentialName).Error("Failed to cleanup credential from store during credential creation failure")
	}
}
