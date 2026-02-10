package handler

import (
	"net/http"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// PolicyHandler handles policy management endpoints
type PolicyHandler struct {
	store       *store.PolicyStore
	groupStore  *store.GroupStore
	syncService interface{}
	logger      *logrus.Logger
}

// NewPolicyHandler creates a new policy handler
func NewPolicyHandler(policyStore *store.PolicyStore, logger *logrus.Logger) *PolicyHandler {
	return &PolicyHandler{
		store:  policyStore,
		logger: logger,
	}
}

// NewPolicyHandlerWithSync creates a new policy handler with sync capabilities
func NewPolicyHandlerWithSync(policyStore *store.PolicyStore, groupStore *store.GroupStore, syncService interface{}, logger *logrus.Logger) *PolicyHandler {
	return &PolicyHandler{
		store:       policyStore,
		groupStore:  groupStore,
		syncService: syncService,
		logger:      logger,
	}
}

// PolicyRequest represents a request to create/update a policy
type PolicyRequest struct {
	Name        string                 `json:"name" binding:"required"`
	Description string                 `json:"description"`
	Policy      map[string]interface{} `json:"policy" binding:"required"`
}

// PolicyResponse represents a policy in API responses
type PolicyResponse struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Policy      map[string]interface{} `json:"policy"`
}

// ListPolicies lists all policies
func (h *PolicyHandler) ListPolicies(c *gin.Context) {
	// All authenticated users can view policies
	policies, err := h.store.List()
	if err != nil {
		h.logger.WithError(err).Error("Failed to list policies")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}

	responses := make([]PolicyResponse, 0, len(policies))
	for _, policy := range policies {
		responses = append(responses, PolicyResponse{
			Name:        policy.Name,
			Description: policy.Description,
			Policy:      policy.Policy,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": responses,
		"count":    len(responses),
	})
}

// GetPolicy retrieves a specific policy
func (h *PolicyHandler) GetPolicy(c *gin.Context) {
	// All authenticated users can view policies
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy name is required"})
		return
	}

	policy, err := h.store.Get(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policy": PolicyResponse{
			Name:        policy.Name,
			Description: policy.Description,
			Policy:      policy.Policy,
		},
	})
}

// CreatePolicy creates a new policy
func (h *PolicyHandler) CreatePolicy(c *gin.Context) {
	// Only admin users can manage policies
	if !h.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin role required to manage policies"})
		return
	}

	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Validate policy JSON
	if err := store.ValidatePolicyJSON(req.Policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "Invalid policy JSON",
			"validation_error": err.Error(),
		})
		return
	}

	policy, err := h.store.Create(req.Name, req.Description, req.Policy)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create policy")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userInfo := h.getUserInfo(c)
	h.logger.WithFields(logrus.Fields{
		"user_id":     userInfo.Subject,
		"user_email":  userInfo.Email,
		"policy_name": req.Name,
	}).Info("Policy created")

	c.JSON(http.StatusCreated, gin.H{
		"policy": PolicyResponse{
			Name:        policy.Name,
			Description: policy.Description,
			Policy:      policy.Policy,
		},
		"message": "Policy created successfully",
	})
}

// UpdatePolicy updates an existing policy
func (h *PolicyHandler) UpdatePolicy(c *gin.Context) {
	// Only admin users can manage policies
	if !h.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin role required to manage policies"})
		return
	}

	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy name is required"})
		return
	}

	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Validate policy JSON
	if err := store.ValidatePolicyJSON(req.Policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "Invalid policy JSON",
			"validation_error": err.Error(),
		})
		return
	}

	policy, err := h.store.Update(name, req.Description, req.Policy)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update policy")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userInfo := h.getUserInfo(c)
	h.logger.WithFields(logrus.Fields{
		"user_id":     userInfo.Subject,
		"user_email":  userInfo.Email,
		"policy_name": name,
	}).Info("Policy updated")

	// Sync affected groups - find all groups using this policy and update their IAM policies
	if h.groupStore != nil {
		affectedGroups := h.groupStore.GetGroupsUsingPolicy(name)
		if len(affectedGroups) > 0 {
			h.logger.WithFields(logrus.Fields{
				"policy":          name,
				"affected_groups": len(affectedGroups),
			}).Info("Policy updated - file watcher will trigger full sync")
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"policy": PolicyResponse{
			Name:        policy.Name,
			Description: policy.Description,
			Policy:      policy.Policy,
		},
		"message": "Policy updated successfully",
	})
}

// DeletePolicy deletes a policy
func (h *PolicyHandler) DeletePolicy(c *gin.Context) {
	// Only admin users can manage policies
	if !h.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin role required to manage policies"})
		return
	}

	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy name is required"})
		return
	}

	if err := h.store.Delete(name); err != nil {
		h.logger.WithError(err).Error("Failed to delete policy")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userInfo := h.getUserInfo(c)
	h.logger.WithFields(logrus.Fields{
		"user_id":     userInfo.Subject,
		"user_email":  userInfo.Email,
		"policy_name": name,
	}).Info("Policy deleted")

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted successfully"})
}

// ValidatePolicy validates a policy without saving it
func (h *PolicyHandler) ValidatePolicy(c *gin.Context) {
	// Only admin users can manage policies
	if !h.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin role required to manage policies"})
		return
	}

	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Validate policy JSON
	if err := store.ValidatePolicyJSON(req.Policy); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "Policy is valid",
	})
}

// getUserInfo extracts user info from context
func (h *PolicyHandler) getUserInfo(c *gin.Context) *auth.UserInfo {
	userInfoValue, exists := c.Get("userInfo")
	if !exists {
		return nil
	}

	userInfo, ok := userInfoValue.(*auth.UserInfo)
	if !ok {
		return nil
	}

	return userInfo
}

// isAdmin checks if the user has admin role (global admin or tenant admin)
func (h *PolicyHandler) isAdmin(c *gin.Context) bool {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return false
	}

	return userInfo.Role == auth.UserRoleGlobalAdmin || userInfo.Role == auth.UserRoleTenantAdmin
}
