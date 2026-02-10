package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/backend"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/sirupsen/logrus"
)

// UserHandler handles user management endpoints (admin only)
type UserHandler struct {
	userManager   backend.UserManager
	userStore     *store.UserStore
	adminUsername string
	logger        *logrus.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userManager backend.UserManager, userStore *store.UserStore, adminUsername string, logger *logrus.Logger) *UserHandler {
	return &UserHandler{
		userManager:   userManager,
		userStore:     userStore,
		adminUsername: adminUsername,
		logger:        logger,
	}
}

// ListUsers lists all users (admin only)
func (h *UserHandler) ListUsers(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	// Check if user is admin (global admin or tenant admin)
	if userInfo.Role != auth.UserRoleGlobalAdmin && userInfo.Role != auth.UserRoleTenantAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	if h.userManager == nil {
		c.JSON(http.StatusOK, gin.H{
			"users":   []string{},
			"count":   0,
			"message": "User management not available for this backend",
		})
		return
	}

	// List all users
	users, err := h.userManager.ListUsers(c.Request.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	// Check which users are SCIM-managed
	userDetails := make([]gin.H, 0, len(users))
	for _, username := range users {
		_, isSCIM := h.userStore.GetUserByUserName(username)
		userDetails = append(userDetails, gin.H{
			"username": username,
			"scim":     isSCIM,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"users": userDetails,
		"count": len(users),
	})
}

// GetUserDetails returns detailed information about a specific user (admin only)
func (h *UserHandler) GetUserDetails(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	// Check if user is admin (global admin or tenant admin)
	if userInfo.Role != auth.UserRoleGlobalAdmin && userInfo.Role != auth.UserRoleTenantAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	if h.userManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User management not available for this backend"})
		return
	}

	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	// Get detailed user information
	details, err := h.userManager.GetUserDetails(c.Request.Context(), username)
	if err != nil {
		h.logger.WithError(err).WithField("username", username).Error("Failed to get user details")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user details"})
		return
	}

	// Add SCIM details if available
	if scimUser, exists := h.userStore.GetUserByUserName(username); exists {
		details.ScimDetails = &backend.ScimUserDetails{
			ID:          scimUser.ID,
			DisplayName: scimUser.DisplayName,
			Email:       scimUser.UserName, // SCIM username is email
		}

		// Get SCIM groups for this user
		details.ScimDetails.Groups = h.userStore.GetUserGroups(username)
	}

	c.JSON(http.StatusOK, details)
}

// DeleteUser deletes a user and all their access keys (admin only)
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	// Check if user is admin (global admin or tenant admin)
	if userInfo.Role != auth.UserRoleGlobalAdmin && userInfo.Role != auth.UserRoleTenantAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	if h.userManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User management not available for this backend"})
		return
	}

	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	// Prevent admin from deleting themselves
	if username == h.adminUsername {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete admin user"})
		return
	}

	// Prevent deletion of SCIM-managed users
	if _, exists := h.userStore.GetUserByUserName(username); exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete SCIM-managed user"})
		return
	}

	// Delete the user
	if err := h.userManager.DeleteUser(c.Request.Context(), username); err != nil {
		h.logger.WithError(err).WithField("username", username).Error("Failed to delete user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"admin":    userInfo.Email,
		"username": username,
	}).Info("User deleted by admin")

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// getUserInfo is a helper to extract user info from context
func (h *UserHandler) getUserInfo(c *gin.Context) *auth.UserInfo {
	userInfoVal, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User information not found"})
		return nil
	}

	userInfo, ok := userInfoVal.(*auth.UserInfo)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user information"})
		return nil
	}

	return userInfo
}
