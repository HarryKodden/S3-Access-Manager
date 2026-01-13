package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/backend"
	"github.com/sirupsen/logrus"
)

// UserHandler handles user management endpoints (admin only)
type UserHandler struct {
	userManager   backend.UserManager
	adminUsername string
	logger        *logrus.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userManager backend.UserManager, adminUsername string, logger *logrus.Logger) *UserHandler {
	return &UserHandler{
		userManager:   userManager,
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

	// Check if user is admin
	if userInfo.Email != h.adminUsername {
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

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"count": len(users),
	})
}

// DeleteUser deletes a user and all their access keys (admin only)
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userInfo := h.getUserInfo(c)
	if userInfo == nil {
		return
	}

	// Check if user is admin
	if userInfo.Email != h.adminUsername {
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
