package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/sync"
	"github.com/sirupsen/logrus"
)

// UserSync creates a middleware that syncs IAM users and policies after authentication
func Sync(syncService *sync.SyncService, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user info from context (set by auth middleware)
		userInfoVal, exists := c.Get("userInfo")
		if !exists {
			logger.Warn("UserSync middleware called but no userInfo in context")
			c.Next()
			return
		}

		userInfo, ok := userInfoVal.(*auth.UserInfo)
		if !ok {
			logger.Warn("UserSync middleware: userInfo has wrong type")
			c.Next()
			return
		}

		// Sync user and policies asynchronously to not block request
		// Use context.Background() instead of request context to avoid cancellation
		go func() {
			if err := syncService.SyncUser(context.Background(), userInfo); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"username": userInfo.Email,
					"groups":   userInfo.Groups,
				}).Warn("Failed to sync IAM user/policies")
			}
		}()

		c.Next()
	}
}
