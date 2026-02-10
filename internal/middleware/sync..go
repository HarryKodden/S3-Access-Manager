package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Sync creates a middleware that does nothing (sync is now handled by file watcher only)
func Sync(syncService interface{}, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Sync is now handled exclusively by the file watcher
		// when SCIM data files change. This removes the complexity
		// of per-request user sync.
		c.Next()
	}
}
