package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// TenantContextKey is the key used to store tenant information in gin context
const TenantContextKey = "tenant"

// TenantValidator is a function that checks if a tenant name is valid
type TenantValidator func(tenantName string) bool

// TenantAuth creates a tenant authentication middleware that extracts tenant from URL path
func TenantAuth(tenantValidator TenantValidator, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if path starts with /tenant/
		if !strings.HasPrefix(path, "/tenant/") {
			logger.WithField("path", path).Warn("Request does not include tenant prefix")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant prefix required in URL path"})
			c.Abort()
			return
		}

		// Extract tenant name from path: /tenant/{tenant}/...
		parts := strings.Split(strings.TrimPrefix(path, "/tenant/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			logger.WithField("path", path).Warn("Invalid tenant path format")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant path format"})
			c.Abort()
			return
		}

		tenantName := parts[0]

		// Validate tenant using the validator function
		if !tenantValidator(tenantName) {
			logger.WithFields(logrus.Fields{
				"path":      path,
				"requested": tenantName,
			}).Warn("Invalid tenant requested")
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			c.Abort()
			return
		}

		// Store tenant in context
		c.Set(TenantContextKey, tenantName)

		// Remove tenant prefix from path for further processing
		newPath := strings.TrimPrefix(path, "/tenant/"+tenantName)
		if newPath == "" {
			newPath = "/"
		}
		c.Request.URL.Path = newPath

		logger.WithFields(logrus.Fields{
			"original_path": path,
			"tenant":        tenantName,
			"new_path":      newPath,
		}).Debug("Tenant extracted from URL")

		c.Next()
	}
}
