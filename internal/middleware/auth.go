package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/sirupsen/logrus"
)

// OIDCAuth creates an OIDC authentication middleware
func OIDCAuth(authenticator *auth.Authenticator, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.WithField("path", c.Request.URL.Path).Warn("Missing Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			c.Abort()
			return
		}

		logger.WithFields(logrus.Fields{
			"path":         c.Request.URL.Path,
			"token_length": len(authHeader),
		}).Debug("Authenticating request")

		// Validate access token (uses session cache if available)
		userInfo, err := authenticator.VerifyAccessToken(c.Request.Context(), authHeader)
		if err != nil {
			logger.WithError(err).WithField("path", c.Request.URL.Path).Warn("Invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Store user info in context
		c.Set("userInfo", userInfo)

		c.Next()
	}
}
