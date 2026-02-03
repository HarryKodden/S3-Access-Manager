package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/store"
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

// RequireAdmin creates a middleware that requires the user to be an admin
func RequireAdmin(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user info from context (set by OIDCAuth middleware)
		userInfoValue, exists := c.Get("userInfo")
		if !exists {
			logger.WithField("path", c.Request.URL.Path).Warn("User info not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User info not found"})
			c.Abort()
			return
		}

		userInfo, ok := userInfoValue.(*auth.UserInfo)
		if !ok {
			logger.WithField("path", c.Request.URL.Path).Error("Invalid user info type in context")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user info"})
			c.Abort()
			return
		}

		// Check if user is admin
		if !userInfo.IsAdmin {
			logger.WithFields(logrus.Fields{
				"path":    c.Request.URL.Path,
				"email":   userInfo.Email,
				"subject": userInfo.Subject,
			}).Warn("Non-admin user attempted to access admin endpoint")
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		logger.WithFields(logrus.Fields{
			"path":  c.Request.URL.Path,
			"email": userInfo.Email,
		}).Debug("Admin access granted")

		c.Next()
	}
}

// S3Auth creates authentication middleware that supports both OIDC and AWS access key authentication
// This allows AWS CLI users to authenticate using access keys while web UI users use OIDC
func S3Auth(authenticator *auth.Authenticator, credStore *store.CredentialStore, groupStore *store.GroupStore, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		credHeader := c.GetHeader("X-S3-Credential-AccessKey")

		// Check for AWS SigV4 authentication first (CLI users)
		if authHeader != "" && strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {

			// Extract credential part
			credStart := strings.Index(authHeader, "Credential=")
			if credStart == -1 {
				logger.WithField("path", c.Request.URL.Path).Warn("Invalid AWS4 authorization header: missing Credential")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid AWS authorization header"})
				c.Abort()
				return
			}

			credPart := authHeader[credStart+len("Credential="):]
			credEnd := strings.Index(credPart, ",")
			if credEnd == -1 {
				credEnd = len(credPart)
			}

			credential := credPart[:credEnd]

			// Extract access key from credential (first part before /)
			accessKeyID := strings.Split(credential, "/")[0]

			logger.WithFields(logrus.Fields{
				"path":       c.Request.URL.Path,
				"access_key": accessKeyID,
			}).Debug("Authenticating request with AWS SigV4 access key")

			// Look up credential by access key
			cred, err := credStore.Get(accessKeyID)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"path":       c.Request.URL.Path,
					"access_key": accessKeyID,
				}).Warn("Credential not found for access key")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access key"})
				c.Abort()
				return
			}

			logger.WithFields(logrus.Fields{
				"path":       c.Request.URL.Path,
				"access_key": accessKeyID,
				"cred_found": true,
				"user_id":    cred.UserID,
			}).Debug("Credential found for access key")

			// Get user information from credential
			// For CLI users, we need to reconstruct user info from the credential
			userInfo := &auth.UserInfo{
				Subject: cred.UserID,
				Email:   cred.UserID,
				Groups:  cred.Groups,
			}

			// Store user info and credential in context
			c.Set("userInfo", userInfo)
			c.Set("selectedCredential", cred)
			c.Set("authMethod", "access_key")
			c.Next()
			return
		}

		// Check for X-S3-Credential-AccessKey header (web UI users selecting credentials)
		if credHeader != "" {
			logger.WithFields(logrus.Fields{
				"path":       c.Request.URL.Path,
				"access_key": credHeader,
			}).Info("Authenticating request with X-S3-Credential-AccessKey header")

			// Look up credential by access key
			cred, err := credStore.Get(credHeader)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"path":       c.Request.URL.Path,
					"access_key": credHeader,
				}).Warn("Credential not found for access key")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access key"})
				c.Abort()
				return
			}

			logger.WithFields(logrus.Fields{
				"path":       c.Request.URL.Path,
				"access_key": credHeader,
				"cred_found": true,
				"user_id":    cred.UserID,
			}).Info("Credential found for access key")

			// Get user information from credential
			userInfo := &auth.UserInfo{
				Subject: cred.UserID,
				Email:   cred.UserID,
				Groups:  cred.Groups,
			}

			// Store user info and credential in context
			c.Set("userInfo", userInfo)
			c.Set("selectedCredential", cred)
			c.Set("authMethod", "credential_header")
			c.Next()
			return
		}

		// Check for OIDC token (web UI users)
		if authHeader != "" {
			logger.WithFields(logrus.Fields{
				"path":         c.Request.URL.Path,
				"token_length": len(authHeader),
			}).Debug("Authenticating request with OIDC token")

			// Validate access token (uses session cache if available)
			userInfo, err := authenticator.VerifyAccessToken(c.Request.Context(), authHeader)
			if err != nil {
				logger.WithError(err).WithField("path", c.Request.URL.Path).Warn("Invalid OIDC token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
				c.Abort()
				return
			}

			// Store user info in context
			c.Set("userInfo", userInfo)
			c.Set("authMethod", "oidc")
			c.Next()
			return
		}

		// No authentication provided
		logger.WithField("path", c.Request.URL.Path).Warn("No authentication provided")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		c.Abort()
	}
}
