package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RequestLogger creates a logging middleware
func RequestLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(startTime)

		// Get user info if available
		userID := ""
		if userInfo, exists := c.Get("userInfo"); exists {
			if ui, ok := userInfo.(*interface{}); ok {
				userID = "authenticated"
				_ = ui
			}
		}

		// Log request
		logger.WithFields(logrus.Fields{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"latency_ms": latency.Milliseconds(),
			"client_ip":  c.ClientIP(),
			"user_id":    userID,
			"user_agent": c.Request.UserAgent(),
		}).Info("Request completed")
	}
}
