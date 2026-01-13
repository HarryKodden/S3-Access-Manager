package middleware

import (
	"github.com/harrykodden/s3-gateway/internal/config"

	"github.com/gin-gonic/gin"
)

// CORS creates a CORS middleware
func CORS(cfg config.SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.CORSEnabled {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			c.Next()
			return
		}

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range cfg.CORSOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if !allowed {
			c.Next()
			return
		}

		// Set CORS headers
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
		c.Header("Access-Control-Max-Age", "86400")

		// Handle preflight
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
