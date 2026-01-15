package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/config"
)

// OIDCConfigHandler returns public OIDC configuration
type OIDCConfigHandler struct {
	config *config.Config
}

// NewOIDCConfigHandler creates a new OIDC config handler
func NewOIDCConfigHandler(cfg *config.Config) *OIDCConfigHandler {
	return &OIDCConfigHandler{
		config: cfg,
	}
}

// OIDCConfigResponse represents the public OIDC configuration
type OIDCConfigResponse struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Scopes   string `json:"scopes"`
}

// GetOIDCConfig returns the OIDC configuration for the frontend
func (h *OIDCConfigHandler) GetOIDCConfig(c *gin.Context) {
	// Convert internal Docker network URLs to external localhost URLs for frontend access
	issuer := strings.Replace(h.config.OIDC.Issuer, "http://oidc:8888", "http://localhost:8888", 1)

	response := OIDCConfigResponse{
		Issuer:   issuer,
		ClientID: h.config.OIDC.ClientID,
		Scopes:   h.config.OIDC.Scopes,
	}

	c.JSON(http.StatusOK, response)
}
