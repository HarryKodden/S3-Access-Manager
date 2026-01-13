package handler

import (
	"net/http"

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
}

// GetOIDCConfig returns the OIDC configuration for the frontend
func (h *OIDCConfigHandler) GetOIDCConfig(c *gin.Context) {
	response := OIDCConfigResponse{
		Issuer:   h.config.OIDC.Issuer,
		ClientID: h.config.OIDC.ClientID,
	}

	c.JSON(http.StatusOK, response)
}
