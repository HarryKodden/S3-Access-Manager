package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

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

// TokenExchangeRequest represents the request for token exchange
type TokenExchangeRequest struct {
	Code         string `json:"code" binding:"required"`
	CodeVerifier string `json:"code_verifier" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
}

// TokenExchangeResponse represents the response with tokens
type TokenExchangeResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// GetOIDCConfig returns the OIDC configuration for the frontend
func (h *OIDCConfigHandler) GetOIDCConfig(c *gin.Context) {
	response := OIDCConfigResponse{
		Issuer:   h.config.OIDC.Issuer,
		ClientID: h.config.OIDC.ClientID,
		Scopes:   h.config.OIDC.Scopes,
	}

	c.JSON(http.StatusOK, response)
}

// ExchangeToken handles the OIDC token exchange
func (h *OIDCConfigHandler) ExchangeToken(c *gin.Context) {
	var req TokenExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Discover token endpoint
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", h.config.OIDC.Issuer)
	resp, err := http.Get(discoveryURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to discover OIDC endpoints"})
		return
	}
	defer resp.Body.Close()

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse discovery document"})
		return
	}

	tokenEndpoint, ok := discovery["token_endpoint"].(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token endpoint not found"})
		return
	}

	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", req.Code)
	data.Set("redirect_uri", req.RedirectURI)
	data.Set("client_id", h.config.OIDC.ClientID)
	data.Set("client_secret", h.config.OIDC.ClientSecret)
	data.Set("code_verifier", req.CodeVerifier)

	// Make token request
	tokenResp, err := http.Post(tokenEndpoint, "application/x-www-form-urlencoded", bytes.NewBufferString(data.Encode()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token request failed"})
		return
	}
	defer tokenResp.Body.Close()

	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read token response"})
		return
	}

	if tokenResp.StatusCode != http.StatusOK {
		c.JSON(tokenResp.StatusCode, gin.H{"error": string(body)})
		return
	}

	var tokenResponse TokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token response"})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}
