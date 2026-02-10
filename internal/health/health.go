package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/sram"
	"github.com/sirupsen/logrus"
)

// TenantHealth represents the health status of a tenant
type TenantHealth struct {
	Name            string    `json:"name"`
	Healthy         bool      `json:"healthy"`
	AdminAccepted   bool      `json:"admin_accepted"`
	IAMWorking      bool      `json:"iam_working"`
	CollaborationID string    `json:"collaboration_id,omitempty"`
	SRAMConfigured  bool      `json:"sram_configured"`
	LastChecked     time.Time `json:"last_checked"`
	Error           string    `json:"error,omitempty"`
}

// GlobalHealth represents the overall system health
type GlobalHealth struct {
	Healthy       bool                    `json:"healthy"`
	SRAMConnected bool                    `json:"sram_connected"`
	SRAMError     string                  `json:"sram_error,omitempty"`
	TenantHealth  map[string]TenantHealth `json:"tenant_health"`
	LastChecked   time.Time               `json:"last_checked"`
}

// Checker manages health checks with caching
type Checker struct {
	cfg             *config.Config
	logger          *logrus.Logger
	sramClient      *sram.Client
	refreshInterval time.Duration
	globalHealth    *GlobalHealth
	mu              sync.RWMutex
	lastCheck       time.Time
}

// NewChecker creates a new health checker
func NewChecker(cfg *config.Config, logger *logrus.Logger, refreshInterval time.Duration) *Checker {
	var sramClient *sram.Client
	if cfg.SRAM.Enabled {
		sramClient = sram.NewClient(cfg.SRAM.APIURL, cfg.SRAM.APIKey)
	}

	return &Checker{
		cfg:             cfg,
		logger:          logger,
		sramClient:      sramClient,
		refreshInterval: refreshInterval,
		globalHealth: &GlobalHealth{
			TenantHealth: make(map[string]TenantHealth),
		},
	}
}

// GetHealth returns the current health status, refreshing if needed
func (h *Checker) GetHealth() *GlobalHealth {
	h.mu.RLock()
	if time.Since(h.lastCheck) < h.refreshInterval && h.globalHealth != nil {
		defer h.mu.RUnlock()
		return h.globalHealth
	}
	h.mu.RUnlock()

	// Need to refresh
	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(h.lastCheck) < h.refreshInterval && h.globalHealth != nil {
		return h.globalHealth
	}

	h.refreshHealth()
	return h.globalHealth
}

// ForceRefresh forces an immediate health check refresh
func (h *Checker) ForceRefresh() *GlobalHealth {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.refreshHealth()
	return h.globalHealth
}

// refreshHealth performs the actual health check (must be called with lock held)
func (h *Checker) refreshHealth() {
	h.logger.Debug("Refreshing health check")

	health := &GlobalHealth{
		Healthy:      true,
		TenantHealth: make(map[string]TenantHealth),
		LastChecked:  time.Now(),
	}

	// Check SRAM connection if enabled
	if h.cfg.SRAM.Enabled && h.sramClient != nil {
		health.SRAMConnected = h.checkSRAMConnection()
		if !health.SRAMConnected {
			health.Healthy = false
			health.SRAMError = "SRAM API connection failed"
		}
	} else {
		health.SRAMConnected = true // Not applicable
	}

	// Check each tenant
	for _, tenant := range h.cfg.Tenants {
		tenantHealth := h.checkTenantHealth(tenant)
		health.TenantHealth[tenant.Name] = tenantHealth
		if !tenantHealth.Healthy {
			health.Healthy = false
		}
	}

	h.globalHealth = health
	h.lastCheck = time.Now()
}

// checkSRAMConnection checks if SRAM API is reachable
func (h *Checker) checkSRAMConnection() bool {
	// Try a simple API call to verify connectivity
	// We'll use a dummy collaboration lookup that should return 404 but proves connection works
	_, err := h.sramClient.GetCollaboration("00000000-0000-0000-0000-000000000000")

	// We expect a 404, but any HTTP response means SRAM is reachable
	if err != nil {
		errStr := err.Error()
		// If we get a 404, that's actually good - SRAM is responding
		// Check if error message contains "404"
		if len(errStr) >= 3 {
			for i := 0; i <= len(errStr)-3; i++ {
				if errStr[i:i+3] == "404" {
					return true
				}
			}
		}
		h.logger.WithError(err).Debug("SRAM connection check returned error (expected for dummy ID)")
		return false
	}
	return true
}

// checkTenantHealth checks the health of a specific tenant
func (h *Checker) checkTenantHealth(tenant config.TenantConfig) TenantHealth {
	health := TenantHealth{
		Name:        tenant.Name,
		Healthy:     false,
		LastChecked: time.Now(),
	}

	// Get collaboration ID from tenant config
	tenantCfg, err := config.LoadTenantConfig(tenant.Name)
	if err != nil {
		health.Error = fmt.Sprintf("Failed to load tenant config: %v", err)
		return health
	}

	health.CollaborationID = tenantCfg.SRAMCollaborationID

	// Check if at least one admin has accepted invitation
	if h.cfg.SRAM.Enabled && h.sramClient != nil && tenantCfg.SRAMCollaborationID != "" {
		health.SRAMConfigured = true
		health.AdminAccepted = h.checkAdminAccepted(tenantCfg.SRAMCollaborationID)
	} else {
		health.SRAMConfigured = false
		health.AdminAccepted = false // SRAM not configured, so no admin accepted yet
	}

	// Check if IAM credentials are working (optional)
	iamConfigured := tenantCfg.IAM.AccessKey != "" && tenantCfg.IAM.SecretKey != ""
	if iamConfigured {
		health.IAMWorking = h.checkIAMCredentials(tenant.Name, tenantCfg)
	} else {
		// IAM not configured - cannot be working
		health.IAMWorking = false
		health.Error = ""
	}

	// Tenant is healthy if:
	// - Always healthy (SRAM admin acceptance is configuration, not health)
	health.Healthy = true

	return health
}

// checkAdminAccepted checks if at least one admin member is active in the collaboration
// Note: Once an invitation is accepted, it's removed from the invitations list and the
// user becomes an active member in the collaboration_memberships list
func (h *Checker) checkAdminAccepted(collaborationIdentifier string) bool {
	collaboration, err := h.sramClient.GetCollaboration(collaborationIdentifier, h.cfg.OIDC.ClientID)
	if err != nil {
		h.logger.WithError(err).Warn("Failed to get collaboration details")
		return false
	}

	// Check if there are any active admin members in the collaboration_memberships array
	for _, membership := range collaboration.Memberships {
		if membership.Role == "admin" && membership.Status == "active" {
			return true
		}
	}

	return false
}

// checkIAMCredentials tests if IAM credentials are working
func (h *Checker) checkIAMCredentials(tenantName string, tenantCfg *config.TenantConfig) bool {
	// Create IAM client with tenant's IAM credentials
	iamClient, err := s3client.NewIAMClient(h.cfg.S3, tenantCfg.IAM, h.logger)
	if err != nil {
		h.logger.WithError(err).Warn("Failed to create IAM client for health check")
		return false
	}

	// Try to list users (simple operation to test credentials)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = iamClient.ListUsers(ctx)
	if err != nil {
		h.logger.WithError(err).WithField("tenant", tenantName).Warn("IAM credentials check failed")
		return false
	}

	return true
}
