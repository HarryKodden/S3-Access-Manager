package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/sirupsen/logrus"
)

// RoleHandler handles role management requests
type RoleHandler struct {
	roleStore   *store.RoleStore
	policyStore *store.PolicyStore
	roleManager interface{} // RoleManager for backend operations
	logger      *logrus.Logger
	policiesDir string
}

// NewRoleHandler creates a new role handler
func NewRoleHandler(roleStore *store.RoleStore, policyStore *store.PolicyStore, roleManager interface{}, policiesDir string, logger *logrus.Logger) *RoleHandler {
	return &RoleHandler{
		roleStore:   roleStore,
		policyStore: policyStore,
		roleManager: roleManager,
		policiesDir: policiesDir,
		logger:      logger,
	}
}

// ListRoles returns all roles with backend sync status
func (h *RoleHandler) ListRoles(c *gin.Context) {
	localRoles := h.roleStore.List()

	// Prepare response with backend status
	type RoleWithStatus struct {
		store.Role
		BackendStatus string `json:"backend_status"` // "OK", "Missing", "PolicyMismatch", "Unknown"
	}

	var rolesWithStatus []RoleWithStatus

	// Get backend roles if roleManager is available
	var backendRoles []string
	if h.roleManager != nil {
		if rm, ok := h.roleManager.(*awscli.RoleManager); ok {
			var err error
			backendRoles, err = rm.ListRoles(c.Request.Context())
			if err != nil {
				h.logger.WithError(err).Warn("Failed to list backend roles")
			} else {
				h.logger.WithField("backend_roles", backendRoles).Debug("Retrieved backend roles")
			}
		} else {
			h.logger.Warn("Role manager is not AWS CLI role manager")
		}
	} else {
		h.logger.Warn("Role manager is nil")
	}

	for _, role := range localRoles {
		status := "Unknown"

		if len(backendRoles) > 0 {
			// Check if role exists in backend
			existsInBackend := false
			for _, backendRole := range backendRoles {
				if backendRole == role.Name {
					existsInBackend = true
					break
				}
			}

			if !existsInBackend {
				status = "Missing"
			} else {
				// Role exists, check if policy matches
				if rm, ok := h.roleManager.(*awscli.RoleManager); ok {
					backendPolicy, err := rm.GetRolePolicy(c.Request.Context(), role.Name)
					if err != nil {
						h.logger.WithError(err).WithField("role", role.Name).Warn("Failed to get backend policy")
						status = "Error"
					} else {
						localPolicy, err := h.combineRolePolicies(role.Policies)
						if err != nil {
							h.logger.WithError(err).WithField("role", role.Name).Warn("Failed to combine local policies")
							status = "Error"
						} else if h.policiesEqual(backendPolicy, localPolicy) {
							status = "OK"
						} else {
							status = "PolicyMismatch"
						}
					}
				}
			}
		}

		rolesWithStatus = append(rolesWithStatus, RoleWithStatus{
			Role:          *role,
			BackendStatus: status,
		})
	}

	h.logger.WithField("count", len(rolesWithStatus)).Debug("Listed roles with backend status")

	c.JSON(http.StatusOK, gin.H{"roles": rolesWithStatus})
}

// combineRolePolicies combines policy documents from multiple policies into one
func (h *RoleHandler) combineRolePolicies(policyNames []string) (map[string]interface{}, error) {
	combinedStatements := []map[string]interface{}{}

	for _, policyName := range policyNames {
		policyDoc, err := h.loadPolicyDocument(policyName)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy %s: %w", policyName, err)
		}

		if statements, ok := policyDoc["Statement"].([]interface{}); ok {
			for _, stmt := range statements {
				if stmtMap, ok := stmt.(map[string]interface{}); ok {
					combinedStatements = append(combinedStatements, stmtMap)
				}
			}
		}
	}

	combinedDoc := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": combinedStatements,
	}

	return combinedDoc, nil
}

// loadPolicyDocument loads a policy document from file
func (h *RoleHandler) loadPolicyDocument(policyName string) (map[string]interface{}, error) {
	// Try different file name patterns
	patterns := []string{
		fmt.Sprintf("%s.json", policyName),
		fmt.Sprintf("%s.json", strings.ToLower(policyName)),
	}

	var policyPath string
	var found bool

	for _, pattern := range patterns {
		testPath := filepath.Join(h.policiesDir, pattern)
		if _, err := os.Stat(testPath); err == nil {
			policyPath = testPath
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("policy file not found for '%s', tried patterns: %v", policyName, patterns)
	}

	// Read and parse policy file
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", policyPath, err)
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal(policyData, &policyDoc); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON from %s: %w", policyPath, err)
	}

	return policyDoc, nil
}

// policiesEqual compares two policy documents for equality
func (h *RoleHandler) policiesEqual(a, b map[string]interface{}) bool {
	aJSON, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bJSON, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return reflect.DeepEqual(aJSON, bJSON)
}

// GetRole returns a specific role
func (h *RoleHandler) GetRole(c *gin.Context) {
	name := c.Param("name")

	role, err := h.roleStore.Get(name)
	if err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Role not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"role": role})
}

// CreateRole creates a new role
func (h *RoleHandler) CreateRole(c *gin.Context) {
	var role store.Role
	if err := c.ShouldBindJSON(&role); err != nil {
		h.logger.WithError(err).Warn("Invalid role request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate
	if role.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role name is required"})
		return
	}

	if err := h.roleStore.Create(&role); err != nil {
		h.logger.WithError(err).WithField("name", role.Name).Warn("Failed to create role")
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithField("name", role.Name).Info("Role created")
	c.JSON(http.StatusCreated, role)
}

// UpdateRole updates an existing role
func (h *RoleHandler) UpdateRole(c *gin.Context) {
	name := c.Param("name")

	var role store.Role
	if err := c.ShouldBindJSON(&role); err != nil {
		h.logger.WithError(err).Warn("Invalid role request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Ensure name matches URL parameter
	if role.Name != name {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role name mismatch"})
		return
	}

	if err := h.roleStore.Update(&role); err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Failed to update role")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithField("name", name).Info("Role updated")
	c.JSON(http.StatusOK, role)
}

// DeleteRole deletes a role
func (h *RoleHandler) DeleteRole(c *gin.Context) {
	name := c.Param("name")

	if err := h.roleStore.Delete(name); err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Failed to delete role")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithField("name", name).Info("Role deleted")
	c.JSON(http.StatusOK, gin.H{"message": "Role deleted successfully"})
}
