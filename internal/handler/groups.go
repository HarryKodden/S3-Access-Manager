package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/harrykodden/s3-gateway/internal/auth"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/harrykodden/s3-gateway/internal/sync"
	"github.com/sirupsen/logrus"
)

// GroupHandler handles group management requests
type GroupHandler struct {
	groupStore    *store.GroupStore
	userStore     *store.UserStore
	policyStore   *store.PolicyStore
	groupManager  interface{} // GroupManager for backend operations
	logger        *logrus.Logger
	policiesDir   string
	syncService   interface{} // SyncService for SCIM synchronization
	adminUsername string      // Admin username for RBAC
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(groupStore *store.GroupStore, userStore *store.UserStore, policyStore *store.PolicyStore, groupManager interface{}, policiesDir string, syncService interface{}, adminUsername string, logger *logrus.Logger) *GroupHandler {
	return &GroupHandler{
		groupStore:    groupStore,
		userStore:     userStore,
		policyStore:   policyStore,
		groupManager:  groupManager,
		policiesDir:   policiesDir,
		syncService:   syncService,
		adminUsername: adminUsername,
		logger:        logger,
	}
}

// ListGroups returns all groups with backend sync status
// For non-admin users, only returns groups matching their OIDC groups
func (h *GroupHandler) ListGroups(c *gin.Context) {
	// Get user info from context
	userInfoValue, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User info not found"})
		return
	}
	userInfo := userInfoValue.(*auth.UserInfo)

	// Check if user is admin
	isAdmin := h.adminUsername != "" && userInfo.Email == h.adminUsername

	localGroups := h.groupStore.List()

	// Prepare response with backend status
	type GroupWithStatus struct {
		store.Group
		BackendStatus string `json:"backend_status"` // "OK", "Missing", "PolicyMismatch", "Unknown"
		Scim          bool   `json:"scim"`           // Whether this group is SCIM-managed
		ScimId        string `json:"scim_id"`        // SCIM group ID
	}

	var groupsWithStatus []GroupWithStatus

	// Get backend groups if groupManager is available
	var backendGroups []string
	if h.groupManager != nil {
		if gm, ok := h.groupManager.(*awscli.GroupManager); ok {
			var err error
			backendGroups, err = gm.ListGroups(c.Request.Context())
			if err != nil {
				h.logger.WithError(err).Warn("Failed to list backend groups")
			} else {
				h.logger.WithField("backend_groups", backendGroups).Debug("Retrieved backend groups")
			}
		} else {
			h.logger.Warn("Group manager is not AWS CLI group manager")
		}
	} else {
		h.logger.Warn("Group manager is nil")
	}

	for _, group := range localGroups {
		// If this group has a SCIM group ID, populate the name from SCIM data
		if group.ScimGroupId != "" {
			if scimGroup, exists := h.userStore.GetGroupByID(group.ScimGroupId); exists {
				group.Name = scimGroup.DisplayName
			} else {
				h.logger.WithField("scimGroupId", group.ScimGroupId).Warn("SCIM group not found for policy group")
			}
		}
		status := "Unknown"

		if len(backendGroups) > 0 {
			// Check if group exists in backend
			iamGroupName := group.Name
			if group.ScimGroupId != "" {
				iamGroupName = group.ScimGroupId
			}
			// For non-admin users, only include groups that match their OIDC groups
			if !isAdmin {
				// Check if this group's SCIM ID matches any of the user's groups
				if group.ScimGroupId == "" {
					// Skip non-SCIM groups for non-admin users
					continue
				}
				matchesUserGroup := false
				for _, userGroup := range userInfo.OriginalGroups {
					if group.ScimGroupId == userGroup {
						matchesUserGroup = true
						break
					}
				}
				if !matchesUserGroup {
					continue
				}
			}

			existsInBackend := false
			for _, backendGroup := range backendGroups {
				if backendGroup == iamGroupName {
					existsInBackend = true
					break
				}
			}

			if !existsInBackend {
				status = "Missing"
			} else {
				// Group exists, check if policy matches
				if gm, ok := h.groupManager.(*awscli.GroupManager); ok {
					backendPolicy, err := gm.GetGroupPolicy(c.Request.Context(), iamGroupName, fmt.Sprintf("%s-policy", iamGroupName))
					if err != nil {
						h.logger.WithError(err).WithField("group", iamGroupName).Warn("Failed to get backend policy")
						status = "Error"
					} else {
						localPolicy, err := h.combineGroupPolicies(group.Policies)
						if err != nil {
							h.logger.WithError(err).WithField("group", iamGroupName).Warn("Failed to combine local policies")
							status = "Error"
						} else if h.policiesEqual(backendPolicy, localPolicy) {
							status = "OK"
						} else {
							status = "PolicyMismatch"
						}
					}
				}
			}
		} else {
			// No backend groups available - still filter for non-admin users
			if !isAdmin {
				if group.ScimGroupId == "" {
					continue
				}
				matchesUserGroup := false
				for _, userGroup := range userInfo.OriginalGroups {
					if group.ScimGroupId == userGroup {
						matchesUserGroup = true
						break
					}
				}
				if !matchesUserGroup {
					continue
				}
			}
		}

		groupsWithStatus = append(groupsWithStatus, GroupWithStatus{
			Group:         *group,
			BackendStatus: status,
			Scim:          group.ScimGroupId != "",
			ScimId:        group.ScimGroupId,
		})
	}

	h.logger.WithField("count", len(groupsWithStatus)).Debug("Listed groups with backend status")

	c.JSON(http.StatusOK, gin.H{"groups": groupsWithStatus})
}

// ListSCIMGroups returns all SCIM groups
func (h *GroupHandler) ListSCIMGroups(c *gin.Context) {
	scimGroups := h.userStore.GetAllGroups()

	type SCIMGroupResponse struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		MemberCount int    `json:"memberCount"`
	}

	var response []SCIMGroupResponse
	for _, group := range scimGroups {
		response = append(response, SCIMGroupResponse{
			ID:          group.ID,
			DisplayName: group.DisplayName,
			MemberCount: len(group.Members),
		})
	}

	h.logger.WithField("count", len(response)).Debug("Listed all SCIM groups")
	c.JSON(http.StatusOK, gin.H{"Resources": response})
}

// combineGroupPolicies combines policy documents from multiple policies into one
func (h *GroupHandler) combineGroupPolicies(policyNames []string) (map[string]interface{}, error) {
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
func (h *GroupHandler) loadPolicyDocument(policyName string) (map[string]interface{}, error) {
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
func (h *GroupHandler) policiesEqual(a, b map[string]interface{}) bool {
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

// GetGroup returns a specific group
func (h *GroupHandler) GetGroup(c *gin.Context) {
	name := c.Param("name")

	// First try to get the group directly by SCIM ID
	group, err := h.groupStore.Get(name)
	if err == nil {
		// Found group by SCIM ID
		c.JSON(http.StatusOK, gin.H{"group": group})
		return
	}

	// If not found by SCIM ID, try to find by display name
	var scimGroupId string
	if scimGroup, exists := h.userStore.GetGroupByDisplayName(name); exists {
		scimGroupId = scimGroup.ID
	} else {
		// Try to find a local group with this display name
		localGroups := h.groupStore.List()
		for _, g := range localGroups {
			if g.Name == name {
				scimGroupId = g.ScimGroupId
				break
			}
		}
	}

	if scimGroupId == "" {
		h.logger.WithField("name", name).Warn("Group not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	group, err = h.groupStore.Get(scimGroupId)
	if err != nil {
		h.logger.WithError(err).WithField("scimGroupId", scimGroupId).Warn("Group not found in store")
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"group": group})
}

// CreateGroup creates a new group
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Policies    []string `json:"policies"`
		ScimGroupId string   `json:"scim_group_id,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Invalid group request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// If scim_group_id is provided, look up the display name from SCIM
	if req.ScimGroupId != "" {
		if _, exists := h.userStore.GetGroupByID(req.ScimGroupId); !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SCIM group ID"})
			return
		}
	}

	// Validate
	if req.ScimGroupId == "" && req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group name is required for non-SCIM groups"})
		return
	}
	if req.ScimGroupId != "" && req.Name != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name should not be provided for SCIM groups"})
		return
	}

	// For SCIM groups, don't store the name in JSON - it will be derived from SCIM
	// For legacy groups, use the provided name
	groupName := ""
	if req.ScimGroupId == "" {
		groupName = req.Name
	}

	group := store.Group{
		Name:        groupName, // Empty for SCIM groups
		Description: req.Description,
		Policies:    req.Policies,
		ScimGroupId: req.ScimGroupId,
	}

	if err := h.groupStore.Create(&group); err != nil {
		h.logger.WithError(err).WithField("name", group.Name).Warn("Failed to create group")
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithField("name", group.Name).Info("Group created")

	// Trigger targeted sync to push only this group to S3 IAM
	if h.syncService != nil {
		if syncSvc, ok := h.syncService.(*sync.SyncService); ok {
			go func() {
				if err := syncSvc.SyncGroup(context.Background(), group.ScimGroupId); err != nil {
					h.logger.WithError(err).Error("Failed to sync group after creation")
				} else {
					h.logger.Info("Group sync completed after creation")
				}
			}()
		}
	}

	c.JSON(http.StatusCreated, group)
}

// UpdateGroup updates an existing group
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	name := c.Param("name")

	// First try to get the group directly by SCIM ID
	var scimGroupId string
	if _, err := h.groupStore.Get(name); err == nil {
		// Name is a valid SCIM ID
		scimGroupId = name
	} else {
		// Try to find by display name
		if scimGroup, exists := h.userStore.GetGroupByDisplayName(name); exists {
			scimGroupId = scimGroup.ID
		} else {
			// Try to find a local group with this display name
			localGroups := h.groupStore.List()
			for _, g := range localGroups {
				if g.Name == name {
					scimGroupId = g.ScimGroupId
					break
				}
			}
		}
	}

	if scimGroupId == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var group store.Group
	if err := c.ShouldBindJSON(&group); err != nil {
		h.logger.WithError(err).Warn("Invalid group request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Get the existing group to preserve current data
	existingGroup, err := h.groupStore.Get(scimGroupId)
	if err != nil {
		h.logger.WithError(err).WithField("scimGroupId", scimGroupId).Warn("Group not found in store")
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Update only description and policies for SCIM groups (name is derived from SCIM)
	existingGroup.Description = group.Description
	existingGroup.Policies = group.Policies

	// Special handling for SCIM groups: if policies become empty, remove the group assignment
	if existingGroup.ScimGroupId != "" && len(group.Policies) == 0 {
		// Delete the group from store (removes the file)
		if err := h.groupStore.Delete(scimGroupId); err != nil {
			h.logger.WithError(err).WithField("scimGroupId", scimGroupId).Warn("Failed to delete group from store")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove group assignment"})
			return
		}

		// Delete the group policy from S3 IAM
		if h.groupManager != nil {
			if gm, ok := h.groupManager.(*awscli.GroupManager); ok {
				policyName := fmt.Sprintf("%s-policy", name)
				if err := gm.DeleteGroupPolicy(c.Request.Context(), name, policyName); err != nil {
					h.logger.WithError(err).WithFields(logrus.Fields{
						"group":  name,
						"policy": policyName,
					}).Warn("Failed to delete group policy from S3")
					// Don't fail the request, just log the warning
				} else {
					h.logger.WithFields(logrus.Fields{
						"group":  name,
						"policy": policyName,
					}).Info("Deleted group policy from S3")
				}
			}
		}

		h.logger.WithField("name", name).Info("Group policy assignment removed (SCIM group now available for reassignment)")

		// No need to trigger sync since we removed the assignment
		c.JSON(http.StatusOK, gin.H{"message": "Group policy assignment removed successfully"})
		return
	}

	if err := h.groupStore.Update(existingGroup); err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Failed to update group")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithField("name", name).Info("Group updated")

	// Trigger targeted sync to update only this group's policy in S3 IAM
	if h.syncService != nil {
		if syncSvc, ok := h.syncService.(*sync.SyncService); ok {
			go func() {
				if err := syncSvc.SyncGroupPolicy(context.Background(), existingGroup.ScimGroupId); err != nil {
					h.logger.WithError(err).Error("Failed to sync group policy after update")
				} else {
					h.logger.Info("Group policy sync completed after update")
				}
			}()
		}
	}

	c.JSON(http.StatusOK, group)
}

// DeleteGroup deletes a group
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	name := c.Param("name")

	// Get the group before deleting to get SCIM ID
	group, err := h.groupStore.Get(name)
	if err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Group not found for deletion")
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	// Delete from store
	if err := h.groupStore.Delete(name); err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Failed to delete group")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Delete from S3 IAM and cleanup credentials
	if h.syncService != nil {
		if syncSvc, ok := h.syncService.(*sync.SyncService); ok {
			// Note: Using synchronous call here to ensure cleanup before response
			if err := syncSvc.DeleteGroupAndCleanup(context.Background(), group.ScimGroupId); err != nil {
				h.logger.WithError(err).Error("Failed to cleanup group from S3 IAM")
				// Continue anyway - local deletion succeeded
			}
		}
	}

	h.logger.WithField("name", name).Info("Group deleted")
	c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
}
