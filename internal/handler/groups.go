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

// ListRoles returns all groups with backend sync status
// For non-admin users, only returns groups matching their OIDC groups
func (h *GroupHandler) ListRoles(c *gin.Context) {
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
						// Policy doesn't exist or can't be retrieved - try to create and attach it
						h.logger.WithError(err).WithField("group", iamGroupName).Warn("Failed to get backend policy, attempting to create/attach policy")
						if attachErr := h.createAndAttachGroupPolicy(c.Request.Context(), gm, iamGroupName, group.Policies); attachErr != nil {
							h.logger.WithError(attachErr).WithField("group", iamGroupName).Error("Failed to create/attach policy during status check")
							status = "Error"
						} else {
							h.logger.WithField("group", iamGroupName).Info("Successfully created/attached policy during status check")
							status = "OK"
						}
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

	// If scim_group_id is provided, validate it exists in local SCIM store
	// Note: For SRAM groups (UUIDs), we don't validate here as they come from SRAM API
	if req.ScimGroupId != "" {
		// Check if it's a local SCIM group (exists in userStore)
		// SRAM group IDs are UUIDs and won't be in the local store
		if _, exists := h.userStore.GetGroupByID(req.ScimGroupId); !exists {
			// If not found in local store, assume it's an SRAM group ID (UUID format)
			// SRAM groups are validated when fetched from SRAM API, so we accept them here
			h.logger.WithField("scim_group_id", req.ScimGroupId).Debug("Group ID not in local SCIM store, assuming SRAM group")
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

	// Create IAM group in backend if groupManager is available
	if h.groupManager != nil {
		if gm, ok := h.groupManager.(*awscli.GroupManager); ok {
			iamGroupName := group.Name
			if group.ScimGroupId != "" {
				iamGroupName = group.ScimGroupId
			}

			if err := gm.CreateGroup(c.Request.Context(), iamGroupName); err != nil {
				h.logger.WithError(err).WithField("group", iamGroupName).Warn("Failed to create IAM group, continuing anyway")
				// Don't fail the request - the group exists locally and will show as "Missing" status
			} else {
				h.logger.WithField("group", iamGroupName).Info("Created IAM group")
			}

			// Always try to create and attach the group policy, even if group creation failed (group might already exist)
			if err := h.createAndAttachGroupPolicy(c.Request.Context(), gm, iamGroupName, group.Policies); err != nil {
				h.logger.WithError(err).WithField("group", iamGroupName).Warn("Failed to attach group policy")
			}
		}
	}

	h.logger.WithField("name", group.Name).Info("Group created")

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

	c.JSON(http.StatusOK, group)
}

// DeleteGroup deletes a group
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	name := c.Param("name")

	// Delete from store
	if err := h.groupStore.Delete(name); err != nil {
		h.logger.WithError(err).WithField("name", name).Warn("Failed to delete group")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithField("name", name).Info("Group deleted")
	c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
}

// createAndAttachGroupPolicy creates a policy document from the group's policies and attaches it to the IAM group
func (h *GroupHandler) createAndAttachGroupPolicy(ctx context.Context, gm *awscli.GroupManager, iamGroupName string, policyNames []string) error {
	if len(policyNames) == 0 {
		h.logger.WithField("group", iamGroupName).Debug("No policies to attach to group")
		return nil
	}

	// Combine all policy documents
	var policyDocuments []map[string]interface{}
	for _, policyName := range policyNames {
		policyDoc, err := h.policyStore.Get(policyName)
		if err != nil {
			h.logger.WithError(err).WithField("policy", policyName).Warn("Failed to get policy document for group")
			continue
		}
		policyDocuments = append(policyDocuments, policyDoc.Policy)
	}

	if len(policyDocuments) == 0 {
		h.logger.WithField("group", iamGroupName).Warn("No valid policy documents found for group")
		return fmt.Errorf("no valid policies found")
	}

	// Combine policies
	combinedPolicy, err := h.combineGroupPolicies(policyNames)
	if err != nil {
		h.logger.WithError(err).WithField("group", iamGroupName).Warn("Failed to combine group policies")
		return fmt.Errorf("failed to combine policies: %w", err)
	}

	// Create the group policy
	policyName := fmt.Sprintf("%s-policy", iamGroupName)
	if err := gm.PutGroupPolicy(ctx, iamGroupName, policyName, combinedPolicy); err != nil {
		return fmt.Errorf("failed to put group policy: %w", err)
	}

	h.logger.WithFields(logrus.Fields{
		"group":        iamGroupName,
		"policy_name":  policyName,
		"policy_count": len(policyNames),
	}).Info("Attached combined policy to IAM group")

	return nil
}
