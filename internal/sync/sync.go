package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/harrykodden/s3-gateway/internal/auth"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/sirupsen/logrus"
)

// SyncService synchronizes users and groups between gateway and backend
type SyncService struct {
	iamClient     *s3client.IAMClient
	groupStore    *store.GroupStore
	userStore     *store.UserStore
	credStore     *store.CredentialStore
	policiesDir   string
	adminUsername string
	groupManager  interface{}
	logger        *logrus.Logger
}

// NewSyncService creates a new sync service
func NewSyncService(iamClient *s3client.IAMClient, groupStore *store.GroupStore, userStore *store.UserStore, credStore *store.CredentialStore, policiesDir string, adminUsername string, groupManager interface{}, logger *logrus.Logger) *SyncService {
	return &SyncService{
		iamClient:     iamClient,
		groupStore:    groupStore,
		userStore:     userStore,
		credStore:     credStore,
		policiesDir:   policiesDir,
		adminUsername: adminUsername,
		groupManager:  groupManager,
		logger:        logger,
	}
}

// SyncUser synchronizes a user's IAM account and groups based on OIDC claims
func (s *SyncService) SyncUser(ctx context.Context, userInfo *auth.UserInfo) error {
	// Skip if IAM client is not configured
	if s.iamClient == nil {
		s.logger.Debug("IAM client not configured, skipping user sync")
		return nil
	}

	username := userInfo.Email
	if username == "" {
		return fmt.Errorf("user email is required for IAM sync")
	}

	// Check if this is the admin user
	isAdmin := s.adminUsername != "" && username == s.adminUsername

	groups := userInfo.Groups
	if isAdmin {
		// Ensure admin user always has "admin" group
		hasAdminGroup := false
		for _, group := range groups {
			if group == "admin" {
				hasAdminGroup = true
				break
			}
		}
		if !hasAdminGroup {
			groups = append(groups, "admin")
			s.logger.WithField("username", username).Info("Admin user identified, adding admin group")
		}
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"groups":   groups,
		"is_admin": isAdmin,
	}).Info("Syncing IAM user and groups")

	// Step 1: Ensure IAM user exists
	if err := s.iamClient.CreateUser(ctx, username); err != nil {
		return fmt.Errorf("failed to ensure IAM user exists: %w", err)
	}

	// Step 2: Sync groups - ensure groups exist and have correct policies
	for _, groupName := range groups {
		// Group name is now the SCIM group ID
		scimGroupId := groupName

		// Get group definition
		group, err := s.groupStore.Get(scimGroupId)
		if err != nil {
			s.logger.WithError(err).WithField("group", groupName).Warn("Group not found in store, skipping")
			continue
		}

		// Ensure group exists in IAM
		if s.groupManager != nil {
			if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
				// Create group if it doesn't exist
				backendGroups, err := gm.ListGroups(ctx)
				if err != nil {
					s.logger.WithError(err).Warn("Failed to list backend groups")
				} else {
					exists := false
					for _, bg := range backendGroups {
						if bg == groupName {
							exists = true
							break
						}
					}
					if !exists {
						if err := gm.CreateGroup(ctx, groupName); err != nil {
							s.logger.WithError(err).WithField("group", groupName).Error("Failed to create group in backend")
							continue
						}
					}
				}

				// Combine group policies
				combinedPolicy, err := s.combineGroupPolicies(group.Policies)
				if err != nil {
					s.logger.WithError(err).WithField("group", groupName).Error("Failed to combine group policies")
					continue
				}

				// Put the combined policy on the group
				policyName := fmt.Sprintf("%s-policy", groupName)
				if err := gm.PutGroupPolicy(ctx, groupName, policyName, combinedPolicy); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"group":  groupName,
						"policy": policyName,
					}).Error("Failed to put group policy")
				}
			}
		}

		// Add user to group
		if s.groupManager != nil {
			if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
				if err := gm.AddUserToGroup(ctx, groupName, username); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"group":    groupName,
						"username": username,
					}).Error("Failed to add user to group")
				}
			}
		}
	}

	// Step 3: Remove user from groups they should not be in
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			backendGroups, err := gm.ListGroups(ctx)
			if err != nil {
				s.logger.WithError(err).Warn("Failed to list backend groups for cleanup")
			} else {
				for _, backendGroup := range backendGroups {
					// Check if user should be in this group
					shouldBeInGroup := false
					for _, userGroup := range groups {
						if userGroup == backendGroup {
							shouldBeInGroup = true
							break
						}
					}
					if !shouldBeInGroup {
						// Remove user from group
						if err := gm.RemoveUserFromGroup(ctx, backendGroup, username); err != nil {
							s.logger.WithError(err).WithFields(logrus.Fields{
								"group":    backendGroup,
								"username": username,
							}).Warn("Failed to remove user from group")
						}
					}
				}
			}
		}
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"groups":   groups,
		"is_admin": isAdmin,
	}).Info("IAM user sync completed successfully")

	return nil
}

// SyncAllSCIM synchronizes all SCIM users and groups to S3 IAM, making SCIM authoritative
func (s *SyncService) SyncAllSCIM(ctx context.Context) error {
	// Skip if IAM client is not configured
	if s.iamClient == nil {
		s.logger.Debug("IAM client not configured, skipping SCIM sync")
		return nil
	}

	// Skip if user store is not configured
	if s.userStore == nil {
		s.logger.Debug("User store not configured, skipping SCIM sync")
		return nil
	}

	s.logger.Info("Starting SCIM authoritative sync to S3 IAM")

	// Get all SCIM users
	scimUsers := s.userStore.GetAllUsers()
	scimUsernames := make([]string, 0, len(scimUsers))
	for _, user := range scimUsers {
		if user.Active {
			scimUsernames = append(scimUsernames, user.UserName)
		}
	}

	s.logger.WithField("scim_users", scimUsernames).Info("SCIM users to sync")

	// Get all current S3 IAM users
	iamUsers, err := s.iamClient.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list IAM users: %w", err)
	}

	s.logger.WithField("iam_users", iamUsers).Info("Current IAM users")

	// Step 1: Ensure all active SCIM users exist in IAM and have correct groups
	for _, scimUser := range scimUsers {
		if !scimUser.Active {
			s.logger.WithField("username", scimUser.UserName).Debug("Skipping inactive SCIM user")
			continue
		}

		username := scimUser.UserName

		// Create IAM user if it doesn't exist
		if err := s.iamClient.CreateUser(ctx, username); err != nil {
			s.logger.WithError(err).WithField("username", username).Error("Failed to create IAM user from SCIM")
			continue
		}

		// Get user's groups from SCIM
		userGroups := s.userStore.GetUserGroups(username)
		s.logger.WithFields(logrus.Fields{
			"username": username,
			"groups":   userGroups,
		}).Debug("Syncing SCIM user groups")

		// Check if this is the admin user
		isAdmin := s.adminUsername != "" && username == s.adminUsername
		if isAdmin {
			// Ensure admin user always has "admin" group
			hasAdminGroup := false
			for _, group := range userGroups {
				if group == "admin" {
					hasAdminGroup = true
					break
				}
			}
			if !hasAdminGroup {
				userGroups = append(userGroups, "admin")
				s.logger.WithField("username", username).Info("Admin user identified, adding admin group")
			}
		}

		// Sync groups for this user
		if err := s.syncUserGroups(ctx, username, userGroups); err != nil {
			s.logger.WithError(err).WithField("username", username).Error("Failed to sync user groups")
		}
	}

	// Step 2: Sync SCIM groups authoritatively
	s.logger.Info("Starting SCIM group authoritative sync")

	// Get all SCIM groups
	scimGroups := s.userStore.GetAllGroups()
	scimGroupNames := make([]string, 0, len(scimGroups))
	for _, group := range scimGroups {
		scimGroupNames = append(scimGroupNames, group.DisplayName)
	}

	s.logger.WithField("groups", scimGroupNames).Info("SCIM groups to sync")

	// Get all current IAM groups
	var iamGroups []string
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			var err error
			iamGroups, err = gm.ListGroups(ctx)
			if err != nil {
				s.logger.WithError(err).Warn("Failed to list IAM groups for SCIM group sync")
			}
		}
	}

	s.logger.WithField("iam_groups", iamGroups).Info("Current IAM groups")

	// Ensure all SCIM groups exist in IAM and have correct memberships
	for _, scimGroup := range scimGroups {
		// Use SCIM group ID as IAM group name (sanitized)
		groupName := scimGroup.ID
		if s.groupManager != nil {
			if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
				exists := false
				for _, iamGroup := range iamGroups {
					if iamGroup == groupName {
						exists = true
						break
					}
				}
				if !exists {
					if err := gm.CreateGroup(ctx, groupName); err != nil {
						s.logger.WithError(err).WithField("group", groupName).Error("Failed to create IAM group from SCIM")
						continue
					}
					s.logger.WithField("group", groupName).Info("Created IAM group from SCIM")
				}

				// Get group definition from group store for policies
				var group *store.Group
				allGroups := s.groupStore.List()
				for _, g := range allGroups {
					if g.ScimGroupId == scimGroup.ID {
						group = g
						break
					}
				}

				if group == nil {
					s.logger.WithField("group", groupName).Warn("Group not found in group store, skipping policy sync")
				} else {
					// Combine group policies
					combinedPolicy, err := s.combineGroupPolicies(group.Policies)
					if err != nil {
						s.logger.WithError(err).WithField("group", groupName).Error("Failed to combine group policies")
					} else {
						// Put the combined policy on the group
						policyName := fmt.Sprintf("%s-policy", groupName)
						if err := gm.PutGroupPolicy(ctx, groupName, policyName, combinedPolicy); err != nil {
							s.logger.WithError(err).WithFields(logrus.Fields{
								"group":  groupName,
								"policy": policyName,
							}).Error("Failed to put group policy")
						}
					}
				}

				// Sync group memberships based on SCIM group members
				currentMembers, err := gm.GetGroupUsers(ctx, groupName)
				if err != nil {
					s.logger.WithError(err).WithField("group", groupName).Error("Failed to get current group members")
					continue
				}

				// Get expected members from SCIM group
				expectedMembers := make([]string, 0, len(scimGroup.Members))
				for _, member := range scimGroup.Members {
					// member.Value should be the user ID, we need to get the username
					if user, exists := s.userStore.GetUserByID(member.Value); exists && user.Active {
						expectedMembers = append(expectedMembers, user.UserName)
					}
				}

				s.logger.WithFields(logrus.Fields{
					"group":            groupName,
					"current_members":  currentMembers,
					"expected_members": expectedMembers,
				}).Debug("Syncing SCIM group memberships")

				// Add missing members
				for _, expectedMember := range expectedMembers {
					found := false
					for _, currentMember := range currentMembers {
						if currentMember == expectedMember {
							found = true
							break
						}
					}
					if !found {
						if err := gm.AddUserToGroup(ctx, groupName, expectedMember); err != nil {
							s.logger.WithError(err).WithFields(logrus.Fields{
								"group":    groupName,
								"username": expectedMember,
							}).Error("Failed to add user to SCIM group")
						} else {
							s.logger.WithFields(logrus.Fields{
								"group":    groupName,
								"username": expectedMember,
							}).Info("Added user to SCIM group")
						}
					}
				}

				// Remove extra members
				for _, currentMember := range currentMembers {
					found := false
					for _, expectedMember := range expectedMembers {
						if currentMember == expectedMember {
							found = true
							break
						}
					}
					if !found {
						if err := gm.RemoveUserFromGroup(ctx, groupName, currentMember); err != nil {
							s.logger.WithError(err).WithFields(logrus.Fields{
								"group":    groupName,
								"username": currentMember,
							}).Error("Failed to remove user from SCIM group")
						} else {
							s.logger.WithFields(logrus.Fields{
								"group":    groupName,
								"username": currentMember,
							}).Info("Removed user from SCIM group")
						}
					}
				}
			}
		}
	}

	// Remove IAM groups that don't exist in SCIM
	for _, iamGroup := range iamGroups {
		found := false
		for _, scimGroup := range scimGroups {
			if scimGroup.ID == iamGroup {
				found = true
				break
			}
		}

		if !found {
			s.logger.WithField("group", iamGroup).Info("Removing IAM group not found in SCIM")
			if s.groupManager != nil {
				if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
					if err := gm.DeleteGroup(ctx, iamGroup); err != nil {
						s.logger.WithError(err).WithField("group", iamGroup).Error("Failed to delete IAM group not in SCIM")
					} else {
						s.logger.WithField("group", iamGroup).Info("Deleted IAM group not in SCIM")
					}
				}
			}
		}
	}

	// Step 3: Remove IAM users that don't exist in SCIM
	for _, iamUser := range iamUsers {
		found := false
		for _, scimUser := range scimUsers {
			if scimUser.UserName == iamUser && scimUser.Active {
				found = true
				break
			}
		}

		if !found {
			s.logger.WithField("username", iamUser).Info("Removing IAM user not found in SCIM")
			if err := s.iamClient.DeleteUser(ctx, iamUser); err != nil {
				// Check if the error is about access keys that need to be removed first
				if strings.Contains(err.Error(), "AccessKeys are removed") || strings.Contains(err.Error(), "access keys") {
					s.logger.WithField("username", iamUser).Info("User has access keys, removing them first")

					// List all access keys for this user
					accessKeys, listErr := s.iamClient.ListAccessKeys(ctx, iamUser)
					if listErr != nil {
						s.logger.WithError(listErr).WithField("username", iamUser).Error("Failed to list access keys for user")
					} else {
						// Delete each access key
						for _, accessKeyID := range accessKeys {
							if deleteErr := s.iamClient.DeleteAccessKey(ctx, iamUser, accessKeyID); deleteErr != nil {
								s.logger.WithError(deleteErr).WithFields(logrus.Fields{
									"username":   iamUser,
									"access_key": accessKeyID,
								}).Error("Failed to delete access key")
							} else {
								s.logger.WithFields(logrus.Fields{
									"username":   iamUser,
									"access_key": accessKeyID,
								}).Info("Deleted access key")
							}
						}

						// Try to delete the user again now that access keys are removed
						if retryErr := s.iamClient.DeleteUser(ctx, iamUser); retryErr != nil {
							// Check if the error is now about user policies
							if strings.Contains(retryErr.Error(), "user policies are removed") {
								s.logger.WithField("username", iamUser).Info("User has inline policies, removing them first")

								// List all user policies for this user
								userPolicies, policyListErr := s.iamClient.ListUserPolicies(ctx, iamUser)
								if policyListErr != nil {
									s.logger.WithError(policyListErr).WithField("username", iamUser).Error("Failed to list user policies")
								} else {
									// Delete each user policy
									for _, policyName := range userPolicies {
										if policyDeleteErr := s.iamClient.DeleteUserPolicy(ctx, iamUser, policyName); policyDeleteErr != nil {
											s.logger.WithError(policyDeleteErr).WithFields(logrus.Fields{
												"username": iamUser,
												"policy":   policyName,
											}).Error("Failed to delete user policy")
										} else {
											s.logger.WithFields(logrus.Fields{
												"username": iamUser,
												"policy":   policyName,
											}).Info("Deleted user policy")
										}
									}

									// Try to delete the user again now that policies are removed
									if finalRetryErr := s.iamClient.DeleteUser(ctx, iamUser); finalRetryErr != nil {
										s.logger.WithError(finalRetryErr).WithField("username", iamUser).Error("Failed to delete IAM user after removing access keys and policies")
									} else {
										s.logger.WithField("username", iamUser).Info("Successfully deleted IAM user after removing access keys and policies")
									}
								}
							} else {
								s.logger.WithError(retryErr).WithField("username", iamUser).Error("Failed to delete IAM user after removing access keys")
							}
						} else {
							s.logger.WithField("username", iamUser).Info("Successfully deleted IAM user after removing access keys")
						}
					}
				} else if strings.Contains(err.Error(), "user policies are removed") {
					s.logger.WithField("username", iamUser).Info("User has inline policies, removing them first")

					// List all user policies for this user
					userPolicies, policyListErr := s.iamClient.ListUserPolicies(ctx, iamUser)
					if policyListErr != nil {
						s.logger.WithError(policyListErr).WithField("username", iamUser).Error("Failed to list user policies")
					} else {
						// Delete each user policy
						for _, policyName := range userPolicies {
							if policyDeleteErr := s.iamClient.DeleteUserPolicy(ctx, iamUser, policyName); policyDeleteErr != nil {
								s.logger.WithError(policyDeleteErr).WithFields(logrus.Fields{
									"username": iamUser,
									"policy":   policyName,
								}).Error("Failed to delete user policy")
							} else {
								s.logger.WithFields(logrus.Fields{
									"username": iamUser,
									"policy":   policyName,
								}).Info("Deleted user policy")
							}
						}

						// Try to delete the user again now that policies are removed
						if retryErr := s.iamClient.DeleteUser(ctx, iamUser); retryErr != nil {
							s.logger.WithError(retryErr).WithField("username", iamUser).Error("Failed to delete IAM user after removing policies")
						} else {
							s.logger.WithField("username", iamUser).Info("Successfully deleted IAM user after removing policies")
						}
					}
				} else {
					s.logger.WithError(err).WithField("username", iamUser).Error("Failed to delete IAM user")
				}
			} else {
				s.logger.WithField("username", iamUser).Info("Deleted IAM user")
			}
		}
	}

	// Step 4: Clean up IAM groups that don't have any users (optional)
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			backendGroups, err := gm.ListGroups(ctx)
			if err != nil {
				s.logger.WithError(err).Warn("Failed to list backend groups for cleanup")
			} else {
				for _, groupName := range backendGroups {
					// Check if group has any users
					users, err := gm.GetGroupUsers(ctx, groupName)
					if err != nil {
						s.logger.WithError(err).WithField("group", groupName).Warn("Failed to get group users")
						continue
					}

					if len(users) == 0 {
						s.logger.WithField("group", groupName).Info("Removing empty IAM group")
						if err := gm.DeleteGroup(ctx, groupName); err != nil {
							s.logger.WithError(err).WithField("group", groupName).Error("Failed to delete empty IAM group")
						}
					}
				}
			}
		}
	}

	s.logger.Info("SCIM authoritative sync completed")
	return nil
}

// syncUserGroups synchronizes groups for a specific user
func (s *SyncService) syncUserGroups(ctx context.Context, username string, userGroups []string) error {
	// Step 1: Ensure groups exist and have correct policies
	for _, groupName := range userGroups {
		// For SCIM groups, find the SCIM group ID from display name
		var scimGroupId string
		if scimGroup, exists := s.userStore.GetGroupByDisplayName(groupName); exists {
			scimGroupId = scimGroup.ID
		} else {
			// For non-SCIM groups, use the display name as the key (legacy support)
			scimGroupId = groupName
		}

		// Get group definition from group store
		group, err := s.groupStore.Get(scimGroupId)
		if err != nil {
			s.logger.WithError(err).WithField("group", groupName).Warn("Group not found in store, skipping")
			continue
		}

		// Use SCIM group ID as IAM group name for SCIM groups
		iamGroupName := scimGroupId
		if scimGroupId == groupName {
			// Legacy non-SCIM group
			iamGroupName = groupName
		}

		// Ensure group exists in IAM
		if s.groupManager != nil {
			if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
				// Create group if it doesn't exist
				backendGroups, err := gm.ListGroups(ctx)
				if err != nil {
					s.logger.WithError(err).Warn("Failed to list backend groups")
				} else {
					exists := false
					for _, bg := range backendGroups {
						if bg == iamGroupName {
							exists = true
							break
						}
					}
					if !exists {
						if err := gm.CreateGroup(ctx, iamGroupName); err != nil {
							s.logger.WithError(err).WithField("group", iamGroupName).Error("Failed to create group in backend")
							continue
						}
					}
				}

				// Combine group policies
				combinedPolicy, err := s.combineGroupPolicies(group.Policies)
				if err != nil {
					s.logger.WithError(err).WithField("group", iamGroupName).Error("Failed to combine group policies")
					continue
				}

				// Put the combined policy on the group
				policyName := fmt.Sprintf("%s-policy", iamGroupName)
				if err := gm.PutGroupPolicy(ctx, iamGroupName, policyName, combinedPolicy); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"group":  iamGroupName,
						"policy": policyName,
					}).Error("Failed to put group policy")
				}
			}
		}

		// Add user to group
		if s.groupManager != nil {
			if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
				if err := gm.AddUserToGroup(ctx, iamGroupName, username); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"group":    iamGroupName,
						"username": username,
					}).Error("Failed to add user to group")
				}
			}
		}
	}

	// Step 2: Remove user from groups they should not be in
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			backendGroups, err := gm.ListGroups(ctx)
			if err != nil {
				s.logger.WithError(err).Warn("Failed to list backend groups for cleanup")
			} else {
				// Convert userGroups to IAM group names for comparison
				userIamGroups := make([]string, 0, len(userGroups))
				for _, userGroup := range userGroups {
					if scimGroup, exists := s.userStore.GetGroupByDisplayName(userGroup); exists {
						userIamGroups = append(userIamGroups, scimGroup.ID)
					} else {
						// Legacy non-SCIM group
						userIamGroups = append(userIamGroups, userGroup)
					}
				}

				for _, backendGroup := range backendGroups {
					// Check if user should be in this group
					shouldBeInGroup := false
					for _, userIamGroup := range userIamGroups {
						if userIamGroup == backendGroup {
							shouldBeInGroup = true
							break
						}
					}
					if !shouldBeInGroup {
						// Remove user from group
						if err := gm.RemoveUserFromGroup(ctx, backendGroup, username); err != nil {
							s.logger.WithError(err).WithFields(logrus.Fields{
								"group":    backendGroup,
								"username": username,
							}).Warn("Failed to remove user from group")
						}
					}
				}
			}
		}
	}

	return nil
}

// FetchUsers retrieves all users from the backend
func (s *SyncService) FetchUsers(ctx context.Context) ([]string, error) {
	if s.iamClient == nil {
		return nil, fmt.Errorf("IAM client not configured")
	}
	return s.iamClient.ListUsers(ctx)
}

// combineGroupPolicies combines policy documents from multiple policies into one
func (s *SyncService) combineGroupPolicies(policyNames []string) (map[string]interface{}, error) {
	combinedStatements := []map[string]interface{}{}

	for _, policyName := range policyNames {
		policyDoc, err := s.loadPolicyDocument(policyName)
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
func (s *SyncService) loadPolicyDocument(policyName string) (map[string]interface{}, error) {
	// Try different file name patterns
	patterns := []string{
		fmt.Sprintf("%s.json", policyName),
		fmt.Sprintf("%s.json", strings.ToLower(policyName)),
	}

	var policyPath string
	var found bool

	for _, pattern := range patterns {
		testPath := filepath.Join(s.policiesDir, pattern)
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

// SyncGroup synchronizes a single SCIM group to S3 IAM - creates group, sets policies, and adds members
func (s *SyncService) SyncGroup(ctx context.Context, scimGroupId string) error {
	if s.iamClient == nil {
		s.logger.Debug("IAM client not configured, skipping group sync")
		return nil
	}

	s.logger.WithField("group_id", scimGroupId).Info("Syncing single group to S3 IAM")

	// Get group definition from group store
	group, err := s.groupStore.Get(scimGroupId)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	// Get SCIM group for members
	scimGroup, exists := s.userStore.GetGroupByID(scimGroupId)
	if !exists {
		return fmt.Errorf("SCIM group not found: %s", scimGroupId)
	}

	// Create group in IAM if it doesn't exist
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			backendGroups, err := gm.ListGroups(ctx)
			if err != nil {
				return fmt.Errorf("failed to list backend groups: %w", err)
			}

			exists := false
			for _, bg := range backendGroups {
				if bg == scimGroupId {
					exists = true
					break
				}
			}

			if !exists {
				if err := gm.CreateGroup(ctx, scimGroupId); err != nil {
					return fmt.Errorf("failed to create group in backend: %w", err)
				}
				s.logger.WithField("group", scimGroupId).Info("Created IAM group")
			}

			// Combine and apply group policies
			if err := s.syncGroupPolicyInternal(ctx, gm, scimGroupId, group); err != nil {
				return fmt.Errorf("failed to sync group policy: %w", err)
			}

			// Sync group memberships
			if err := s.syncGroupMembersInternal(ctx, gm, scimGroupId, scimGroup); err != nil {
				return fmt.Errorf("failed to sync group members: %w", err)
			}
		}
	}

	s.logger.WithField("group_id", scimGroupId).Info("Group sync completed successfully")
	return nil
}

// SyncGroupPolicy updates only the policy for a specific group (no membership changes)
func (s *SyncService) SyncGroupPolicy(ctx context.Context, scimGroupId string) error {
	if s.iamClient == nil {
		s.logger.Debug("IAM client not configured, skipping group policy sync")
		return nil
	}

	s.logger.WithField("group_id", scimGroupId).Info("Syncing group policy to S3 IAM")

	// Get group definition
	group, err := s.groupStore.Get(scimGroupId)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			if err := s.syncGroupPolicyInternal(ctx, gm, scimGroupId, group); err != nil {
				return fmt.Errorf("failed to sync group policy: %w", err)
			}
		}
	}

	s.logger.WithField("group_id", scimGroupId).Info("Group policy sync completed successfully")
	return nil
}

// DeleteGroupAndCleanup deletes a group from S3 IAM and cleans up associated credentials
func (s *SyncService) DeleteGroupAndCleanup(ctx context.Context, scimGroupId string) error {
	if s.iamClient == nil {
		s.logger.Debug("IAM client not configured, skipping group deletion")
		return nil
	}

	s.logger.WithField("group_id", scimGroupId).Info("Deleting group from S3 IAM and cleaning up credentials")

	// First, delete the group policy
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			policyName := fmt.Sprintf("%s-policy", scimGroupId)
			if err := gm.DeleteGroupPolicy(ctx, scimGroupId, policyName); err != nil {
				s.logger.WithError(err).WithField("group", scimGroupId).Warn("Failed to delete group policy (may not exist)")
			} else {
				s.logger.WithField("group", scimGroupId).Info("Deleted group policy")
			}
		}
	}

	// Get all users from the group before deleting it
	var groupUsers []string
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			users, err := gm.GetGroupUsers(ctx, scimGroupId)
			if err != nil {
				s.logger.WithError(err).WithField("group", scimGroupId).Warn("Failed to get group users")
			} else {
				groupUsers = users
				s.logger.WithFields(logrus.Fields{
					"group": scimGroupId,
					"users": groupUsers,
				}).Info("Retrieved group users for cleanup")
			}
		}
	}

	// Remove all users from the group before deleting it
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			for _, username := range groupUsers {
				if err := gm.RemoveUserFromGroup(ctx, scimGroupId, username); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"group": scimGroupId,
						"user":  username,
					}).Warn("Failed to remove user from group before deletion")
				} else {
					s.logger.WithFields(logrus.Fields{
						"group": scimGroupId,
						"user":  username,
					}).Info("Removed user from group before deletion")
				}
			}
		}
	}

	// Delete the group itself from IAM
	if s.groupManager != nil {
		if gm, ok := s.groupManager.(*awscli.GroupManager); ok {
			if err := gm.DeleteGroup(ctx, scimGroupId); err != nil {
				s.logger.WithError(err).WithField("group", scimGroupId).Error("Failed to delete group from backend")
				return fmt.Errorf("failed to delete IAM group: %w", err)
			} else {
				s.logger.WithField("group", scimGroupId).Info("Deleted IAM group")
			}
		}
	}

	// Cleanup: Delete credentials that reference the deleted group
	// Find all credentials using this group
	if s.credStore != nil {
		credentialsToDelete, err := s.credStore.ListByGroups([]string{scimGroupId})
		if err != nil {
			s.logger.WithError(err).WithField("group", scimGroupId).Warn("Failed to list credentials for deleted group")
		} else {
			s.logger.WithFields(logrus.Fields{
				"group":             scimGroupId,
				"credentials_count": len(credentialsToDelete),
			}).Info("Found credentials referencing deleted group")

			// Delete each credential (including IAM access keys and inline policies)
			for _, cred := range credentialsToDelete {
				s.logger.WithFields(logrus.Fields{
					"credential": cred.Name,
					"access_key": cred.AccessKey,
					"user":       cred.UserID,
					"group":      scimGroupId,
				}).Info("Deleting credential that references deleted group")

				// Delete IAM access key
				if s.iamClient != nil {
					if err := s.iamClient.DeleteAccessKey(ctx, cred.UserID, cred.AccessKey); err != nil {
						s.logger.WithError(err).WithFields(logrus.Fields{
							"user":       cred.UserID,
							"access_key": cred.AccessKey,
						}).Warn("Failed to delete IAM access key for credential")
					} else {
						s.logger.WithFields(logrus.Fields{
							"user":       cred.UserID,
							"access_key": cred.AccessKey,
						}).Info("Deleted IAM access key")
					}

					// Delete user inline policy
					policyName := fmt.Sprintf("%s-%s-policy", cred.UserID, cred.Name)
					if err := s.iamClient.DeleteUserPolicy(ctx, cred.UserID, policyName); err != nil {
						s.logger.WithError(err).WithFields(logrus.Fields{
							"user":   cred.UserID,
							"policy": policyName,
						}).Warn("Failed to delete user inline policy")
					} else {
						s.logger.WithFields(logrus.Fields{
							"user":   cred.UserID,
							"policy": policyName,
						}).Info("Deleted user inline policy")
					}
				}

				// Delete from local credential store
				if err := s.credStore.Delete(cred.AccessKey, cred.UserID); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"credential": cred.Name,
						"user":       cred.UserID,
					}).Warn("Failed to delete credential from local store")
				} else {
					s.logger.WithFields(logrus.Fields{
						"credential": cred.Name,
						"user":       cred.UserID,
					}).Info("Deleted credential from local store")
				}
			}
		}
	}

	// Sync each user's group memberships
	for _, username := range groupUsers {
		s.logger.WithFields(logrus.Fields{
			"user":          username,
			"deleted_group": scimGroupId,
		}).Info("Syncing user group memberships after group deletion")

		// Get user's current groups from SCIM
		userGroups := s.userStore.GetUserGroups(username)

		// Sync the user's groups (this will update their IAM group memberships)
		if err := s.syncUserGroups(ctx, username, userGroups); err != nil {
			s.logger.WithError(err).WithField("user", username).Warn("Failed to sync user groups after group deletion")
		}
	}

	return nil
}

// syncGroupPolicyInternal is a helper to sync policies for a group
func (s *SyncService) syncGroupPolicyInternal(ctx context.Context, gm *awscli.GroupManager, groupName string, group *store.Group) error {
	// Combine group policies
	combinedPolicy, err := s.combineGroupPolicies(group.Policies)
	if err != nil {
		return fmt.Errorf("failed to combine group policies: %w", err)
	}

	// Put the combined policy on the group
	policyName := fmt.Sprintf("%s-policy", groupName)
	if err := gm.PutGroupPolicy(ctx, groupName, policyName, combinedPolicy); err != nil {
		return fmt.Errorf("failed to put group policy: %w", err)
	}

	return nil
}

// syncGroupMembersInternal is a helper to sync members for a group
func (s *SyncService) syncGroupMembersInternal(ctx context.Context, gm *awscli.GroupManager, groupName string, scimGroup *store.SCIMGroup) error {
	// Get current members in IAM
	currentMembers, err := gm.GetGroupUsers(ctx, groupName)
	if err != nil {
		return fmt.Errorf("failed to get current group members: %w", err)
	}

	// Get expected members from SCIM
	expectedMembers := make([]string, 0)
	for _, member := range scimGroup.Members {
		expectedMembers = append(expectedMembers, member.Value) // username
	}

	// Add missing members
	for _, expectedMember := range expectedMembers {
		found := false
		for _, currentMember := range currentMembers {
			if currentMember == expectedMember {
				found = true
				break
			}
		}
		if !found {
			if err := gm.AddUserToGroup(ctx, groupName, expectedMember); err != nil {
				s.logger.WithError(err).WithFields(logrus.Fields{
					"group": groupName,
					"user":  expectedMember,
				}).Warn("Failed to add user to group")
			}
		}
	}

	// Remove extra members
	for _, currentMember := range currentMembers {
		found := false
		for _, expectedMember := range expectedMembers {
			if expectedMember == currentMember {
				found = true
				break
			}
		}
		if !found {
			if err := gm.RemoveUserFromGroup(ctx, groupName, currentMember); err != nil {
				s.logger.WithError(err).WithFields(logrus.Fields{
					"group": groupName,
					"user":  currentMember,
				}).Warn("Failed to remove user from group")
			}
		}
	}

	return nil
}
