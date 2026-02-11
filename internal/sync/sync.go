package sync

import (
	"context"
	"fmt"

	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/sirupsen/logrus"
)

// SyncService synchronizes users and groups between gateway and backend
type SyncService struct {
	iamClient       *s3client.IAMClient
	groupStore      *store.GroupStore
	userStore       *store.UserStore
	credentialStore *store.CredentialStore
	policiesDir     string
	adminUsername   string
	logger          *logrus.Logger
}

// NewSyncService creates a new sync service
func NewSyncService(iamClient *s3client.IAMClient, groupStore *store.GroupStore, userStore *store.UserStore, credentialStore *store.CredentialStore, policiesDir string, adminUsername string, logger *logrus.Logger) *SyncService {
	return &SyncService{
		iamClient:       iamClient,
		groupStore:      groupStore,
		userStore:       userStore,
		credentialStore: credentialStore,
		policiesDir:     policiesDir,
		adminUsername:   adminUsername,
		logger:          logger,
	}
}

// SyncAllSCIM performs authoritative sync of all SCIM users to IAM
func (s *SyncService) SyncAllSCIM(ctx context.Context, healthRefresher func()) error {
	if s.iamClient == nil {
		s.logger.Debug("IAM client not configured, skipping SCIM sync")
		return nil
	}

	s.logger.Info("Starting simplified SCIM-to-IAM sync")

	// Get all active SCIM users
	scimUsers := s.userStore.GetAllUsers()
	activeUsers := make([]*store.SCIMUser, 0)
	for _, user := range scimUsers {
		if user.Active {
			activeUsers = append(activeUsers, user)
		}
	}

	s.logger.WithField("active_users", len(activeUsers)).Info("Processing active SCIM users")

	// Process each active user
	for _, user := range activeUsers {
		if err := s.syncUserToIAM(ctx, user); err != nil {
			s.logger.WithError(err).WithField("username", user.UserName).Error("Failed to sync user to IAM")
			continue
		}
	}

	// Clean up inactive users
	if err := s.cleanupInactiveUsers(ctx, activeUsers); err != nil {
		s.logger.WithError(err).Error("Failed to cleanup inactive users")
	}

	s.logger.Info("SCIM-to-IAM sync completed")

	// Trigger health refresh since SCIM data may have changed admin acceptance status
	if healthRefresher != nil {
		healthRefresher()
	}

	return nil
}

// syncUserToIAM syncs a single SCIM user to IAM
func (s *SyncService) syncUserToIAM(ctx context.Context, user *store.SCIMUser) error {
	username := user.UserName

	// Ensure IAM user exists
	if err := s.iamClient.CreateUser(ctx, username); err != nil {
		return fmt.Errorf("failed to create IAM user %s: %w", username, err)
	}

	// Get user's current groups
	userGroups := s.userStore.GetUserGroups(username)

	// Clean up credentials that are no longer valid due to group membership changes
	if err := s.cleanupInvalidCredentials(ctx, username, userGroups); err != nil {
		s.logger.WithError(err).WithField("username", username).Error("Failed to cleanup invalid credentials")
		// Continue with sync despite cleanup failure
	}

	policyNames := s.groupStore.GetPoliciesForGroups(userGroups)

	// Handle admin user
	if s.adminUsername != "" && username == s.adminUsername {
		policyNames = append(policyNames, "admin")
	}

	// Attach policies directly to user (simplified approach)
	for _, policyName := range policyNames {
		if err := s.attachPolicyToUser(ctx, username, policyName); err != nil {
			s.logger.WithError(err).WithFields(logrus.Fields{
				"username": username,
				"policy":   policyName,
			}).Warn("Failed to attach policy to user")
		}
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"groups":   userGroups,
		"policies": policyNames,
	}).Debug("User synced to IAM")

	return nil
}

// attachPolicyToUser attaches a policy to an IAM user
func (s *SyncService) attachPolicyToUser(ctx context.Context, username, policyName string) error {
	// For now, just log - actual implementation would depend on backend
	s.logger.WithFields(logrus.Fields{
		"username": username,
		"policy":   policyName,
	}).Debug("Attaching policy to user (simplified)")

	// TODO: Implement actual policy attachment based on backend
	return nil
}

// cleanupInvalidCredentials removes credentials that are no longer valid due to group membership changes
func (s *SyncService) cleanupInvalidCredentials(ctx context.Context, username string, currentUserGroups []string) error {
	if s.credentialStore == nil {
		return nil // No credential store configured
	}

	// Get all credentials for this user
	credentials, err := s.credentialStore.ListByUser(username)
	if err != nil {
		return fmt.Errorf("failed to list credentials for user %s: %w", username, err)
	}

	// Create a set of current user groups for efficient lookup
	userGroupSet := make(map[string]bool)
	for _, group := range currentUserGroups {
		userGroupSet[group] = true
	}

	var credentialsToDelete []*store.Credential

	// Check each credential
	for _, cred := range credentials {
		valid := true
		for _, credGroup := range cred.Groups {
			if !userGroupSet[credGroup] {
				valid = false
				break
			}
		}

		if !valid {
			credentialsToDelete = append(credentialsToDelete, cred)
			s.logger.WithFields(logrus.Fields{
				"username":        username,
				"credential_id":   cred.ID,
				"credential_name": cred.Name,
				"cred_groups":     cred.Groups,
				"user_groups":     currentUserGroups,
			}).Warn("Credential is no longer valid due to group membership changes")
		}
	}

	// Delete invalid credentials
	for _, cred := range credentialsToDelete {
		// Delete from backend first
		if s.iamClient != nil {
			if err := s.iamClient.DeleteAccessKey(ctx, username, cred.AccessKey); err != nil {
				s.logger.WithError(err).WithFields(logrus.Fields{
					"username":   username,
					"access_key": cred.AccessKey,
					"credential": cred.Name,
				}).Error("Failed to delete access key from backend")
				continue // Don't delete from local store if backend deletion failed
			}
		}

		// Delete from local store
		if err := s.credentialStore.Delete(cred.AccessKey, username); err != nil {
			s.logger.WithError(err).WithFields(logrus.Fields{
				"username":   username,
				"access_key": cred.AccessKey,
				"credential": cred.Name,
			}).Error("Failed to delete credential from local store")
		} else {
			s.logger.WithFields(logrus.Fields{
				"username":   username,
				"access_key": cred.AccessKey,
				"credential": cred.Name,
			}).Info("Deleted invalid credential due to group membership changes")
		}
	}

	if len(credentialsToDelete) > 0 {
		s.logger.WithFields(logrus.Fields{
			"username":            username,
			"credentials_deleted": len(credentialsToDelete),
		}).Info("Completed cleanup of invalid credentials")
	}

	return nil
}

// cleanupInactiveUsers removes IAM users that are no longer active in SCIM
func (s *SyncService) cleanupInactiveUsers(ctx context.Context, activeUsers []*store.SCIMUser) error {
	// Get all IAM users
	iamUsers, err := s.iamClient.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list IAM users: %w", err)
	}

	// Create set of active usernames
	activeUsernames := make(map[string]bool)
	for _, user := range activeUsers {
		activeUsernames[user.UserName] = true
	}

	// Remove inactive users (except admin)
	for _, iamUser := range iamUsers {
		if !activeUsernames[iamUser] && iamUser != s.adminUsername {
			s.logger.WithField("username", iamUser).Info("Removing inactive IAM user")
			// TODO: Implement user removal
		}
	}

	return nil
}
