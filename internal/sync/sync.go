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
	iamClient     *s3client.IAMClient
	groupStore    *store.GroupStore
	userStore     *store.UserStore
	policiesDir   string
	adminUsername string
	logger        *logrus.Logger
}

// NewSyncService creates a new sync service
func NewSyncService(iamClient *s3client.IAMClient, groupStore *store.GroupStore, userStore *store.UserStore, policiesDir string, adminUsername string, logger *logrus.Logger) *SyncService {
	return &SyncService{
		iamClient:     iamClient,
		groupStore:    groupStore,
		userStore:     userStore,
		policiesDir:   policiesDir,
		adminUsername: adminUsername,
		logger:        logger,
	}
}

// SyncAllSCIM performs authoritative sync of all SCIM users to IAM
func (s *SyncService) SyncAllSCIM(ctx context.Context) error {
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
	return nil
}

// syncUserToIAM syncs a single SCIM user to IAM
func (s *SyncService) syncUserToIAM(ctx context.Context, user *store.SCIMUser) error {
	username := user.UserName

	// Ensure IAM user exists
	if err := s.iamClient.CreateUser(ctx, username); err != nil {
		return fmt.Errorf("failed to create IAM user %s: %w", username, err)
	}

	// Get user's groups and resolve to policies
	userGroups := s.userStore.GetUserGroups(username)
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
