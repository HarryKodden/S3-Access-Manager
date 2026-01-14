package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/harrykodden/s3-gateway/internal/auth"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/sirupsen/logrus"
)

// SyncService synchronizes users and roles between gateway and backend
type SyncService struct {
	iamClient     *s3client.IAMClient
	roleStore     *store.RoleStore
	policiesDir   string
	adminUsername string
	roleManager   interface{}
	logger        *logrus.Logger
}

// NewSyncService creates a new sync service
func NewSyncService(iamClient *s3client.IAMClient, roleStore *store.RoleStore, policiesDir string, adminUsername string, roleManager interface{}, logger *logrus.Logger) *SyncService {
	return &SyncService{
		iamClient:     iamClient,
		roleStore:     roleStore,
		policiesDir:   policiesDir,
		adminUsername: adminUsername,
		roleManager:   roleManager,
		logger:        logger,
	}
}

// SyncUser synchronizes a user's IAM account and policies based on OIDC claims
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

	roles := userInfo.Roles
	if isAdmin {
		// Ensure admin user always has "admin" role
		hasAdminRole := false
		for _, role := range roles {
			if role == "admin" {
				hasAdminRole = true
				break
			}
		}
		if !hasAdminRole {
			roles = append(roles, "admin")
			s.logger.WithField("username", username).Info("Admin user identified, adding admin role")
		}
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"roles":    roles,
		"is_admin": isAdmin,
	}).Info("Syncing IAM user and policies")

	// Step 1: Ensure IAM user exists
	if err := s.iamClient.CreateUser(ctx, username); err != nil {
		return fmt.Errorf("failed to ensure IAM user exists: %w", err)
	}

	// Step 2: Get current policies attached to user
	currentPolicies, err := s.iamClient.ListUserPolicies(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to list current user policies: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"username":         username,
		"current_policies": currentPolicies,
	}).Debug("Current user policies")

	// Step 3: Determine desired policies from OIDC roles using role store
	desiredPolicies := make(map[string]bool)

	// Get policies for all roles from role store
	allPolicies := s.roleStore.GetPoliciesForRoles(roles)
	for _, policy := range allPolicies {
		desiredPolicies[policy] = true
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"roles":    roles,
		"policies": allPolicies,
	}).Info("Computed policies from roles")

	// Step 4: Add missing policies
	for policy := range desiredPolicies {
		s.logger.WithFields(logrus.Fields{
			"username": username,
			"policy":   policy,
			"attached": contains(currentPolicies, policy),
		}).Debug("Checking policy attachment")

		if !contains(currentPolicies, policy) {
			s.logger.WithFields(logrus.Fields{
				"username": username,
				"policy":   policy,
			}).Info("Attaching missing policy")

			if err := s.attachPolicyFromFile(ctx, username, policy); err != nil {
				s.logger.WithError(err).WithFields(logrus.Fields{
					"username": username,
					"policy":   policy,
				}).Warn("Failed to attach policy, continuing with other policies")
			}
		} else {
			s.logger.WithFields(logrus.Fields{
				"username": username,
				"policy":   policy,
			}).Debug("Policy already attached")
		}
	}

	// Step 6: Sync all local roles to backend
	if err := s.SyncRoles(ctx); err != nil {
		s.logger.WithError(err).Warn("Failed to sync roles to backend")
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"roles":    roles,
		"is_admin": isAdmin,
	}).Info("IAM user sync completed successfully")

	return nil
}

// attachPolicyFromFile loads a policy from file and attaches it to the user
func (s *SyncService) attachPolicyFromFile(ctx context.Context, username, policyName string) error {
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
		return fmt.Errorf("policy file not found for role '%s', tried patterns: %v", policyName, patterns)
	}

	// Read policy file
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy file %s: %w", policyPath, err)
	}

	// Parse policy JSON
	var policyDoc map[string]interface{}
	if err := json.Unmarshal(policyData, &policyDoc); err != nil {
		return fmt.Errorf("failed to parse policy JSON from %s: %w", policyPath, err)
	}

	// Attach policy to user
	if err := s.iamClient.PutUserPolicy(ctx, username, policyName, policyDoc); err != nil {
		return fmt.Errorf("failed to attach policy: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"username":    username,
		"policy_name": policyName,
		"policy_file": filepath.Base(policyPath),
	}).Info("Attached policy from file")

	return nil
}

// FetchUsers retrieves all users from the backend
func (s *SyncService) FetchUsers(ctx context.Context) ([]string, error) {
	if s.iamClient == nil {
		return nil, fmt.Errorf("IAM client not configured")
	}
	return s.iamClient.ListUsers(ctx)
}

// FetchRoles retrieves all roles from the backend
func (s *SyncService) FetchRoles(ctx context.Context) ([]string, error) {
	if s.roleManager == nil {
		return nil, nil // No role manager, return empty
	}
	if rm, ok := s.roleManager.(*awscli.RoleManager); ok {
		return rm.ListRoles(ctx)
	}
	return nil, fmt.Errorf("unsupported role manager type")
}

// SyncRoles ensures all local roles are synced to backend with correct policy documents
func (s *SyncService) SyncRoles(ctx context.Context) error {
	localRoles := s.roleStore.List()

	for _, role := range localRoles {
		// Create combined policy document
		combinedDoc, err := s.combineRolePolicies(role.Policies)
		if err != nil {
			s.logger.WithError(err).WithField("role", role.Name).Warn("Failed to combine policies for role")
			continue
		}

		// Check backend role
		if s.roleManager != nil {
			if rm, ok := s.roleManager.(*awscli.RoleManager); ok {
				backendRoles, err := rm.ListRoles(ctx)
				if err != nil {
					s.logger.WithError(err).Warn("Failed to list backend roles")
					continue
				}

				exists := false
				for _, br := range backendRoles {
					if br == role.Name {
						exists = true
						break
					}
				}

				if !exists {
					// Create
					err = rm.CreateRole(ctx, role.Name, combinedDoc)
					if err != nil {
						s.logger.WithError(err).WithField("role", role.Name).Warn("Failed to create role in backend")
					} else {
						s.logger.WithField("role", role.Name).Info("Created role in backend")
					}
				} else {
					// Check if policy needs updating
					currentPolicy, err := rm.GetRolePolicy(ctx, role.Name)
					if err != nil {
						s.logger.WithError(err).WithField("role", role.Name).Warn("Failed to get current backend policy, updating anyway")
						err = rm.UpdateRole(ctx, role.Name, combinedDoc)
						if err != nil {
							s.logger.WithError(err).WithField("role", role.Name).Warn("Failed to update role in backend")
						} else {
							s.logger.WithField("role", role.Name).Info("Updated role in backend (policy check failed)")
						}
					} else {
						// Compare policies
						if s.policiesEqual(currentPolicy, combinedDoc) {
							s.logger.WithField("role", role.Name).Debug("Role policy already matches, skipping update")
						} else {
							err = rm.UpdateRole(ctx, role.Name, combinedDoc)
							if err != nil {
								s.logger.WithError(err).WithField("role", role.Name).Warn("Failed to update role in backend")
							} else {
								s.logger.WithField("role", role.Name).Info("Updated role in backend (policy changed)")
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// policiesEqual compares two policy documents for equality
func (s *SyncService) policiesEqual(a, b map[string]interface{}) bool {
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

// combineRolePolicies combines policy documents from multiple policies into one
func (s *SyncService) combineRolePolicies(policyNames []string) (map[string]interface{}, error) {
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

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
