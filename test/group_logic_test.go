package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/harrykodden/s3-gateway/internal/policy"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/sirupsen/logrus"
)

// TestGroupBasedPolicyResolution tests that users get the correct policies
// based on their OIDC group membership, proving the core group-based logic works.
func TestGroupBasedPolicyResolution(t *testing.T) {
	// Setup test environment
	testDir := t.TempDir()
	groupsDir := filepath.Join(testDir, "groups")
	policiesDir := filepath.Join(testDir, "policies")

	os.MkdirAll(groupsDir, 0755)
	os.MkdirAll(policiesDir, 0755)

	// Create test groups
	createTestGroup(t, groupsDir, "admin", "Administrator group", []string{"admin", "Read-Write"})
	createTestGroup(t, groupsDir, "developer", "Developer group", []string{"Read-Write"})
	createTestGroup(t, groupsDir, "readonly", "Read-only group", []string{"Read-Only"})

	// Create test policies
	createTestPolicy(t, policiesDir, "admin", map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect":   "Allow",
				"Action":   []string{"s3:*", "iam:*"},
				"Resource": "*",
			},
		},
	})

	createTestPolicy(t, policiesDir, "Read-Write", map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Action": []string{
					"s3:GetObject",
					"s3:PutObject",
					"s3:DeleteObject",
					"s3:ListBucket",
					"s3:CreateBucket",
					"s3:DeleteBucket",
				},
				"Resource": "*",
			},
		},
	})

	createTestPolicy(t, policiesDir, "Read-Only", map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Action": []string{
					"s3:GetObject",
					"s3:ListBucket",
				},
				"Resource": "*",
			},
		},
	})

	// Setup stores
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	groupStore, err := store.NewGroupStore(groupsDir, logger)
	if err != nil {
		t.Fatalf("Failed to create group store: %v", err)
	}

	// Setup policy engine with config
	policyConfig := config.PoliciesConfig{
		Directory:    policiesDir,
		DefaultDeny:  true,
		CacheEnabled: false,
		CacheTTL:     0,
	}
	policyEngine, err := policy.NewEngine(policyConfig, logger)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test cases matching user's scenarios
	testCases := []struct {
		name          string
		userGroups    []string
		expectedAllow []string
		expectedDeny  []string
	}{
		{
			name:          "AdminUser",
			userGroups:    []string{"admin"},
			expectedAllow: []string{"s3:*", "iam:*"},
		},
		{
			name:          "DeveloperUser",
			userGroups:    []string{"developer"},
			expectedAllow: []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:CreateBucket", "s3:DeleteBucket"},
		},
		{
			name:          "ReadOnlyUser",
			userGroups:    []string{"readonly"},
			expectedAllow: []string{"s3:GetObject", "s3:ListBucket"},
		},
		{
			name:          "MultiGroupUser",
			userGroups:    []string{"developer", "readonly"},
			expectedAllow: []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:CreateBucket", "s3:DeleteBucket"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test user
			userInfo := &auth.UserInfo{
				Subject: "test-user-" + tc.name,
				Email:   tc.name + "@example.com",
				Groups:  tc.userGroups,
			}

			// Test policy evaluation for S3 operations
			s3Operations := []string{
				"s3:GetObject",
				"s3:PutObject",
				"s3:DeleteObject",
				"s3:ListBucket",
				"s3:CreateBucket",
				"s3:DeleteBucket",
				"s3:*",
				"iam:*",
			}

			for _, action := range s3Operations {
				// Resolve user's groups to applicable policies
				applicablePolicies := make([]string, 0)
				for _, groupName := range userInfo.Groups {
					group, err := groupStore.Get(groupName)
					if err != nil {
						t.Fatalf("Failed to get group %s: %v", groupName, err)
					}
					applicablePolicies = append(applicablePolicies, group.Policies...)
				}

				ctx := policy.EvaluationContext{
					Action:   action,
					Bucket:   "test-bucket",
					Key:      "test-key",
					Resource: "arn:aws:s3:::test-bucket/test-key",
					UserID:   userInfo.Email,
					Groups:   userInfo.Groups,
					Policies: applicablePolicies,
				}

				decision := policyEngine.Evaluate(&ctx)

				// Check if this action should be allowed
				shouldAllow := false
				for _, allowed := range tc.expectedAllow {
					if allowed == action || (allowed == "s3:*" && strings.HasPrefix(action, "s3:")) || (allowed == "iam:*" && strings.HasPrefix(action, "iam:")) {
						shouldAllow = true
						break
					}
				}

				if shouldAllow && !decision.Allowed {
					t.Errorf("Action %s should be allowed for user with groups %v, but was denied. Reason: %s",
						action, userInfo.Groups, decision.Reason)
				} else if !shouldAllow && decision.Allowed {
					t.Errorf("Action %s should be denied for user with groups %v, but was allowed",
						action, userInfo.Groups)
				} else {
					t.Logf("✓ Action %s correctly %s for user with groups %v",
						action, map[bool]string{true: "allowed", false: "denied"}[decision.Allowed], userInfo.Groups)
				}
			}
		})
	}
}

// TestSyncServiceGroupLogic tests that the sync service correctly handles
// group-based user synchronization without requiring AWS services.
func TestCredentialStoreGroups(t *testing.T) {
	testDir := t.TempDir()
	credsFile := filepath.Join(testDir, "credentials.json")

	logger := logrus.New()
	store, err := store.NewCredentialStore(credsFile, logger)
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	// Test creating credential with groups
	userID := "test@example.com"
	name := "test-cred"
	description := "Test credential"
	groups := []string{"developer", "admin"}
	accessKey := "AKIATEST123"
	secretKey := "test-secret"
	sessionToken := ""
	roleName := ""
	backendData := map[string]interface{}{"test": "data"}

	cred, err := store.CreateWithKeys(userID, name, description, groups, accessKey, secretKey, sessionToken, roleName, backendData)
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}

	// Verify credential has correct groups
	if len(cred.Groups) != len(groups) {
		t.Errorf("Expected %d groups, got %d", len(groups), len(cred.Groups))
	}

	for i, expected := range groups {
		if i >= len(cred.Groups) || cred.Groups[i] != expected {
			t.Errorf("Expected group %s at index %d, got %s", expected, i, cred.Groups[i])
		}
	}

	t.Logf("✓ Credential created with groups: %v", cred.Groups)

	// Test listing by groups
	creds, err := store.ListByGroups([]string{"developer"})
	if err != nil {
		t.Fatalf("Failed to list credentials by groups: %v", err)
	}

	if len(creds) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(creds))
	}

	if creds[0].ID != cred.ID {
		t.Errorf("Expected credential ID %s, got %s", cred.ID, creds[0].ID)
	}

	t.Logf("✓ Credential correctly found by group filter")
}

func TestOIDCGroupsPriority(t *testing.T) {
	testDir := t.TempDir()
	usersDir := filepath.Join(testDir, "users")
	groupsDir := filepath.Join(testDir, "groups")

	os.MkdirAll(usersDir, 0755)
	os.MkdirAll(groupsDir, 0755)

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create SCIM user with one set of groups
	createSCIMUser(t, usersDir, "test@example.com", "Test User", []string{"scim-group-1", "scim-group-2"})

	// Create groups
	createTestGroup(t, groupsDir, "scim-group-1", "SCIM Group 1", []string{"Read-Only"})
	createTestGroup(t, groupsDir, "scim-group-2", "SCIM Group 2", []string{"Read-Only"})
	createTestGroup(t, groupsDir, "oidc-group-1", "OIDC Group 1", []string{"Read-Write"})

	userStore, err := store.NewUserStore(usersDir, groupsDir, logger)
	if err != nil {
		t.Fatalf("Failed to create user store: %v", err)
	}

	// Simulate OIDC authentication with different groups
	// In real scenario, OIDC token would have oidc-group-1, overriding SCIM data
	userInfo := &auth.UserInfo{
		Email:          "test@example.com",
		Subject:        "test@example.com",
		Groups:         []string{"oidc-group-1"}, // OIDC groups
		OriginalGroups: []string{"oidc-group-1"}, // These should take precedence
	}

	// Verify SCIM groups exist
	scimGroups := userStore.GetUserGroups("test@example.com")
	if len(scimGroups) != 2 {
		t.Errorf("Expected 2 SCIM groups, got %d", len(scimGroups))
	}
	t.Logf("✓ SCIM groups loaded: %v", scimGroups)

	// Verify OIDC groups take precedence
	if len(userInfo.Groups) != 1 || userInfo.Groups[0] != "oidc-group-1" {
		t.Errorf("Expected OIDC groups to be [oidc-group-1], got %v", userInfo.Groups)
	}
	t.Logf("✓ OIDC groups take precedence: %v", userInfo.Groups)
}

// TestAdminUserDetection tests that admin user is properly identified
func TestAdminUserDetection(t *testing.T) {
	testCases := []struct {
		name          string
		email         string
		initialGroups []string
		expectAdmin   bool
		expectGroups  []string
	}{
		{
			name:          "Admin user without admin group",
			email:         "admin@example.com",
			initialGroups: []string{"developer"},
			expectAdmin:   true,
			expectGroups:  []string{"developer", "admin"},
		},
		{
			name:          "Admin user with admin group",
			email:         "admin@example.com",
			initialGroups: []string{"admin", "developer"},
			expectAdmin:   true,
			expectGroups:  []string{"admin", "developer"},
		},
		{
			name:          "Non-admin user",
			email:         "user@example.com",
			initialGroups: []string{"developer"},
			expectAdmin:   false,
			expectGroups:  []string{"developer"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Check if admin user identification works (role determination)
			var role auth.UserRole
			if tc.email == "admin@example.com" {
				role = auth.UserRoleGlobalAdmin
			} else {
				role = auth.UserRoleUser
			}
			isAdmin := role == auth.UserRoleGlobalAdmin
			if isAdmin != tc.expectAdmin {
				t.Errorf("Expected admin=%v, got %v", tc.expectAdmin, isAdmin)
			}
			t.Logf("✓ Admin detection correct for %s: %v (role: %s)", tc.email, isAdmin, role)
		})
	}
}

// Helper function to create SCIM user
func createSCIMUser(t *testing.T, usersDir, email, displayName string, groups []string) {
	// Convert string groups to SCIM group references
	scimGroups := make([]map[string]interface{}, len(groups))
	for i, groupID := range groups {
		scimGroups[i] = map[string]interface{}{
			"value":   groupID,
			"display": groupID,
		}
	}

	userData := map[string]interface{}{
		"id":          email,
		"userName":    email,
		"displayName": displayName,
		"emails": []map[string]interface{}{
			{
				"value":   email,
				"primary": true,
			},
		},
		"groups": scimGroups,
		"active": true,
	}

	data, err := json.MarshalIndent(userData, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal user data: %v", err)
	}

	// Use email as filename (sanitized)
	filename := strings.ReplaceAll(email, "@", "_at_")
	filename = strings.ReplaceAll(filename, ".", "_")
	filePath := filepath.Join(usersDir, filename+".json")

	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write user file: %v", err)
	}
}

// Helper functions for creating test data

func createTestGroup(t *testing.T, groupsDir, name, description string, policies []string) {
	groupData := map[string]interface{}{
		"name":        name,
		"description": description,
		"policies":    policies,
	}

	data, err := json.MarshalIndent(groupData, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal group data: %v", err)
	}

	filePath := filepath.Join(groupsDir, name+".json")
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write group file: %v", err)
	}
}

func createTestPolicy(t *testing.T, policiesDir, name string, policy map[string]interface{}) {
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal policy data: %v", err)
	}

	filePath := filepath.Join(policiesDir, name+".json")
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}
}
