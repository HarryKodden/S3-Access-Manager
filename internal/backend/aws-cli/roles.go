package awscli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// RoleManager handles AWS IAM Role management operations via CLI
type RoleManager struct {
	client *Client
	logger *logrus.Logger
}

// NewRoleManager creates a new AWS CLI Role manager
func NewRoleManager(client *Client) *RoleManager {
	return &RoleManager{
		client: client,
		logger: client.logger,
	}
}

// ListRoles lists all IAM Roles
func (u *RoleManager) ListRoles(ctx context.Context) ([]string, error) {
	stdout, stderr, err := u.client.RunAwsCliCommand(u.logger, "iam", "list-roles", "--output", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to run aws iam list-roles: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		Roles []struct {
			RoleName string `json:"RoleName"`
		} `json:"Roles"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse aws output: %w", err)
	}

	var roles []string
	for _, role := range result.Roles {
		// Strip RGW prefix (everything before the last $)
		if lastDollar := strings.LastIndex(role.RoleName, "$"); lastDollar >= 0 {
			roles = append(roles, role.RoleName[lastDollar+1:])
		} else {
			roles = append(roles, role.RoleName)
		}
	}

	return roles, nil
}

// CreateRole creates an IAM Role with the combined policy document
func (u *RoleManager) CreateRole(ctx context.Context, roleName string, combinedPolicyDoc map[string]interface{}) error {
	// Default assume role policy allowing the gateway to assume the role
	assumeRolePolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect":    "Allow",
				"Principal": "*",
				"Action":    "sts:AssumeRole",
			},
		},
	}

	// Create assume role policy file
	assumePolicyJSON, err := json.Marshal(assumeRolePolicy)
	if err != nil {
		return fmt.Errorf("failed to marshal assume role policy: %w", err)
	}

	tmpAssumeFile, err := os.CreateTemp("", "assume-policy-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp assume policy file: %w", err)
	}
	defer os.Remove(tmpAssumeFile.Name())

	if _, err := tmpAssumeFile.Write(assumePolicyJSON); err != nil {
		return fmt.Errorf("failed to write assume policy: %w", err)
	}
	tmpAssumeFile.Close()

	u.logger.Info(string(assumePolicyJSON))

	// Create role
	_, stderr, err := u.client.RunAwsCliCommand(u.logger, "iam", "create-role",
		"--role-name", roleName,
		"--assume-role-policy-document", fmt.Sprintf("file://%s", tmpAssumeFile.Name()),
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to create IAM role: %w (stderr: %s)", err, string(stderr))
	}

	// Attach combined policy as inline policy
	combinedPolicyJSON, err := json.Marshal(combinedPolicyDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal combined policy: %w", err)
	}

	tmpPolicyFile, err := os.CreateTemp("", "combined-policy-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp policy file: %w", err)
	}
	defer os.Remove(tmpPolicyFile.Name())

	if _, err := tmpPolicyFile.Write(combinedPolicyJSON); err != nil {
		return fmt.Errorf("failed to write combined policy: %w", err)
	}
	tmpPolicyFile.Close()

	_, stderr, err = u.client.RunAwsCliCommand(u.logger, "iam", "put-role-policy",
		"--role-name", roleName,
		"--policy-name", fmt.Sprintf("%s-policy", roleName),
		"--policy-document", fmt.Sprintf("file://%s", tmpPolicyFile.Name()),
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to attach combined policy: %w (stderr: %s)", err, string(stderr))
	}

	u.logger.WithField("role_name", roleName).Info("Created IAM role with combined policy")
	return nil
}

// UpdateRole updates an IAM Role's combined policy document
func (u *RoleManager) UpdateRole(ctx context.Context, roleName string, combinedPolicyDoc map[string]interface{}) error {
	// Detach old inline policy
	_, _, err := u.client.RunAwsCliCommand(u.logger, "iam", "delete-role-policy",
		"--role-name", roleName,
		"--policy-name", fmt.Sprintf("%s-policy", roleName),
		"--output", "json",
	)
	if err != nil {
		u.logger.WithError(err).WithField("role_name", roleName).Warn("Failed to detach old policy, continuing")
	}

	// Attach new combined policy
	combinedPolicyJSON, err := json.Marshal(combinedPolicyDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal combined policy: %w", err)
	}

	tmpPolicyFile, err := os.CreateTemp("", "combined-policy-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp policy file: %w", err)
	}
	defer os.Remove(tmpPolicyFile.Name())

	if _, err := tmpPolicyFile.Write(combinedPolicyJSON); err != nil {
		return fmt.Errorf("failed to write combined policy: %w", err)
	}
	tmpPolicyFile.Close()

	_, stderr, err := u.client.RunAwsCliCommand(u.logger, "iam", "put-role-policy",
		"--role-name", roleName,
		"--policy-name", fmt.Sprintf("%s-policy", roleName),
		"--policy-document", fmt.Sprintf("file://%s", tmpPolicyFile.Name()),
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to attach updated combined policy: %w (stderr: %s)", err, string(stderr))
	}

	u.logger.WithField("role_name", roleName).Info("Updated IAM role with new combined policy")
	return nil
}

// GetRolePolicy retrieves the inline policy document for a role
func (u *RoleManager) GetRolePolicy(ctx context.Context, roleName string) (map[string]interface{}, error) {
	stdout, stderr, err := u.client.RunAwsCliCommand(u.logger, "iam", "get-role-policy",
		"--role-name", roleName,
		"--policy-name", fmt.Sprintf("%s-policy", roleName),
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get role policy: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		PolicyDocument map[string]interface{} `json:"PolicyDocument"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %w", err)
	}

	return result.PolicyDocument, nil
}

// DeleteRole deletes an IAM Role and all associated resources
func (u *RoleManager) DeleteRole(ctx context.Context, roleName string) error {
	_, stderr, err := u.client.RunAwsCliCommand(u.logger, "iam", "delete-role",
		"--role-name", roleName,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to delete IAM role: %w (stderr: %s)", err, string(stderr))
	}

	return nil
}
