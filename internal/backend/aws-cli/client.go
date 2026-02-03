package awscli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/harrykodden/s3-gateway/internal/backend"
	"github.com/sirupsen/logrus"
)

// Client handles AWS operations via AWS CLI
type Client struct {
	logger    *logrus.Logger
	accountID string
	callerArn string
	accessKey string
	secretKey string
}

// UserInfo contains basic IAM user information
type UserInfo struct {
	Username   string
	CreateDate string
}

// AttachedPolicy represents a managed policy attached to a user
type AttachedPolicy struct {
	PolicyArn  string `json:"PolicyArn"`
	PolicyName string `json:"PolicyName"`
}

// AccessKey represents an access key for a user
type AccessKey struct {
	AccessKeyId string `json:"AccessKeyId"`
	Status      string `json:"Status"`
	CreateDate  string `json:"CreateDate"`
}

// CreateUserProfile creates an AWS profile for a user credential
func (c *Client) CreateUserProfile(email, credentialName, accessKey, secretKey, sessionToken, region, endpoint string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	awsDir := filepath.Join(homeDir, ".aws")
	if err := os.MkdirAll(awsDir, 0700); err != nil {
		return fmt.Errorf("failed to create .aws directory: %w", err)
	}

	// Create profile name: <email>-<credential-name>
	emailPrefix := strings.Split(email, "@")[0] // Use email prefix to avoid @ in profile name
	sanitizedCredName := strings.ToLower(strings.ReplaceAll(credentialName, " ", "-"))
	sanitizedCredName = strings.ReplaceAll(sanitizedCredName, "_", "-")
	// Remove any other invalid characters
	for _, char := range []string{".", ",", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "[", "]", "{", "}", "|", "\\", ":", ";", "\"", "'", "<", ">", "?", "/"} {
		sanitizedCredName = strings.ReplaceAll(sanitizedCredName, char, "")
	}
	profileName := fmt.Sprintf("%s-%s", emailPrefix, sanitizedCredName)

	// Read existing config file or create new one
	configPath := filepath.Join(awsDir, "config")
	configContent, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read AWS config: %w", err)
	}

	// Check if profile already exists
	existingConfig := string(configContent)
	if strings.Contains(existingConfig, fmt.Sprintf("[profile %s]", profileName)) {
		c.logger.WithField("profile", profileName).Info("AWS profile already exists, skipping creation")
		return nil
	}

	// Append new profile to config
	newProfileConfig := fmt.Sprintf(`
[profile %s]
region = %s
endpoint_url = %s
signature_version = s3v4
payload_signing_enabled = true
addressing_style = path
`, profileName, region, endpoint)

	newConfigContent := existingConfig + newProfileConfig
	if err := os.WriteFile(configPath, []byte(newConfigContent), 0600); err != nil {
		return fmt.Errorf("failed to write AWS config: %w", err)
	}

	// Read existing credentials file or create new one
	credPath := filepath.Join(awsDir, "credentials")
	credContent, err := os.ReadFile(credPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read AWS credentials: %w", err)
	}

	// Check if credentials already exist
	existingCred := string(credContent)
	if strings.Contains(existingCred, fmt.Sprintf("[%s]", profileName)) {
		c.logger.WithField("profile", profileName).Info("AWS credentials already exist, skipping creation")
		return nil
	}

	// Append new credentials
	var newCredContent string
	if sessionToken != "" {
		newCredContent = fmt.Sprintf(`
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s
`, profileName, accessKey, secretKey, sessionToken)
	} else {
		newCredContent = fmt.Sprintf(`
[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
`, profileName, accessKey, secretKey)
	}

	newCredFileContent := existingCred + newCredContent
	if err := os.WriteFile(credPath, []byte(newCredFileContent), 0600); err != nil {
		return fmt.Errorf("failed to write AWS credentials: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"profile":     profileName,
		"email":       email,
		"credential":  credentialName,
		"config_path": configPath,
		"cred_path":   credPath,
	}).Info("AWS user profile created")

	return nil
}

// RemoveUserProfile removes an AWS profile for a user credential
func (c *Client) RemoveUserProfile(email, credentialName string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	awsDir := filepath.Join(homeDir, ".aws")

	// Create profile name: <email>-<credential-name>
	emailPrefix := strings.Split(email, "@")[0] // Use email prefix to avoid @ in profile name
	sanitizedCredName := strings.ToLower(strings.ReplaceAll(credentialName, " ", "-"))
	sanitizedCredName = strings.ReplaceAll(sanitizedCredName, "_", "-")
	// Remove any other invalid characters
	for _, char := range []string{".", ",", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "[", "]", "{", "}", "|", "\\", ":", ";", "\"", "'", "<", ">", "?", "/"} {
		sanitizedCredName = strings.ReplaceAll(sanitizedCredName, char, "")
	}
	profileName := fmt.Sprintf("%s-%s", emailPrefix, sanitizedCredName)

	// Remove from config file
	configPath := filepath.Join(awsDir, "config")
	if err := c.removeProfileFromFile(configPath, profileName); err != nil {
		c.logger.WithError(err).WithField("profile", profileName).Warn("Failed to remove profile from config")
	}

	// Remove from credentials file
	credPath := filepath.Join(awsDir, "credentials")
	if err := c.removeProfileFromFile(credPath, profileName); err != nil {
		c.logger.WithError(err).WithField("profile", profileName).Warn("Failed to remove profile from credentials")
	}

	c.logger.WithFields(logrus.Fields{
		"profile":    profileName,
		"email":      email,
		"credential": credentialName,
	}).Info("AWS user profile removed")

	return nil
}

// removeProfileFromFile removes a profile section from an AWS config/credentials file
func (c *Client) removeProfileFromFile(filePath, profileName string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to remove
		}
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inProfileSection := false

	for _, line := range lines {
		// Check if we're entering the profile section
		if strings.HasPrefix(line, fmt.Sprintf("[%s]", profileName)) || strings.HasPrefix(line, fmt.Sprintf("[profile %s]", profileName)) {
			inProfileSection = true
			continue // Skip this line
		}

		// If we're in a profile section, skip lines until we find the next section
		if inProfileSection {
			// Check if this is the start of a new section (starts with [)
			if strings.HasPrefix(line, "[") {
				inProfileSection = false
			} else {
				continue // Skip lines in the profile section
			}
		}

		// Keep non-profile lines
		newLines = append(newLines, line)
	}

	// Write back the cleaned content
	newContent := strings.Join(newLines, "\n")
	// Remove any trailing empty lines
	newContent = strings.TrimRight(newContent, "\n") + "\n"

	if err := os.WriteFile(filePath, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// NewClient creates a new AWS CLI client and sets up AWS config files
func NewClient(endpoint, accessKey, secretKey, region string, logger *logrus.Logger) (*Client, error) {
	// Set up AWS config directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	awsDir := filepath.Join(homeDir, ".aws")
	if err := os.MkdirAll(awsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create .aws directory: %w", err)
	}

	// Create ~/.aws/config
	configContent := fmt.Sprintf(`[default]
region = %s
endpoint_url = %s
signature_version = s3v4
payload_signing_enabled = true
addressing_style = path
`, region, endpoint)

	configPath := filepath.Join(awsDir, "config")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to write AWS config: %w", err)
	}

	// Create ~/.aws/credentials
	credContent := fmt.Sprintf(`[default]
aws_access_key_id = %s
aws_secret_access_key = %s
`, accessKey, secretKey)

	credPath := filepath.Join(awsDir, "credentials")
	if err := os.WriteFile(credPath, []byte(credContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to write AWS credentials: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"config_path": configPath,
		"cred_path":   credPath,
		"endpoint":    endpoint,
		"region":      region,
	}).Info("AWS CLI configuration created")

	c := &Client{
		logger:    logger,
		accessKey: accessKey,
		secretKey: secretKey,
	}

	// Get caller identity
	stdout, stderr, err := c.RunAwsCliCommand(logger, "sts", "get-caller-identity", "--output", "json")
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error":  err,
			"stderr": string(stderr),
		}).Warn("Failed to get caller identity, proceeding without account info")
		c.accountID = ""
		c.callerArn = ""
	} else {
		var identity struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
		}
		if err := json.Unmarshal(stdout, &identity); err != nil {
			logger.WithError(err).Warn("Failed to parse caller identity")
			c.accountID = ""
			c.callerArn = ""
		} else {
			c.accountID = identity.Account
			c.callerArn = identity.Arn

			logger.WithFields(logrus.Fields{
				"account_id": identity.Account,
				"caller_arn": identity.Arn,
			}).Info("Retrieved AWS account information")
		}
	}

	return c, nil
}

// GetBackendType returns the backend type
func (c *Client) GetBackendType() string {
	return "aws-cli"
}

// RunAwsCliCommand executes an AWS CLI command with logging
func (c *Client) RunAwsCliCommand(logger *logrus.Logger, args ...string) ([]byte, []byte, error) {
	logger.WithField("aws_cli_args", args).Info("Executing AWS CLI command")
	cmd := exec.Command("aws", args...)
	stdout, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.WithFields(logrus.Fields{
				"aws_cli_args": args,
				"stdout":       string(stdout),
				"stderr":       string(exitErr.Stderr),
			}).Error("AWS CLI command failed")
			return stdout, exitErr.Stderr, err
		}
		logger.WithFields(logrus.Fields{
			"aws_cli_args": args,
			"stdout":       string(stdout),
		}).Error("AWS CLI command failed (non-exit error)")
		return stdout, nil, err
	}
	logger.WithFields(logrus.Fields{
		"aws_cli_args": args,
		"stdout":       string(stdout),
	}).Debug("AWS CLI command succeeded")
	return stdout, nil, nil
}

// CreateUser creates a user in the backend
func (c *Client) CreateUser(email, displayName string) error {
	// Create IAM user
	_, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "create-user",
		"--user-name", email,
		"--output", "json",
	)
	if err != nil {
		// Check if user already exists (this is not an error)
		if strings.Contains(string(stderr), "EntityAlreadyExists") {
			c.logger.WithField("email", email).Debug("IAM user already exists")
			return nil
		}
		return fmt.Errorf("failed to create IAM user: %w (stderr: %s)", err, string(stderr))
	}

	c.logger.WithField("email", email).Info("Created IAM user")
	return nil
}

// CreateCredential creates access keys for IAM users
func (c *Client) CreateCredential(email, credentialName string, policyDoc map[string]interface{}) (backend.CredentialInfo, error) {
	// Ensure IAM user exists
	if err := c.CreateUser(email, ""); err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to ensure user exists: %w", err)
	}

	// Check current access key count (AWS limit: 2 per user)
	keyCount, err := c.getUserAccessKeyCount(email)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to check access key count: %w", err)
	}
	if keyCount >= 2 {
		return backend.CredentialInfo{}, fmt.Errorf("user already has maximum access keys (2). Delete an existing credential first")
	}

	// Create access key for the user
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "create-access-key",
		"--user-name", email,
		"--output", "json",
	)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to create access key: %w (stderr: %s)", err, string(stderr))
	}

	var accessKeyResult struct {
		AccessKey struct {
			AccessKeyId     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			Status          string `json:"Status"`
		} `json:"AccessKey"`
	}
	if err := json.Unmarshal(stdout, &accessKeyResult); err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to parse access key output: %w", err)
	}

	// Attach policy to user
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to marshal policy: %w", err)
	}

	policyFile, err := os.CreateTemp("", "policy-*.json")
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to create policy temp file: %w", err)
	}
	defer os.Remove(policyFile.Name())

	if _, err := policyFile.Write(policyJSON); err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to write policy: %w", err)
	}
	policyFile.Close()

	policyName := fmt.Sprintf("%s-%s-policy", email, credentialName)
	_, stderr, err = c.RunAwsCliCommand(
		c.logger, "iam", "put-user-policy",
		"--user-name", email,
		"--policy-name", policyName,
		"--policy-document", fmt.Sprintf("file://%s", policyFile.Name()),
		"--output", "json",
	)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to attach policy to user: %w (stderr: %s)", err, string(stderr))
	}

	c.logger.WithFields(logrus.Fields{
		"user":        email,
		"credential":  credentialName,
		"access_key":  accessKeyResult.AccessKey.AccessKeyId,
		"policy_name": policyName,
	}).Info("Created IAM access key and attached policy")

	return backend.CredentialInfo{
		AccessKey: accessKeyResult.AccessKey.AccessKeyId,
		SecretKey: accessKeyResult.AccessKey.SecretAccessKey,
		BackendData: map[string]interface{}{
			"type":        "iam-user",
			"user":        email,
			"credential":  credentialName,
			"policy_name": policyName,
		},
	}, nil
}

// getUserAccessKeyCount returns the number of access keys for a user
func (c *Client) getUserAccessKeyCount(username string) (int, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-access-keys",
		"--user-name", username,
		"--output", "json",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to list access keys: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		AccessKeyMetadata []interface{} `json:"AccessKeyMetadata"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return 0, fmt.Errorf("failed to parse access keys: %w", err)
	}

	return len(result.AccessKeyMetadata), nil
}

// UpdateCredential updates an IAM user's policy
func (c *Client) UpdateCredential(email, credentialName string, policyDoc map[string]interface{}, backendData map[string]interface{}) (map[string]interface{}, error) {

	policyName, ok := backendData["policy_name"].(string)
	if !ok {
		return nil, fmt.Errorf("policy_name not found in backendData")
	}

	// Update the policy
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	policyFile, err := os.CreateTemp("", "policy-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create policy temp file: %w", err)
	}
	defer os.Remove(policyFile.Name())

	if _, err := policyFile.Write(policyJSON); err != nil {
		return nil, fmt.Errorf("failed to write policy: %w", err)
	}
	policyFile.Close()

	_, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "put-user-policy",
		"--user-name", email,
		"--policy-name", policyName,
		"--policy-document", fmt.Sprintf("file://%s", policyFile.Name()),
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update user policy: %w (stderr: %s)", err, string(stderr))
	}

	return backendData, nil
}

// DeleteCredential deletes an IAM user's policy and access keys
func (c *Client) DeleteCredential(email, credentialName string, backendData map[string]interface{}) error {

	policyName, ok := backendData["policy_name"].(string)
	if !ok {
		return fmt.Errorf("policy_name not found in backendData")
	}

	// Delete the user policy
	_, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "delete-user-policy",
		"--user-name", email,
		"--policy-name", policyName,
	)
	if err != nil {
		c.logger.WithError(err).WithField("stderr", string(stderr)).Warn("Failed to delete user policy")
	}

	// Delete all access keys for the user (in case there are multiple)
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-access-keys",
		"--user-name", email,
		"--output", "json",
	)
	if err != nil {
		c.logger.WithError(err).WithField("stderr", string(stderr)).Warn("Failed to list access keys")
		return nil // Don't fail the deletion if we can't list keys
	}

	var keysResult struct {
		AccessKeyMetadata []struct {
			AccessKeyId string `json:"AccessKeyId"`
		} `json:"AccessKeyMetadata"`
	}
	if err := json.Unmarshal(stdout, &keysResult); err != nil {
		c.logger.WithError(err).Warn("Failed to parse access keys")
		return nil
	}

	// Delete all access keys
	for _, key := range keysResult.AccessKeyMetadata {
		_, stderr, err = c.RunAwsCliCommand(
			c.logger, "iam", "delete-access-key",
			"--user-name", email,
			"--access-key-id", key.AccessKeyId,
		)
		if err != nil {
			c.logger.WithError(err).WithFields(logrus.Fields{
				"access_key": key.AccessKeyId,
				"stderr":     string(stderr),
			}).Warn("Failed to delete access key")
		}
	}

	return nil
}

// ListUsers lists all IAM users
func (c *Client) ListUsers(ctx context.Context) ([]string, error) {
	stdout, stderr, err := c.RunAwsCliCommand(c.logger, "iam", "list-users", "--output", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		Users []struct {
			UserName string `json:"UserName"`
		} `json:"Users"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse aws output: %w", err)
	}

	var users []string
	for _, user := range result.Users {
		users = append(users, user.UserName)
	}

	c.logger.WithField("count", len(users)).Debug("Listed IAM users via CLI")
	return users, nil
}

// DeleteUser deletes an IAM user and all associated resources
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	// Delete all access keys first
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-access-keys",
		"--user-name", username,
		"--output", "json")

	if err != nil {
		return fmt.Errorf("failed to list access keys: %w (stderr: %s)", err, string(stderr))
	}

	var keysResult struct {
		AccessKeyMetadata []struct {
			AccessKeyId string `json:"AccessKeyId"`
		} `json:"AccessKeyMetadata"`
	}
	if err := json.Unmarshal(stdout, &keysResult); err != nil {
		return fmt.Errorf("failed to parse access keys: %w", err)
	}

	for _, key := range keysResult.AccessKeyMetadata {
		_, stderr, err = c.RunAwsCliCommand(
			c.logger, "iam", "delete-access-key",
			"--user-name", username,
			"--access-key-id", key.AccessKeyId)
		if err != nil {
			c.logger.WithError(err).WithFields(
				logrus.Fields{
					"access_key": key.AccessKeyId,
					"output":     string(stderr),
				}).Warn("Failed to delete access key")
		}
	}

	// Detach all user policies
	stdout, stderr, err = c.RunAwsCliCommand(
		c.logger, "iam", "list-attached-user-policies",
		"--user-name", username,
		"--output", "json")

	if err == nil {
		var policiesResult struct {
			AttachedPolicies []struct {
				PolicyArn string `json:"PolicyArn"`
			} `json:"AttachedPolicies"`
		}
		if err := json.Unmarshal(stdout, &policiesResult); err == nil {
			for _, policy := range policiesResult.AttachedPolicies {
				_, stderr, err = c.RunAwsCliCommand(
					c.logger, "iam", "detach-user-policy",
					"--user-name", username,
					"--policy-arn", policy.PolicyArn)
				if err != nil {
					c.logger.WithError(err).WithFields(
						logrus.Fields{
							"policy_arn": policy.PolicyArn,
							"output":     string(stderr),
						}).Warn("Failed to detach user policy")
				}
			}
		}
	}

	// Delete all inline user policies
	stdout, stderr, err = c.RunAwsCliCommand(
		c.logger, "iam", "list-user-policies",
		"--user-name", username,
		"--output", "json")

	if err == nil {
		var inlinePoliciesResult struct {
			PolicyNames []string `json:"PolicyNames"`
		}
		if err := json.Unmarshal(stdout, &inlinePoliciesResult); err == nil {
			for _, policyName := range inlinePoliciesResult.PolicyNames {
				_, stderr, err = c.RunAwsCliCommand(
					c.logger, "iam", "delete-user-policy",
					"--user-name", username,
					"--policy-name", policyName)
				if err != nil {
					c.logger.WithError(err).WithFields(
						logrus.Fields{
							"policy_name": policyName,
							"output":      string(stderr),
						}).Warn("Failed to delete inline user policy")
				}
			}
		}
	}

	// Remove user from all groups
	stdout, stderr, err = c.RunAwsCliCommand(
		c.logger, "iam", "list-groups-for-user",
		"--user-name", username,
		"--output", "json")

	if err == nil {
		var groupsResult struct {
			Groups []struct {
				GroupName string `json:"GroupName"`
			} `json:"Groups"`
		}
		if err := json.Unmarshal(stdout, &groupsResult); err == nil {
			for _, group := range groupsResult.Groups {
				_, stderr, err = c.RunAwsCliCommand(
					c.logger, "iam", "remove-user-from-group",
					"--user-name", username,
					"--group-name", group.GroupName)
				if err != nil {
					c.logger.WithError(err).WithFields(
						logrus.Fields{
							"group_name": group.GroupName,
							"output":     string(stderr),
						}).Warn("Failed to remove user from group")
				}
			}
		}
	}

	// Delete user
	_, stderr, err = c.RunAwsCliCommand(
		c.logger, "iam", "delete-user",
		"--user-name", username)

	if err != nil {
		return fmt.Errorf("failed to delete user: %w (stderr: %s)", err, string(stderr))
	}

	c.logger.WithField("username", username).Info("Deleted IAM user via CLI")
	return nil
}

// GetUserInfo returns basic information about an IAM user
func (c *Client) GetUserInfo(ctx context.Context, username string) (*UserInfo, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "get-user",
		"--user-name", username,
		"--output", "json")

	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		User struct {
			UserName   string `json:"UserName"`
			CreateDate string `json:"CreateDate"`
		} `json:"User"`
	}

	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &UserInfo{
		Username:   result.User.UserName,
		CreateDate: result.User.CreateDate,
	}, nil
}

// ListUserGroups returns the groups that a user belongs to
func (c *Client) ListUserGroups(ctx context.Context, username string) ([]string, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-groups-for-user",
		"--user-name", username,
		"--output", "json")

	if err != nil {
		return nil, fmt.Errorf("failed to list user groups: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		Groups []struct {
			GroupName string `json:"GroupName"`
		} `json:"Groups"`
	}

	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user groups: %w", err)
	}

	groups := make([]string, 0, len(result.Groups))
	for _, group := range result.Groups {
		groups = append(groups, group.GroupName)
	}

	return groups, nil
}

// ListAttachedUserPolicies returns managed policies attached to a user
func (c *Client) ListAttachedUserPolicies(ctx context.Context, username string) ([]AttachedPolicy, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-attached-user-policies",
		"--user-name", username,
		"--output", "json")

	if err != nil {
		return nil, fmt.Errorf("failed to list attached user policies: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		AttachedPolicies []AttachedPolicy `json:"AttachedPolicies"`
	}

	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse attached user policies: %w", err)
	}

	return result.AttachedPolicies, nil
}

// ListUserPolicies returns inline policy names for a user
func (c *Client) ListUserPolicies(ctx context.Context, username string) ([]string, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-user-policies",
		"--user-name", username,
		"--output", "json")

	if err != nil {
		return nil, fmt.Errorf("failed to list user policies: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		PolicyNames []string `json:"PolicyNames"`
	}

	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse user policies: %w", err)
	}

	return result.PolicyNames, nil
}

// GetUserPolicy returns the policy document for an inline user policy
func (c *Client) GetUserPolicy(ctx context.Context, username, policyName string) (string, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "get-user-policy",
		"--user-name", username,
		"--policy-name", policyName,
		"--output", "json")

	if err != nil {
		return "", fmt.Errorf("failed to get user policy: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		PolicyDocument interface{} `json:"PolicyDocument"`
	}

	if err := json.Unmarshal(stdout, &result); err != nil {
		return "", fmt.Errorf("failed to parse user policy: %w", err)
	}

	// Convert the PolicyDocument back to JSON string
	policyJSON, err := json.Marshal(result.PolicyDocument)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy document: %w", err)
	}

	return string(policyJSON), nil
}

// ListAccessKeys returns access keys for a user
func (c *Client) ListAccessKeys(ctx context.Context, username string) ([]AccessKey, error) {
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "list-access-keys",
		"--user-name", username,
		"--output", "json")

	if err != nil {
		return nil, fmt.Errorf("failed to list access keys: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		AccessKeyMetadata []AccessKey `json:"AccessKeyMetadata"`
	}

	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse access keys: %w", err)
	}

	return result.AccessKeyMetadata, nil
}
