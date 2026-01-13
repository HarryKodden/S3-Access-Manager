package awscli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/harrykodden/s3-gateway/internal/backend"
	"github.com/sirupsen/logrus"
)

// Client handles AWS operations via AWS CLI
type Client struct {
	logger *logrus.Logger
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

	return &Client{
		logger: logger,
	}, nil
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

// CreateUser creates an IAM user if it doesn't exist
func (c *Client) CreateUser(email, displayName string) error {
	username := email

	// Check if user exists first
	_, _, err := c.RunAwsCliCommand(c.logger, "iam", "get-user", "--user-name", username, "--output", "json")
	if err == nil {
		c.logger.WithField("username", username).Debug("IAM user already exists")
		return nil
	}

	// Create IAM user
	_, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "create-user", "--user-name", username,
		"--tags", fmt.Sprintf("Key=Email,Value=%s", email),
		fmt.Sprintf("Key=DisplayName,Value=%s", displayName),
		"Key=ManagedBy,Value=S3Gateway",
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to create IAM user: %w (stderr: %s)", err, string(stderr))
	}

	c.logger.WithFields(logrus.Fields{
		"username": username,
		"email":    email,
	}).Info("Created IAM user via CLI")

	return nil
}

// CreateCredential creates an IAM access key for the user
func (c *Client) CreateCredential(email, credentialName string, policyDoc map[string]interface{}) (backend.CredentialInfo, error) {
	username := email

	// Create IAM policy for this credential
	policyName := fmt.Sprintf("%s-%s-policy", username, credentialName)
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Write policy to temp file
	tmpFile, err := os.CreateTemp("", "policy-*.json")
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(policyJSON); err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to write policy: %w", err)
	}
	tmpFile.Close()

	// Create policy
	_, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "put-user-policy",
		"--policy-name", policyName,
		"--policy-document", fmt.Sprintf("file://%s", tmpFile.Name()),
		"--user-name", username,
		"--output", "json",
	)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to create IAM policy: %w (stderr: %s)", err, string(stderr))
	}

	// Create access key
	stdout, stderr, err := c.RunAwsCliCommand(
		c.logger, "iam", "create-access-key",
		"--user-name", username,
		"--output", "json",
	)
	if err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to create access key: %w (stderr: %s)", err, string(stderr))
	}

	var keyResult struct {
		AccessKey struct {
			AccessKeyId     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
		} `json:"AccessKey"`
	}
	if err := json.Unmarshal(stdout, &keyResult); err != nil {
		return backend.CredentialInfo{}, fmt.Errorf("failed to parse access key output: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"username":   username,
		"access_key": keyResult.AccessKey.AccessKeyId,
	}).Info("Created IAM access key via CLI")

	return backend.CredentialInfo{
		AccessKey: keyResult.AccessKey.AccessKeyId,
		SecretKey: keyResult.AccessKey.SecretAccessKey,
	}, nil
}

// UpdateCredential updates an IAM access key's policy
func (c *Client) UpdateCredential(email, credentialName string, policyDoc map[string]interface{}, backendData map[string]interface{}) (map[string]interface{}, error) {
	err := c.DeleteCredential(email, credentialName, backendData)
	if err != nil {
		return nil, err
	}
	credInfo, err := c.CreateCredential(email, credentialName, policyDoc)
	if err != nil {
		return nil, err
	}
	return credInfo.BackendData, nil
}

// DeleteCredential deletes an IAM access key and associated policy
func (c *Client) DeleteCredential(email, credentialName string, backendData map[string]interface{}) error {
	username := email

	// Detach and delete the policy if we have the ARN
	if policyArn, ok := backendData["policy_arn"].(string); ok && policyArn != "" {
		// Detach policy
		cmd := exec.Command("aws", "iam", "detach-user-policy",
			"--user-name", username,
			"--policy-arn", policyArn)
		if output, err := cmd.CombinedOutput(); err != nil {
			c.logger.WithError(err).WithField("output", string(output)).Warn("Failed to detach policy")
		}

		// Delete policy
		cmd = exec.Command("aws", "iam", "delete-policy",
			"--policy-arn", policyArn)
		if output, err := cmd.CombinedOutput(); err != nil {
			c.logger.WithError(err).WithField("output", string(output)).Warn("Failed to delete policy")
		}
	}

	// List and delete all access keys
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
		_, stderr, err := c.RunAwsCliCommand(
			c.logger, "iam", "delete-access-key",
			"--user-name", username,
			"--access-key-id", key.AccessKeyId)
		if err != nil {
			c.logger.WithError(err).WithFields(logrus.Fields{
				"access_key": key.AccessKeyId,
				"output":     string(stderr),
			}).Error("Failed to delete access key")
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
