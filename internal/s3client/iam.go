package s3client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/harrykodden/s3-gateway/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
)

// IAMClient wraps AWS IAM SDK for Ceph object storage
type IAMClient struct {
	client    *iam.Client
	stsClient *sts.Client
	logger    *logrus.Logger
}

// AccessKeyInfo represents access key metadata from IAM
type AccessKeyInfo struct {
	AccessKeyId string
	Status      string
	CreateDate  string
}

// NewIAMClient creates a new IAM client with IAM-specific credentials
func NewIAMClient(cfg config.S3Config, logger *logrus.Logger) (*IAMClient, error) {
	ctx := context.Background()

	accessPrefix := ""
	if len(cfg.IAM.AccessKey) > 5 {
		accessPrefix = cfg.IAM.AccessKey[:5]
	} else if len(cfg.IAM.AccessKey) > 0 {
		accessPrefix = cfg.IAM.AccessKey
	}

	logger.WithFields(logrus.Fields{
		"endpoint":      cfg.Endpoint,
		"region":        cfg.Region,
		"has_access":    cfg.IAM.AccessKey != "",
		"has_secret":    cfg.IAM.SecretKey != "",
		"access_prefix": accessPrefix,
	}).Info("Initializing IAM client")

	// Create AWS config with IAM credentials
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.IAM.AccessKey,
			cfg.IAM.SecretKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for IAM: %w", err)
	}

	// Create IAM client with custom endpoint resolver for Ceph/MinIO
	iamClient := iam.NewFromConfig(awsCfg, func(o *iam.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			// Disable HTTPS requirement if needed
			o.EndpointOptions.DisableHTTPS = false
		}
		// Set the API version in the client options
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Finalize.Add(
				middleware.FinalizeMiddlewareFunc(
					"SetSTSVersion",
					func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
						// Modify the request to use the correct API version
						if req, ok := in.Request.(*smithyhttp.Request); ok {
							q := req.URL.Query()
							q.Set("Version", "2011-06-15")
							req.URL.RawQuery = q.Encode()
						}
						return next.HandleFinalize(ctx, in)
					},
				),
				middleware.Before,
			)
		})
	})

	// Create STS client with same configuration
	stsClient := sts.NewFromConfig(awsCfg, func(o *sts.Options) {
		if cfg.Endpoint != "" {
			// For Ceph/MinIO, STS operations use the same endpoint as S3
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.EndpointOptions.DisableHTTPS = false
		}
	})

	logger.Info("IAM client initialized successfully")

	return &IAMClient{
		client:    iamClient,
		stsClient: stsClient,
		logger:    logger,
	}, nil
}

// CreateUser creates an IAM user if it doesn't exist
func (c *IAMClient) CreateUser(ctx context.Context, username string) error {
	// Check if user exists
	_, err := c.client.GetUser(ctx, &iam.GetUserInput{
		UserName: aws.String(username),
	})
	if err == nil {
		c.logger.WithField("username", username).Debug("IAM user already exists")
		return nil
	}

	// User doesn't exist, create it
	_, err = c.client.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return fmt.Errorf("failed to create IAM user: %w", err)
	}

	c.logger.WithField("username", username).Info("Created IAM user")
	return nil
}

// ListUserPolicies lists all inline policies attached to a user
func (c *IAMClient) ListUserPolicies(ctx context.Context, username string) ([]string, error) {
	result, err := c.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list user policies: %w", err)
	}

	return result.PolicyNames, nil
}

// PutUserPolicy attaches an inline policy to a user
func (c *IAMClient) PutUserPolicy(ctx context.Context, username, policyName string, policyDocument map[string]interface{}) error {
	// Convert policy document to JSON string
	policyJSON, err := json.Marshal(policyDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal policy document: %w", err)
	}

	_, err = c.client.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName:       aws.String(username),
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(string(policyJSON)),
	})
	if err != nil {
		return fmt.Errorf("failed to put user policy: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"username":    username,
		"policy_name": policyName,
	}).Info("Attached policy to IAM user")
	return nil
}

// DeleteUserPolicy removes an inline policy from a user
func (c *IAMClient) DeleteUserPolicy(ctx context.Context, username, policyName string) error {
	_, err := c.client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
		UserName:   aws.String(username),
		PolicyName: aws.String(policyName),
	})
	if err != nil {
		return fmt.Errorf("failed to delete user policy: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"username":    username,
		"policy_name": policyName,
	}).Info("Removed policy from IAM user")
	return nil
}

// CreateAccessKey creates a new access key for a user
func (c *IAMClient) CreateAccessKey(ctx context.Context, username string) (accessKey, secretKey string, err error) {
	result, err := c.client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create access key: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"username":   username,
		"access_key": *result.AccessKey.AccessKeyId,
	}).Info("Created IAM access key")

	return *result.AccessKey.AccessKeyId, *result.AccessKey.SecretAccessKey, nil
}

// DeleteAccessKey deletes an access key
func (c *IAMClient) DeleteAccessKey(ctx context.Context, username, accessKeyID string) error {
	_, err := c.client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName:    aws.String(username),
		AccessKeyId: aws.String(accessKeyID),
	})
	if err != nil {
		return fmt.Errorf("failed to delete access key: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"username":   username,
		"access_key": accessKeyID,
	}).Info("Deleted IAM access key")
	return nil
}

// ListAccessKeys lists all access keys for a user
func (c *IAMClient) ListAccessKeys(ctx context.Context, username string) ([]string, error) {
	result, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access keys: %w", err)
	}

	keys := make([]string, 0, len(result.AccessKeyMetadata))
	for _, key := range result.AccessKeyMetadata {
		keys = append(keys, *key.AccessKeyId)
	}

	return keys, nil
}

// ListAccessKeyMetadata lists all access key metadata for a user
func (c *IAMClient) ListAccessKeyMetadata(ctx context.Context, username string) ([]AccessKeyInfo, error) {
	result, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access keys: %w", err)
	}

	keys := make([]AccessKeyInfo, 0, len(result.AccessKeyMetadata))
	for _, key := range result.AccessKeyMetadata {
		keys = append(keys, AccessKeyInfo{
			AccessKeyId: *key.AccessKeyId,
			Status:      string(key.Status),
			CreateDate:  key.CreateDate.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	return keys, nil
}

// ListUsers lists all IAM users
func (c *IAMClient) ListUsers(ctx context.Context) ([]string, error) {
	result, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]string, 0, len(result.Users))
	for _, user := range result.Users {
		users = append(users, *user.UserName)
	}

	return users, nil
}

// DeleteUser deletes an IAM user
func (c *IAMClient) DeleteUser(ctx context.Context, username string) error {
	_, err := c.client.DeleteUser(ctx, &iam.DeleteUserInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	c.logger.WithField("username", username).Info("Deleted IAM user")
	return nil
}

// AssumeRole assumes a role and returns temporary credentials
func (c *IAMClient) AssumeRole(ctx context.Context, roleArn string, sessionName string, durationSeconds int32) (accessKey, secretKey, sessionToken string, err error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(durationSeconds),
	}

	result, err := c.stsClient.AssumeRole(ctx, input)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to assume role: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"role_arn":     roleArn,
		"session_name": sessionName,
	}).Info("Assumed IAM role")

	return *result.Credentials.AccessKeyId, *result.Credentials.SecretAccessKey, *result.Credentials.SessionToken, nil
}

// GetAccountID retrieves the AWS account ID using STS GetCallerIdentity
func (c *IAMClient) GetAccountID(ctx context.Context) (string, error) {
	input := &sts.GetCallerIdentityInput{}

	result, err := c.stsClient.GetCallerIdentity(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	return *result.Account, nil
}

// CreateRole creates an IAM role with the specified policy document
func (c *IAMClient) CreateRole(ctx context.Context, roleName string, policyDoc map[string]interface{}) error {
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal policy document: %w", err)
	}

	// Create assume role policy document that allows the current user to assume this role
	assumeRolePolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"AWS": "arn:aws:iam::*:user/*", // Allow any user to assume this role (you may want to restrict this)
				},
				"Action": "sts:AssumeRole",
			},
		},
	}

	assumeRoleJSON, err := json.Marshal(assumeRolePolicy)
	if err != nil {
		return fmt.Errorf("failed to marshal assume role policy: %w", err)
	}

	_, err = c.client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(assumeRoleJSON)),
	})
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	// Attach the policy as an inline policy
	_, err = c.client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(fmt.Sprintf("%s-policy", roleName)),
		PolicyDocument: aws.String(string(policyJSON)),
	})
	if err != nil {
		// Try to clean up the role if policy attachment fails
		c.client.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
		return fmt.Errorf("failed to attach role policy: %w", err)
	}

	c.logger.WithField("role_name", roleName).Info("Created IAM role with policy")
	return nil
}

// DeleteRole deletes an IAM role
func (c *IAMClient) DeleteRole(ctx context.Context, roleName string) error {
	_, err := c.client.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	c.logger.WithField("role_name", roleName).Info("Deleted IAM role")
	return nil
}
