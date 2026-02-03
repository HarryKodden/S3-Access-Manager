package awscli

import (
	"context"

	"github.com/harrykodden/s3-gateway/internal/backend"
	"github.com/sirupsen/logrus"
)

// UserManager handles AWS IAM user management operations via CLI
type UserManager struct {
	client *Client
	logger *logrus.Logger
}

// NewUserManager creates a new AWS CLI user manager
func NewUserManager(client *Client) *UserManager {
	return &UserManager{
		client: client,
		logger: client.logger,
	}
}

// ListUsers lists all IAM users
func (u *UserManager) ListUsers(ctx context.Context) ([]string, error) {
	return u.client.ListUsers(ctx)
}

// GetUserDetails returns comprehensive information about a specific IAM user
func (u *UserManager) GetUserDetails(ctx context.Context, username string) (backend.UserDetails, error) {
	details := backend.UserDetails{
		Username: username,
	}

	// Get user information
	userInfo, err := u.client.GetUserInfo(ctx, username)
	if err != nil {
		u.logger.WithError(err).WithField("username", username).Warn("Failed to get user info")
	} else {
		details.CreateDate = userInfo.CreateDate
	}

	// Get user's groups
	groups, err := u.client.ListUserGroups(ctx, username)
	if err != nil {
		u.logger.WithError(err).WithField("username", username).Warn("Failed to get user groups")
	} else {
		details.Groups = groups
	}

	// Get attached managed policies
	managedPolicies, err := u.client.ListAttachedUserPolicies(ctx, username)
	if err != nil {
		u.logger.WithError(err).WithField("username", username).Warn("Failed to get attached user policies")
	} else {
		for _, policy := range managedPolicies {
			details.Policies = append(details.Policies, backend.UserPolicy{
				Name: policy.PolicyName,
				Type: "Managed",
			})
		}
	}

	// Get inline policies
	inlinePolicies, err := u.client.ListUserPolicies(ctx, username)
	if err != nil {
		u.logger.WithError(err).WithField("username", username).Warn("Failed to get user inline policies")
	} else {
		for _, policyName := range inlinePolicies {
			policyDoc, err := u.client.GetUserPolicy(ctx, username, policyName)
			if err != nil {
				u.logger.WithError(err).WithFields(logrus.Fields{
					"username":   username,
					"policyName": policyName,
				}).Warn("Failed to get user policy document")
				details.Policies = append(details.Policies, backend.UserPolicy{
					Name: policyName,
					Type: "Inline",
				})
			} else {
				details.Policies = append(details.Policies, backend.UserPolicy{
					Name:     policyName,
					Type:     "Inline",
					Document: policyDoc,
				})
			}
		}
	}

	// Get access keys
	accessKeys, err := u.client.ListAccessKeys(ctx, username)
	if err != nil {
		u.logger.WithError(err).WithField("username", username).Warn("Failed to get user access keys")
	} else {
		for _, key := range accessKeys {
			details.AccessKeys = append(details.AccessKeys, backend.AccessKeyInfo{
				AccessKeyId: key.AccessKeyId,
				Status:      key.Status,
				CreateDate:  key.CreateDate,
			})
		}
	}

	return details, nil
}

// DeleteUser deletes an IAM user and all associated resources
func (u *UserManager) DeleteUser(ctx context.Context, username string) error {
	return u.client.DeleteUser(ctx, username)
}
