package awscli

import (
	"context"

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

// DeleteUser deletes an IAM user and all associated resources
func (u *UserManager) DeleteUser(ctx context.Context, username string) error {
	return u.client.DeleteUser(ctx, username)
}
