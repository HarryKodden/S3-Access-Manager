package awscli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

// GroupManager handles AWS IAM Group management operations via CLI
type GroupManager struct {
	client *Client
	logger *logrus.Logger
}

// NewGroupManager creates a new AWS CLI Group manager
func NewGroupManager(client *Client) *GroupManager {
	return &GroupManager{
		client: client,
		logger: client.logger,
	}
}

// ListGroups lists all IAM Groups
func (g *GroupManager) ListGroups(ctx context.Context) ([]string, error) {
	stdout, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "list-groups", "--output", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to run aws iam list-groups: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		Groups []struct {
			GroupName string `json:"GroupName"`
		} `json:"Groups"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse aws output: %w", err)
	}

	var groups []string
	for _, group := range result.Groups {
		groups = append(groups, group.GroupName)
	}

	return groups, nil
}

// CreateGroup creates an IAM Group
func (g *GroupManager) CreateGroup(ctx context.Context, groupName string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "create-group",
		"--group-name", groupName,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to create IAM group: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithField("group_name", groupName).Info("Created IAM group")
	return nil
}

// DeleteGroup deletes an IAM Group
func (g *GroupManager) DeleteGroup(ctx context.Context, groupName string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "delete-group",
		"--group-name", groupName,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to delete IAM group: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithField("group_name", groupName).Info("Deleted IAM group")
	return nil
}

// AddUserToGroup adds a user to a group
func (g *GroupManager) AddUserToGroup(ctx context.Context, groupName, userName string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "add-user-to-group",
		"--group-name", groupName,
		"--user-name", userName,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to add user to group: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithFields(logrus.Fields{
		"group_name": groupName,
		"user_name":  userName,
	}).Info("Added user to group")
	return nil
}

// RemoveUserFromGroup removes a user from a group
func (g *GroupManager) RemoveUserFromGroup(ctx context.Context, groupName, userName string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "remove-user-from-group",
		"--group-name", groupName,
		"--user-name", userName,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to remove user from group: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithFields(logrus.Fields{
		"group_name": groupName,
		"user_name":  userName,
	}).Info("Removed user from group")
	return nil
}

// AttachGroupPolicy attaches a managed policy to a group
func (g *GroupManager) AttachGroupPolicy(ctx context.Context, groupName, policyArn string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "attach-group-policy",
		"--group-name", groupName,
		"--policy-arn", policyArn,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to attach group policy: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithFields(logrus.Fields{
		"group_name": groupName,
		"policy_arn": policyArn,
	}).Info("Attached managed policy to group")
	return nil
}

// PutGroupPolicy attaches an inline policy to a group
func (g *GroupManager) PutGroupPolicy(ctx context.Context, groupName, policyName string, policyDoc map[string]interface{}) error {
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal policy document: %w", err)
	}

	tmpPolicyFile, err := os.CreateTemp("", "group-policy-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp policy file: %w", err)
	}
	defer os.Remove(tmpPolicyFile.Name())

	if _, err := tmpPolicyFile.Write(policyJSON); err != nil {
		return fmt.Errorf("failed to write policy: %w", err)
	}
	tmpPolicyFile.Close()

	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "put-group-policy",
		"--group-name", groupName,
		"--policy-name", policyName,
		"--policy-document", fmt.Sprintf("file://%s", tmpPolicyFile.Name()),
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to put group policy: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithFields(logrus.Fields{
		"group_name":  groupName,
		"policy_name": policyName,
	}).Info("Put inline policy on group")
	return nil
}

// DetachGroupPolicy detaches a managed policy from a group
func (g *GroupManager) DetachGroupPolicy(ctx context.Context, groupName, policyArn string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "detach-group-policy",
		"--group-name", groupName,
		"--policy-arn", policyArn,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to detach group policy: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithFields(logrus.Fields{
		"group_name": groupName,
		"policy_arn": policyArn,
	}).Info("Detached managed policy from group")
	return nil
}

// DeleteGroupPolicy deletes an inline policy from a group
func (g *GroupManager) DeleteGroupPolicy(ctx context.Context, groupName, policyName string) error {
	_, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "delete-group-policy",
		"--group-name", groupName,
		"--policy-name", policyName,
		"--output", "json",
	)
	if err != nil {
		return fmt.Errorf("failed to delete group policy: %w (stderr: %s)", err, string(stderr))
	}

	g.logger.WithFields(logrus.Fields{
		"group_name":  groupName,
		"policy_name": policyName,
	}).Info("Deleted inline policy from group")
	return nil
}

// GetGroupPolicy retrieves the inline policy document for a group
func (g *GroupManager) GetGroupPolicy(ctx context.Context, groupName, policyName string) (map[string]interface{}, error) {
	stdout, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "get-group-policy",
		"--group-name", groupName,
		"--policy-name", policyName,
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get group policy: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		PolicyDocument map[string]interface{} `json:"PolicyDocument"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %w", err)
	}

	return result.PolicyDocument, nil
}

// ListAttachedGroupPolicies lists managed policies attached to a group
func (g *GroupManager) ListAttachedGroupPolicies(ctx context.Context, groupName string) ([]string, error) {
	stdout, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "list-attached-group-policies",
		"--group-name", groupName,
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list attached group policies: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		AttachedPolicies []struct {
			PolicyArn string `json:"PolicyArn"`
		} `json:"AttachedPolicies"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse attached policies: %w", err)
	}

	var policies []string
	for _, policy := range result.AttachedPolicies {
		policies = append(policies, policy.PolicyArn)
	}

	return policies, nil
}

// ListGroupPolicies lists inline policies attached to a group
func (g *GroupManager) ListGroupPolicies(ctx context.Context, groupName string) ([]string, error) {
	stdout, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "list-group-policies",
		"--group-name", groupName,
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list group policies: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		PolicyNames []string `json:"PolicyNames"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse group policies: %w", err)
	}

	return result.PolicyNames, nil
}

// GetGroupUsers gets all users in a group
func (g *GroupManager) GetGroupUsers(ctx context.Context, groupName string) ([]string, error) {
	stdout, stderr, err := g.client.RunAwsCliCommand(g.logger, "iam", "get-group",
		"--group-name", groupName,
		"--output", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w (stderr: %s)", err, string(stderr))
	}

	var result struct {
		Users []struct {
			UserName string `json:"UserName"`
		} `json:"Users"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse group users: %w", err)
	}

	var users []string
	for _, user := range result.Users {
		users = append(users, user.UserName)
	}

	return users, nil
}
