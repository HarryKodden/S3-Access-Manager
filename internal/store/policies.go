package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
)

// PolicyDocument represents a complete policy document
type PolicyDocument struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Policy      map[string]interface{} `json:"policy"`
}

// PolicyStore manages S3 policies
type PolicyStore struct {
	policies map[string]*PolicyDocument // policyName -> policy
	mu       sync.RWMutex
	dataPath string // Directory where policies are persisted as individual files
	logger   *logrus.Logger
}

// NewPolicyStore creates a new policy store
func NewPolicyStore(dataPath string, logger *logrus.Logger) (*PolicyStore, error) {
	store := &PolicyStore{
		policies: make(map[string]*PolicyDocument),
		dataPath: dataPath,
		logger:   logger,
	}

	// Ensure directory exists
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create policies directory: %w", err)
	}

	// Load existing policies from directory
	if err := store.Load(); err != nil {
		logger.WithError(err).Warn("Failed to load policies, starting fresh")
	}

	return store, nil
}

// Load loads all policy files from the data directory
func (s *PolicyStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dataPath)
	if err != nil {
		return fmt.Errorf("failed to read policies directory: %w", err)
	}

	s.policies = make(map[string]*PolicyDocument)

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		policyName := entry.Name()[:len(entry.Name())-5] // Remove .json extension
		policyPath := filepath.Join(s.dataPath, entry.Name())

		data, err := os.ReadFile(policyPath)
		if err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Error("Failed to read policy file")
			continue
		}

		var policyContent map[string]interface{}
		if err := json.Unmarshal(data, &policyContent); err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Error("Failed to parse policy JSON")
			continue
		}

		s.policies[policyName] = &PolicyDocument{
			Name:   policyName,
			Policy: policyContent,
		}

		s.logger.WithField("policy", policyName).Info("Loaded policy from file")
	}

	s.logger.WithField("count", len(s.policies)).Info("Policies loaded from disk")
	return nil
}

// List returns all policies
func (s *PolicyStore) List() ([]*PolicyDocument, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policies := make([]*PolicyDocument, 0, len(s.policies))
	for _, policy := range s.policies {
		policies = append(policies, policy)
	}

	return policies, nil
}

// GetPolicyNames returns the names of all policies in the store
func (s *PolicyStore) GetPolicyNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.policies))
	for name := range s.policies {
		names = append(names, name)
	}
	return names
}

// Get retrieves a policy by name
func (s *PolicyStore) Get(name string) (*PolicyDocument, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policy, exists := s.policies[name]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", name)
	}

	return policy, nil
}

// Create creates a new policy
func (s *PolicyStore) Create(name, description string, policyContent map[string]interface{}) (*PolicyDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if policy already exists
	if _, exists := s.policies[name]; exists {
		return nil, fmt.Errorf("policy already exists: %s", name)
	}

	// Validate policy JSON structure
	if err := ValidatePolicyJSON(policyContent); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	policy := &PolicyDocument{
		Name:        name,
		Description: description,
		Policy:      policyContent,
	}

	// Save to memory
	s.policies[name] = policy

	// Persist to disk
	if err := s.savePolicyFile(name, policyContent); err != nil {
		delete(s.policies, name) // Rollback
		return nil, fmt.Errorf("failed to persist policy: %w", err)
	}

	s.logger.WithField("policy", name).Info("Created policy")
	return policy, nil
}

// Update updates an existing policy
func (s *PolicyStore) Update(name, description string, policyContent map[string]interface{}) (*PolicyDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if policy exists
	oldPolicy, exists := s.policies[name]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", name)
	}

	// Validate policy JSON structure
	if err := ValidatePolicyJSON(policyContent); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	policy := &PolicyDocument{
		Name:        name,
		Description: description,
		Policy:      policyContent,
	}

	// Save to memory
	s.policies[name] = policy

	// Persist to disk
	if err := s.savePolicyFile(name, policyContent); err != nil {
		s.policies[name] = oldPolicy // Rollback
		return nil, fmt.Errorf("failed to persist policy: %w", err)
	}

	s.logger.WithField("policy", name).Info("Updated policy")
	return policy, nil
}

// Delete deletes a policy
func (s *PolicyStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if policy exists
	if _, exists := s.policies[name]; !exists {
		return fmt.Errorf("policy not found: %s", name)
	}

	// Delete from memory
	delete(s.policies, name)

	// Delete file
	policyPath := filepath.Join(s.dataPath, name+".json")
	if err := os.Remove(policyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete policy file: %w", err)
	}

	s.logger.WithField("policy", name).Info("Deleted policy")
	return nil
}

// savePolicyFile saves a policy to a file
func (s *PolicyStore) savePolicyFile(name string, policyContent map[string]interface{}) error {
	policyPath := filepath.Join(s.dataPath, name+".json")

	data, err := json.MarshalIndent(policyContent, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(policyPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	return nil
}

// ValidatePolicyJSON validates the structure of a policy document
func ValidatePolicyJSON(policy map[string]interface{}) error {
	// Check for required fields
	version, hasVersion := policy["Version"]
	if !hasVersion {
		return fmt.Errorf("missing required field: Version")
	}

	if versionStr, ok := version.(string); !ok || versionStr == "" {
		return fmt.Errorf("version must be a non-empty string")
	}

	statements, hasStatements := policy["Statement"]
	if !hasStatements {
		return fmt.Errorf("missing required field: Statement")
	}

	statementsArray, ok := statements.([]interface{})
	if !ok {
		return fmt.Errorf("statement must be an array")
	}

	if len(statementsArray) == 0 {
		return fmt.Errorf("statement array cannot be empty")
	}

	// Validate each statement
	for i, stmt := range statementsArray {
		stmtMap, ok := stmt.(map[string]interface{})
		if !ok {
			return fmt.Errorf("statement[%d] must be an object", i)
		}

		// Check Effect
		effect, hasEffect := stmtMap["Effect"]
		if !hasEffect {
			return fmt.Errorf("statement[%d] missing required field: Effect", i)
		}
		effectStr, ok := effect.(string)
		if !ok {
			return fmt.Errorf("statement[%d] Effect must be a string", i)
		}
		if effectStr != "Allow" && effectStr != "Deny" {
			return fmt.Errorf("statement[%d] Effect must be 'Allow' or 'Deny'", i)
		}

		// Check Action
		if _, hasAction := stmtMap["Action"]; !hasAction {
			return fmt.Errorf("statement[%d] missing required field: Action", i)
		}

		// Validate actions are S3-only
		if err := validateS3OnlyActions(stmtMap["Action"], i); err != nil {
			return err
		}

		// Check Resource
		if _, hasResource := stmtMap["Resource"]; !hasResource {
			return fmt.Errorf("statement[%d] missing required field: Resource", i)
		}
	}

	return nil
}

// validateS3OnlyActions ensures all actions are S3-related (not IAM, EC2, etc.)
func validateS3OnlyActions(actions interface{}, statementIndex int) error {
	var actionList []string

	// Handle both string and array of strings
	switch v := actions.(type) {
	case string:
		actionList = []string{v}
	case []interface{}:
		for _, action := range v {
			if actionStr, ok := action.(string); ok {
				actionList = append(actionList, actionStr)
			} else {
				return fmt.Errorf("statement[%d] Action must be string or array of strings", statementIndex)
			}
		}
	default:
		return fmt.Errorf("statement[%d] Action must be string or array of strings", statementIndex)
	}

	// Check each action
	for _, action := range actionList {
		// Allow wildcards for S3
		if action == "s3:*" {
			continue
		}

		// Check if action starts with "s3:"
		if len(action) < 3 || action[:3] != "s3:" {
			return fmt.Errorf("statement[%d] contains non-S3 action '%s'. Only S3 actions (s3:*) are allowed. IAM, EC2, and other service actions are not permitted", statementIndex, action)
		}
	}

	return nil
}
