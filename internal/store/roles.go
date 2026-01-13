package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
)

// Role represents a role definition with associated policies
type Role struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Policies    []string `json:"policies"` // List of policy names
}

// RoleStore manages role definitions
type RoleStore struct {
	dataDir string
	roles   map[string]*Role
	mu      sync.RWMutex
	logger  *logrus.Logger
}

// NewRoleStore creates a new role store
func NewRoleStore(dataDir string, logger *logrus.Logger) (*RoleStore, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create roles directory: %w", err)
	}

	store := &RoleStore{
		dataDir: dataDir,
		roles:   make(map[string]*Role),
		logger:  logger,
	}

	// Load existing roles
	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}

	return store, nil
}

// load reads all role files from the data directory
func (s *RoleStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.WithField("dir", s.dataDir).Info("Roles directory does not exist yet")
			return nil
		}
		return fmt.Errorf("failed to read roles directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(s.dataDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to read role file")
			continue
		}

		var role Role
		if err := json.Unmarshal(data, &role); err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to parse role file")
			continue
		}

		s.roles[role.Name] = &role
		s.logger.WithField("role", role.Name).Debug("Loaded role")
	}

	s.logger.WithField("count", len(s.roles)).Info("Roles loaded")
	return nil
}

// save writes a role to disk
func (s *RoleStore) save(role *Role) error {
	filePath := filepath.Join(s.dataDir, role.Name+".json")
	data, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write role file: %w", err)
	}

	return nil
}

// Create adds a new role
func (s *RoleStore) Create(role *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.Name]; exists {
		return fmt.Errorf("role %s already exists", role.Name)
	}

	if err := s.save(role); err != nil {
		return err
	}

	s.roles[role.Name] = role
	s.logger.WithField("role", role.Name).Info("Role created")
	return nil
}

// Update modifies an existing role
func (s *RoleStore) Update(role *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.Name]; !exists {
		return fmt.Errorf("role %s not found", role.Name)
	}

	if err := s.save(role); err != nil {
		return err
	}

	s.roles[role.Name] = role
	s.logger.WithField("role", role.Name).Info("Role updated")
	return nil
}

// Delete removes a role
func (s *RoleStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[name]; !exists {
		return fmt.Errorf("role %s not found", name)
	}

	filePath := filepath.Join(s.dataDir, name+".json")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete role file: %w", err)
	}

	delete(s.roles, name)
	s.logger.WithField("role", name).Info("Role deleted")
	return nil
}

// Get retrieves a role by name
func (s *RoleStore) Get(name string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[name]
	if !exists {
		return nil, fmt.Errorf("role %s not found", name)
	}

	return role, nil
}

// List returns all roles
func (s *RoleStore) List() []*Role {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles := make([]*Role, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}

	return roles
}

// GetPoliciesForRoles returns all unique policies for the given role names
func (s *RoleStore) GetPoliciesForRoles(roleNames []string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policySet := make(map[string]bool)
	for _, roleName := range roleNames {
		if role, exists := s.roles[roleName]; exists {
			for _, policy := range role.Policies {
				policySet[policy] = true
			}
		}
	}

	policies := make([]string, 0, len(policySet))
	for policy := range policySet {
		policies = append(policies, policy)
	}

	return policies
}

// GetRoleNames returns all role names
func (s *RoleStore) GetRoleNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.roles))
	for name := range s.roles {
		names = append(names, name)
	}

	return names
}
