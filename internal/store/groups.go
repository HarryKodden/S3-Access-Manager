package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Group represents a group definition with associated policies
type Group struct {
	Name        string   `json:"name,omitempty"` // IAM group name (derived from SCIM display name)
	Description string   `json:"description"`
	Policies    []string `json:"policies"` // List of policy names
	ScimGroupId string   `json:"-"`        // SCIM group ID (derived from filename)
}

// GroupStore manages group definitions
type GroupStore struct {
	dataDir string
	groups  map[string]*Group
	mu      sync.RWMutex
	logger  *logrus.Logger
}

// NewGroupStore creates a new group store
func NewGroupStore(dataDir string, logger *logrus.Logger) (*GroupStore, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create groups directory: %w", err)
	}

	store := &GroupStore{
		dataDir: dataDir,
		groups:  make(map[string]*Group),
		logger:  logger,
	}

	// Load existing groups
	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load groups: %w", err)
	}

	return store, nil
}

// load reads all group files from the data directory
func (s *GroupStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.WithField("dir", s.dataDir).Info("Groups directory does not exist yet")
			return nil
		}
		return fmt.Errorf("failed to read groups directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(s.dataDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to read group file")
			continue
		}

		var group Group
		if err := json.Unmarshal(data, &group); err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to parse group file")
			continue
		}

		// Derive SCIM group ID from filename
		scimGroupId := strings.TrimSuffix(entry.Name(), ".json")
		group.ScimGroupId = scimGroupId

		s.groups[scimGroupId] = &group
		s.logger.WithFields(logrus.Fields{
			"scimGroupId": scimGroupId,
			"name":        group.Name,
		}).Debug("Loaded group")
	}

	s.logger.WithField("count", len(s.groups)).Info("Groups loaded")
	return nil
}

// save writes a group to disk
func (s *GroupStore) save(group *Group) error {
	filename := group.Name + ".json"
	if group.ScimGroupId != "" {
		filename = group.ScimGroupId + ".json"
	}
	filePath := filepath.Join(s.dataDir, filename)
	data, err := json.MarshalIndent(group, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal group: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write group file: %w", err)
	}

	return nil
}

// Create adds a new group
func (s *GroupStore) Create(group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[group.ScimGroupId]; exists {
		return fmt.Errorf("group %s already exists", group.ScimGroupId)
	}

	if err := s.save(group); err != nil {
		return err
	}

	s.groups[group.ScimGroupId] = group
	s.logger.WithField("group", group.ScimGroupId).Info("Group created")
	return nil
}

// Update modifies an existing group
func (s *GroupStore) Update(group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[group.ScimGroupId]; !exists {
		return fmt.Errorf("group %s not found", group.ScimGroupId)
	}

	if err := s.save(group); err != nil {
		return err
	}

	s.groups[group.ScimGroupId] = group
	s.logger.WithField("group", group.ScimGroupId).Info("Group updated")
	return nil
}

// Delete removes a group
func (s *GroupStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[name]; !exists {
		return fmt.Errorf("group %s not found", name)
	}

	filePath := filepath.Join(s.dataDir, name+".json")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete group file: %w", err)
	}

	delete(s.groups, name)
	s.logger.WithField("group", name).Info("Group deleted")
	return nil
}

// Get retrieves a group by name
func (s *GroupStore) Get(name string) (*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	group, exists := s.groups[name]
	if !exists {
		return nil, fmt.Errorf("group %s not found", name)
	}

	return group, nil
}

// List returns all groups
func (s *GroupStore) List() []*Group {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make([]*Group, 0, len(s.groups))
	for _, group := range s.groups {
		groups = append(groups, group)
	}

	return groups
}

// GetPoliciesForGroups returns all unique policies for the given group names
func (s *GroupStore) GetPoliciesForGroups(groupNames []string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policySet := make(map[string]bool)
	for _, groupName := range groupNames {
		// First try to find group by SCIM ID (primary key)
		if group, exists := s.groups[groupName]; exists {
			for _, policy := range group.Policies {
				policySet[policy] = true
			}
			continue
		}

		// Fallback: find group by display name
		for _, group := range s.groups {
			if group.Name == groupName {
				for _, policy := range group.Policies {
					policySet[policy] = true
				}
				break
			}
		}
	}

	policies := make([]string, 0, len(policySet))
	for policy := range policySet {
		policies = append(policies, policy)
	}

	return policies
}

// GetGroupNames returns all group names
func (s *GroupStore) GetGroupNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.groups))
	for _, group := range s.groups {
		names = append(names, group.Name)
	}

	return names
}

// GetGroupsUsingPolicy returns all groups that use a specific policy
func (s *GroupStore) GetGroupsUsingPolicy(policyName string) []*Group {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make([]*Group, 0)
	for _, group := range s.groups {
		for _, policy := range group.Policies {
			if policy == policyName {
				groups = append(groups, group)
				break
			}
		}
	}

	return groups
}
