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

// SCIMUser represents a SCIM user resource
type SCIMUser struct {
	Schemas     []string               `json:"schemas"`
	ID          string                 `json:"id"`
	UserName    string                 `json:"userName"`
	Active      bool                   `json:"active"`
	Name        *SCIMName              `json:"name,omitempty"`
	DisplayName string                 `json:"displayName,omitempty"`
	Emails      []SCIMEmail            `json:"emails,omitempty"`
	Groups      []SCIMGroupRef         `json:"groups,omitempty"`
	Meta        *SCIMMeta              `json:"meta,omitempty"`
	Extensions  map[string]interface{} `json:"-"` // For extension attributes
}

// SCIMName represents the name component in SCIM
type SCIMName struct {
	FamilyName string `json:"familyName"`
	GivenName  string `json:"givenName"`
}

// SCIMEmail represents an email in SCIM
type SCIMEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroupRef represents a group reference in SCIM
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// SCIMMeta represents metadata in SCIM
type SCIMMeta struct {
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	ResourceType string `json:"resourceType,omitempty"`
}

// SCIMGroup represents a SCIM group resource
type SCIMGroup struct {
	Schemas     []string               `json:"schemas"`
	ID          string                 `json:"id"`
	DisplayName string                 `json:"displayName"`
	Members     []SCIMGroupMember      `json:"members,omitempty"`
	Meta        *SCIMMeta              `json:"meta,omitempty"`
	Extensions  map[string]interface{} `json:"-"` // For extension attributes
}

// SCIMGroupMember represents a member in a SCIM group
type SCIMGroupMember struct {
	Value   string `json:"value"` // User ID
	Display string `json:"display,omitempty"`
}

// UserStore manages SCIM user and group data
type UserStore struct {
	userDataDir  string
	groupDataDir string
	users        map[string]*SCIMUser  // id -> user
	groups       map[string]*SCIMGroup // id -> group
	mu           sync.RWMutex
	logger       *logrus.Logger
}

// NewUserStore creates a new user store
func NewUserStore(userDataDir, groupDataDir string, logger *logrus.Logger) (*UserStore, error) {
	// Ensure user data directory exists
	if err := os.MkdirAll(userDataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create users directory: %w", err)
	}

	// Ensure group data directory exists
	if err := os.MkdirAll(groupDataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create groups directory: %w", err)
	}

	store := &UserStore{
		userDataDir:  userDataDir,
		groupDataDir: groupDataDir,
		users:        make(map[string]*SCIMUser),
		groups:       make(map[string]*SCIMGroup),
		logger:       logger,
	}

	// Load existing users and groups
	if err := store.loadUsers(); err != nil {
		return nil, fmt.Errorf("failed to load users: %w", err)
	}
	if err := store.loadGroups(); err != nil {
		return nil, fmt.Errorf("failed to load groups: %w", err)
	}

	return store, nil
}

// loadUsers reads all user files from the data directory
func (s *UserStore) loadUsers() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.userDataDir)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.WithField("dir", s.userDataDir).Info("Users directory does not exist yet")
			return nil
		}
		return fmt.Errorf("failed to read users directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(s.userDataDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to read user file")
			continue
		}

		var user SCIMUser
		if err := json.Unmarshal(data, &user); err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to parse user file")
			continue
		}

		s.users[user.ID] = &user
		s.logger.WithFields(logrus.Fields{
			"id":       user.ID,
			"userName": user.UserName,
		}).Debug("Loaded SCIM user")
	}

	s.logger.WithField("count", len(s.users)).Info("SCIM users loaded")
	return nil
}

// loadGroups reads all group files from the data directory
func (s *UserStore) loadGroups() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.groupDataDir)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.WithField("dir", s.groupDataDir).Info("Groups directory does not exist yet")
			return nil
		}
		return fmt.Errorf("failed to read groups directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(s.groupDataDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to read group file")
			continue
		}

		var rawGroup map[string]interface{}
		if err := json.Unmarshal(data, &rawGroup); err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to parse group file")
			continue
		}

		// Extract extensions
		extensions := make(map[string]interface{})
		for key, value := range rawGroup {
			if strings.HasPrefix(key, "urn:") {
				extensions[key] = value
				delete(rawGroup, key)
			}
		}

		// Marshal back without extensions
		cleanData, err := json.Marshal(rawGroup)
		if err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to marshal clean group data")
			continue
		}

		var group SCIMGroup
		if err := json.Unmarshal(cleanData, &group); err != nil {
			s.logger.WithError(err).WithField("file", entry.Name()).Warn("Failed to parse clean group file")
			continue
		}

		group.Extensions = extensions

		s.groups[group.ID] = &group
		s.logger.WithFields(logrus.Fields{
			"id":          group.ID,
			"displayName": group.DisplayName,
		}).Debug("Loaded SCIM group")
	}

	s.logger.WithField("count", len(s.groups)).Info("SCIM groups loaded")
	return nil
}

// GetUserByID retrieves a user by ID
func (s *UserStore) GetUserByID(id string) (*SCIMUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[id]
	return user, exists
}

// GetUserByUserName retrieves a user by userName
func (s *UserStore) GetUserByUserName(userName string) (*SCIMUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.UserName == userName {
			return user, true
		}
	}
	return nil, false
}

// GetAllUsers returns all users
func (s *UserStore) GetAllUsers() map[string]*SCIMUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to prevent external modification
	users := make(map[string]*SCIMUser)
	for k, v := range s.users {
		users[k] = v
	}
	return users
}

// GetAllGroups returns all groups
func (s *UserStore) GetAllGroups() map[string]*SCIMGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to prevent external modification
	groups := make(map[string]*SCIMGroup)
	for k, v := range s.groups {
		groups[k] = v
	}
	return groups
}

// GetGroupByID retrieves a group by ID
func (s *UserStore) GetGroupByID(id string) (*SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, exists := s.groups[id]
	return group, exists
}

// GetGroupByDisplayName retrieves a group by displayName
func (s *UserStore) GetGroupByDisplayName(displayName string) (*SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, group := range s.groups {
		if group.DisplayName == displayName {
			return group, true
		}
	}
	return nil, false
}

// IsUserActive checks if a user exists and is active
func (s *UserStore) IsUserActive(userName string) bool {
	user, exists := s.GetUserByUserName(userName)
	return exists && user.Active
}

// GetUserGroups returns the groups for a user
func (s *UserStore) GetUserGroups(userName string) []string {
	user, exists := s.GetUserByUserName(userName)
	if !exists {
		return nil
	}
	var groups []string
	for _, groupRef := range user.Groups {
		// Return the SCIM group ID directly
		groups = append(groups, groupRef.Value)
	}
	return groups
}
