package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Credential represents a user's S3 credential
type Credential struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	Name         string                 `json:"name"`
	AccessKey    string                 `json:"access_key"`
	SecretKey    string                 `json:"secret_key"`
	SessionToken string                 `json:"session_token,omitempty"` // For temporary STS credentials
	RoleName     string                 `json:"role_name,omitempty"`     // IAM role name used for STS credentials
	Groups       []string               `json:"groups,omitempty"`        // User-selected groups
	BackendData  map[string]interface{} `json:"backend_data,omitempty"`  // Backend-specific data (e.g., policy ARN for AWS)
	CreatedAt    time.Time              `json:"created_at"`
	LastUsedAt   time.Time              `json:"last_used_at,omitempty"`
	Description  string                 `json:"description,omitempty"`
}

// CredentialStore manages user credentials
type CredentialStore struct {
	credentials map[string]*Credential // accessKey -> credential
	userIndex   map[string][]string    // userID -> []accessKey
	mu          sync.RWMutex
	storePath   string
	logger      *logrus.Logger
}

// NewCredentialStore creates a new credential store
func NewCredentialStore(storePath string, logger *logrus.Logger) (*CredentialStore, error) {
	store := &CredentialStore{
		credentials: make(map[string]*Credential),
		userIndex:   make(map[string][]string),
		storePath:   storePath,
		logger:      logger,
	}

	// Load existing credentials from disk
	if err := store.Load(); err != nil {
		logger.WithError(err).Warn("Failed to load credentials, starting fresh")
	}

	return store, nil
}

// Create creates a new credential for a user
func (s *CredentialStore) Create(userID, name, description string, groups []string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate access key and secret key
	accessKey, err := generateKey("AK", 20)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access key: %w", err)
	}

	secretKey, err := generateKey("SK", 40)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret key: %w", err)
	}

	return s.createCredential(userID, name, description, groups, accessKey, secretKey, "", "", nil)
}

// CreateWithKeys creates a new credential with provided access/secret keys (for IAM integration)
func (s *CredentialStore) CreateWithKeys(userID, name, description string, groups []string, accessKey, secretKey, sessionToken, roleName string, backendData map[string]interface{}) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.createCredential(userID, name, description, groups, accessKey, secretKey, sessionToken, roleName, backendData)
}

// generateID generates a unique ID
func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fall back to timestamp-based ID if random generation fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// createCredential is the internal method to create a credential (caller must hold lock)
func (s *CredentialStore) createCredential(userID, name, description string, groups []string, accessKey, secretKey, sessionToken, roleName string, backendData map[string]interface{}) (*Credential, error) {
	// Create credential
	cred := &Credential{
		ID:           generateID(),
		UserID:       userID,
		Name:         name,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		RoleName:     roleName,
		Groups:       groups,
		BackendData:  backendData,
		CreatedAt:    time.Now(),
		Description:  description,
	}

	// Store credential
	s.credentials[accessKey] = cred

	// Update user index
	if s.userIndex[userID] == nil {
		s.userIndex[userID] = []string{}
	}
	s.userIndex[userID] = append(s.userIndex[userID], accessKey)

	// Persist to disk
	if err := s.save(); err != nil {
		s.logger.WithError(err).Error("Failed to persist credentials")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"access_key": accessKey,
		"name":       name,
	}).Info("Created credential")

	return cred, nil
}

// Get retrieves a credential by access key
func (s *CredentialStore) Get(accessKey string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, exists := s.credentials[accessKey]
	if !exists {
		return nil, fmt.Errorf("credential not found")
	}

	return cred, nil
}

// GetByAccessKey is an alias for Get (retrieves credential by access key)
func (s *CredentialStore) GetByAccessKey(accessKey string) *Credential {
	cred, _ := s.Get(accessKey)
	return cred
}

// ListByUser lists all credentials for a user
func (s *CredentialStore) ListByUser(userID string) ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessKeys, exists := s.userIndex[userID]
	if !exists {
		return []*Credential{}, nil
	}

	credentials := make([]*Credential, 0, len(accessKeys))
	for _, key := range accessKeys {
		if cred, exists := s.credentials[key]; exists {
			credentials = append(credentials, cred)
		}
	}

	return credentials, nil
}

// ListByGroups lists all credentials that use any of the specified groups
func (s *CredentialStore) ListByGroups(groupNames []string) ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groupSet := make(map[string]bool)
	for _, group := range groupNames {
		groupSet[group] = true
	}

	var credentials []*Credential
	for _, cred := range s.credentials {
		// Check if credential uses any of the specified groups
		for _, credGroup := range cred.Groups {
			if groupSet[credGroup] {
				credentials = append(credentials, cred)
				break
			}
		}
	}

	return credentials, nil
}

// ListAll lists all credentials in the store
func (s *CredentialStore) ListAll() ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var credentials []*Credential
	for _, cred := range s.credentials {
		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// Delete deletes a credential
func (s *CredentialStore) Delete(accessKey, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify credential exists and belongs to user
	cred, exists := s.credentials[accessKey]
	if !exists {
		return fmt.Errorf("credential not found")
	}

	if cred.UserID != userID {
		return fmt.Errorf("permission denied")
	}

	// Delete from credentials map
	delete(s.credentials, accessKey)

	// Remove from user index
	if keys, exists := s.userIndex[userID]; exists {
		newKeys := make([]string, 0, len(keys)-1)
		for _, k := range keys {
			if k != accessKey {
				newKeys = append(newKeys, k)
			}
		}
		s.userIndex[userID] = newKeys
	}

	// Persist to disk
	if err := s.save(); err != nil {
		s.logger.WithError(err).Error("Failed to persist credentials")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"access_key": accessKey,
	}).Info("Deleted credential")

	return nil
}

// UpdateLastUsed updates the last used timestamp for a credential
func (s *CredentialStore) UpdateLastUsed(accessKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.credentials[accessKey]
	if !exists {
		return fmt.Errorf("credential not found")
	}

	cred.LastUsedAt = time.Now()

	// Persist periodically (not on every use to avoid disk thrashing)
	// You might want to implement batching or periodic saves
	return nil
}

// UpdateGroups updates the groups for a credential
func (s *CredentialStore) UpdateGroups(accessKey string, groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.credentials[accessKey]
	if !exists {
		return fmt.Errorf("credential not found")
	}

	cred.Groups = groups
	return s.save()
}

// UpdateBackendData updates the backend data for a credential
func (s *CredentialStore) UpdateBackendData(accessKey string, backendData map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.credentials[accessKey]
	if !exists {
		return fmt.Errorf("credential not found")
	}

	cred.BackendData = backendData
	return s.save()
}

// Validate checks if a credential is valid and returns associated policies
func (s *CredentialStore) Validate(accessKey, secretKey string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, exists := s.credentials[accessKey]
	if !exists {
		return nil, fmt.Errorf("invalid credentials")
	}

	if cred.SecretKey != secretKey {
		return nil, fmt.Errorf("invalid credentials")
	}

	return cred, nil
}

// CredentialExists checks if a credential with the given name exists for a user
func (s *CredentialStore) CredentialExists(userID, name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessKeys, exists := s.userIndex[userID]
	if !exists {
		return false
	}

	for _, accessKey := range accessKeys {
		if cred, exists := s.credentials[accessKey]; exists && cred.Name == name {
			return true
		}
	}

	return false
}

// Load loads credentials from disk
func (s *CredentialStore) Load() error {
	if s.storePath == "" {
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(s.storePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(s.storePath)
	if err != nil {
		return fmt.Errorf("failed to read credentials file: %w", err)
	}

	var credentials []*Credential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	// Rebuild indexes
	s.credentials = make(map[string]*Credential)
	s.userIndex = make(map[string][]string)

	for _, cred := range credentials {
		s.credentials[cred.AccessKey] = cred

		if _, exists := s.userIndex[cred.UserID]; !exists {
			s.userIndex[cred.UserID] = []string{}
		}
		s.userIndex[cred.UserID] = append(s.userIndex[cred.UserID], cred.AccessKey)
	}

	s.logger.WithField("count", len(credentials)).Info("Loaded credentials from disk")
	return nil
}

// save persists credentials to disk
func (s *CredentialStore) save() error {
	if s.storePath == "" {
		return nil
	}

	// Convert to slice
	credentials := make([]*Credential, 0, len(s.credentials))
	for _, cred := range s.credentials {
		credentials = append(credentials, cred)
	}

	data, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(s.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(s.storePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	return nil
}

// generateKey generates a random key with a prefix
func generateKey(prefix string, length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(bytes)
	// Truncate to desired length
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return prefix + encoded, nil
}

// DeleteCredential removes a credential by name for a specific user
func (s *CredentialStore) DeleteCredential(credentialName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the credential by name
	var accessKeyToDelete string
	var found bool
	for accessKey, cred := range s.credentials {
		if cred.Name == credentialName {
			accessKeyToDelete = accessKey
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("credential not found")
	}

	// Remove from credentials map
	delete(s.credentials, accessKeyToDelete)

	// Remove from user index
	if accessKeys, exists := s.userIndex[s.credentials[accessKeyToDelete].UserID]; exists {
		for i, key := range accessKeys {
			if key == accessKeyToDelete {
				s.userIndex[s.credentials[accessKeyToDelete].UserID] = append(accessKeys[:i], accessKeys[i+1:]...)
				break
			}
		}
		// Remove user entry if no credentials left
		if len(s.userIndex[s.credentials[accessKeyToDelete].UserID]) == 0 {
			delete(s.userIndex, s.credentials[accessKeyToDelete].UserID)
		}
	}

	return s.save()
}
