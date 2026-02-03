package backend

import "context"

// CredentialInfo represents backend credential information
type CredentialInfo struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	BackendData  map[string]interface{}
}

// AdminClient defines the interface for backend admin operations
// Each backend (CEPH, AWS, MinIO) implements this interface
type AdminClient interface {
	// CreateUser creates a new user in the backend (if needed)
	// For CEPH: creates main RadosGW user
	// For AWS: creates IAM user
	// For MinIO: creates MinIO user
	CreateUser(email, displayName string) error

	// CreateCredential creates a new credential for the user
	// For CEPH: creates sub-user with access keys
	// For AWS: creates IAM access key and attaches combined policy
	// For MinIO: creates service account with combined policy
	// policyDoc is the combined IAM policy document for the credential
	CreateCredential(email, credentialName string, policyDoc map[string]interface{}) (CredentialInfo, error)

	// UpdateCredential updates an existing credential's policy
	// For CEPH: updates sub-user permissions
	// For AWS: updates IAM policy attached to access key
	// For MinIO: updates service account policy
	// backendData contains backend-specific information from credential creation
	// Returns updated backendData that should be stored in the credential
	UpdateCredential(email, credentialName string, policyDoc map[string]interface{}, backendData map[string]interface{}) (map[string]interface{}, error)

	// DeleteCredential deletes a credential
	// For CEPH: deletes sub-user
	// For AWS: deletes IAM access key and detaches/deletes policy
	// For MinIO: deletes service account
	// backendData contains backend-specific information (e.g., policy ARN for AWS)
	DeleteCredential(email, credentialName string, backendData map[string]interface{}) error

	// GetBackendType returns the backend type name
	GetBackendType() string
}

// UserManager defines the interface for user management operations
type UserManager interface {
	// ListUsers lists all users in the backend
	ListUsers(ctx context.Context) ([]string, error)

	// GetUserDetails returns detailed information about a specific user
	GetUserDetails(ctx context.Context, username string) (UserDetails, error)

	// DeleteUser deletes a user and all associated resources (access keys, policies, etc.)
	DeleteUser(ctx context.Context, username string) error
}

// UserDetails contains comprehensive information about a user
type UserDetails struct {
	Username    string           `json:"username"`
	CreateDate  string           `json:"create_date,omitempty"`
	Groups      []string         `json:"groups"`
	Policies    []UserPolicy     `json:"policies"`
	AccessKeys  []AccessKeyInfo  `json:"access_keys"`
	ScimDetails *ScimUserDetails `json:"scim_details,omitempty"`
}

// UserPolicy represents a policy attached to a user
type UserPolicy struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "Managed" or "Inline"
	Document string `json:"document,omitempty"`
}

// AccessKeyInfo represents access key information
type AccessKeyInfo struct {
	AccessKeyId string `json:"access_key_id"`
	Status      string `json:"status"`
	CreateDate  string `json:"create_date"`
}

// ScimUserDetails contains SCIM-specific user information
type ScimUserDetails struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Groups      []string `json:"groups"`
}
