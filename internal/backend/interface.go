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

	// DeleteUser deletes a user and all associated resources (access keys, policies, etc.)
	DeleteUser(ctx context.Context, username string) error
}
