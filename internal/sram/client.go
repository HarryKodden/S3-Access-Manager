package sram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

// FlexibleTime is a custom time type that can unmarshal from various formats
type FlexibleTime struct {
	time.Time
}

// UnmarshalJSON implements custom unmarshaling for FlexibleTime
func (ft *FlexibleTime) UnmarshalJSON(b []byte) error {
	// Try to unmarshal as RFC3339 string first
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		t, err := time.Parse(time.RFC3339, s)
		if err == nil {
			ft.Time = t
			return nil
		}
	}

	// Try to unmarshal as Unix timestamp (integer)
	var timestamp int64
	if err := json.Unmarshal(b, &timestamp); err == nil {
		ft.Time = time.Unix(timestamp, 0)
		return nil
	}

	// Try to unmarshal as Unix timestamp (string)
	if err := json.Unmarshal(b, &s); err == nil {
		if timestamp, err := strconv.ParseInt(s, 10, 64); err == nil {
			ft.Time = time.Unix(timestamp, 0)
			return nil
		}
	}

	return fmt.Errorf("unable to parse time from: %s", string(b))
}

// FlexibleString is a custom string type that can unmarshal from string or number
type FlexibleString string

// UnmarshalJSON implements custom unmarshaling for FlexibleString
func (fs *FlexibleString) UnmarshalJSON(b []byte) error {
	// Try to unmarshal as string first
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*fs = FlexibleString(s)
		return nil
	}

	// Try to unmarshal as integer
	var i int64
	if err := json.Unmarshal(b, &i); err == nil {
		*fs = FlexibleString(strconv.FormatInt(i, 10))
		return nil
	}

	// Try to unmarshal as float
	var f float64
	if err := json.Unmarshal(b, &f); err == nil {
		*fs = FlexibleString(strconv.FormatFloat(f, 'f', -1, 64))
		return nil
	}

	return fmt.Errorf("unable to parse string from: %s", string(b))
}

// String returns the string value
func (fs FlexibleString) String() string {
	return string(fs)
}

// Client represents a SRAM API client
type Client struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// CollaborationRequest represents a request to create a SRAM collaboration
type CollaborationRequest struct {
	Name                      string   `json:"name"`
	ShortName                 string   `json:"short_name"`
	Description               string   `json:"description"`
	DisableJoinRequests       bool     `json:"disable_join_requests"`
	DiscloseMemberInformation bool     `json:"disclose_member_information"`
	DiscloseEmailInformation  bool     `json:"disclose_email_information"`
	Administrators            []string `json:"administrators"` // Email addresses or UIDs
}

// CollaborationResponse represents a SRAM collaboration response
type CollaborationResponse struct {
	ID          FlexibleString            `json:"id"`
	Identifier  string                    `json:"identifier"`
	Name        string                    `json:"name"`
	ShortName   string                    `json:"short_name"`
	Description string                    `json:"description"`
	CreatedAt   FlexibleTime              `json:"created_at"`
	Memberships []CollaborationMembership `json:"collaboration_memberships,omitempty"`
	Groups      []CollaborationGroup      `json:"groups,omitempty"`
	Services    []CollaborationService    `json:"services,omitempty"`
	// Deprecated: Use Memberships instead (API returns collaboration_memberships)
	Members []CollaborationMember `json:"collaboration_members,omitempty"`
}

// CollaborationService represents a service connected to a collaboration
type CollaborationService struct {
	ID       FlexibleString `json:"id"`
	EntityID string         `json:"entity_id"` // This is what we need to check for connections
	Name     string         `json:"name"`
}

// CollaborationMembership represents a membership in a collaboration
type CollaborationMembership struct {
	ID              FlexibleString    `json:"id"`
	CollaborationID FlexibleString    `json:"collaboration_id"`
	UserID          FlexibleString    `json:"user_id"`
	Role            string            `json:"role"`
	Status          string            `json:"status"`
	User            CollaborationUser `json:"user"`
}

// CollaborationUser represents user details within a membership
type CollaborationUser struct {
	ID       FlexibleString `json:"id"`
	UID      string         `json:"uid"`
	Email    string         `json:"email"`
	Name     string         `json:"name"`
	Username string         `json:"username"`
}

// CollaborationGroup represents a group within a collaboration
type CollaborationGroup struct {
	ID                   FlexibleString `json:"id"`
	Identifier           string         `json:"identifier"`
	Name                 string         `json:"name"`
	ShortName            string         `json:"short_name"`
	Description          string         `json:"description"`
	GlobalURN            string         `json:"global_urn"`
	CollaborationID      FlexibleString `json:"collaboration_id"`
	AutoProvisionMembers bool           `json:"auto_provision_members"`
	CreatedAt            FlexibleTime   `json:"created_at"`
}

// CollaborationMember represents a member of a collaboration (deprecated structure)
type CollaborationMember struct {
	ID    FlexibleString `json:"id"`
	UID   string         `json:"uid"`
	Email string         `json:"email"`
	Name  string         `json:"name"`
	Role  string         `json:"role"`
}

// InvitationRequest represents a request to send an invitation
type InvitationRequest struct {
	ShortName               string   `json:"short_name"`               // Short name for the collaboration
	CollaborationIdentifier string   `json:"collaboration_identifier"` // Collaboration UUID identifier
	Message                 string   `json:"message"`                  // Invitation message
	IntendedRole            string   `json:"intended_role"`            // e.g., "admin", "member"
	SenderName              string   `json:"sender_name"`              // Name of the sender organization
	InvitationExpiryDate    int64    `json:"invitation_expiry_date"`   // Unix timestamp for invitation expiry
	MembershipExpiryDate    int64    `json:"membership_expiry_date"`   // Unix timestamp for membership expiry
	Invites                 []string `json:"invites"`                  // List of invitee emails
	Groups                  []string `json:"groups"`                   // List of group UUIDs
}

// InvitationResponse represents a SRAM invitation response
type InvitationResponse struct {
	Email                string `json:"email"`                  // Email address of the invitee
	InvitationExpiryDate int64  `json:"invitation_expiry_date"` // Expiry date in epoch seconds
	InvitationID         string `json:"invitation_id"`          // Unique external identifier (UUID)
	Status               string `json:"status"`                 // e.g., "open", "accepted", "declined"
}

// InvitationStatusResponse represents the status of an invitation
type InvitationStatusResponse struct {
	ID           FlexibleString `json:"id"`
	Email        string         `json:"email"`
	Status       string         `json:"status"`
	SRAMUsername string         `json:"sram_username,omitempty"` // SRAM username when invitation is accepted
}

// ServiceConnectionRequest represents a request to connect a collaboration to a service
type ServiceConnectionRequest struct {
	ServiceEntityID string `json:"service_entity_id"`
}

// ServiceConnection represents a connected service
type ServiceConnection struct {
	ServiceIdentifier string       `json:"service_identifier"`
	ServiceName       string       `json:"service_name,omitempty"`
	ConnectedAt       FlexibleTime `json:"connected_at,omitempty"`
}

// NewClient creates a new SRAM API client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// doRequest performs an HTTP request with debug logging
func (c *Client) doRequest(method, url string, body []byte, operation string) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewBuffer(body)
	}

	httpReq, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	// Log the complete request details
	log.Printf("[SRAM DEBUG] %s Request:", operation)
	log.Printf("[SRAM DEBUG]   URL: %s", url)
	log.Printf("[SRAM DEBUG]   Method: %s", method)
	log.Printf("[SRAM DEBUG]   Headers: %v", httpReq.Header)
	if body != nil {
		log.Printf("[SRAM DEBUG]   Body: %s", string(body))
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		log.Printf("[SRAM DEBUG] %s Request failed with error: %v", operation, err)
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	// Read response body
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for caller

	// Log the complete response details
	log.Printf("[SRAM DEBUG] %s Response:", operation)
	log.Printf("[SRAM DEBUG]   Status: %s", resp.Status)
	log.Printf("[SRAM DEBUG]   StatusCode: %d", resp.StatusCode)
	log.Printf("[SRAM DEBUG]   Headers: %v", resp.Header)
	log.Printf("[SRAM DEBUG]   Body: %s", string(bodyBytes))

	return resp, nil
}

// CreateCollaboration creates a new SRAM collaboration
func (c *Client) CreateCollaboration(req CollaborationRequest) (*CollaborationResponse, error) {
	url := fmt.Sprintf("%s/api/collaborations/v1", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest("POST", url, body, "CreateCollaboration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SRAM API returned status %d", resp.StatusCode)
	}

	var result CollaborationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetCollaboration retrieves details of a specific collaboration including groups and members
// If serviceIdentifier is provided and there are active admins but the service is not connected,
// it will automatically connect the service to the collaboration
func (c *Client) GetCollaboration(collaborationIdentifier string, serviceIdentifier ...string) (*CollaborationResponse, error) {
	url := fmt.Sprintf("%s/api/collaborations/v1/%s", c.baseURL, collaborationIdentifier)

	resp, err := c.doRequest("GET", url, nil, "GetCollaboration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SRAM API returned status %d", resp.StatusCode)
	}

	var result CollaborationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// If serviceIdentifier is provided, check if we need to connect the service
	if len(serviceIdentifier) > 0 {
		if serviceIdentifier[0] != "" {
			log.Printf("[SRAM] Auto-connecting service %s during collaboration lookup for %s", serviceIdentifier[0], collaborationIdentifier)
			if err := c.ensureServiceConnectionIfAdminsActive(&result, serviceIdentifier[0]); err != nil {
				// Log the error but don't fail the collaboration retrieval
				log.Printf("[SRAM] Warning: Failed to auto-connect service %s to collaboration %s: %v", serviceIdentifier[0], collaborationIdentifier, err)
			}
		} else {
			log.Printf("[SRAM] Service identifier provided but empty for collaboration %s, skipping auto-connection", collaborationIdentifier)
		}
	} else {
		log.Printf("[SRAM] No service identifier provided for collaboration %s, skipping auto-connection", collaborationIdentifier)
	}

	return &result, nil
}

// SendInvitation sends an invitation to join a collaboration
func (c *Client) SendInvitation(req InvitationRequest) ([]*InvitationResponse, error) {
	url := fmt.Sprintf("%s/api/invitations/v1/collaboration_invites", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest("PUT", url, body, "SendInvitation")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SRAM API returned status %d", resp.StatusCode)
	}

	var result []*InvitationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// GetInvitationStatus retrieves the status of an invitation
func (c *Client) GetInvitationStatus(invitationID string) (*InvitationStatusResponse, error) {
	url := fmt.Sprintf("%s/api/invitations/v1/%s", c.baseURL, invitationID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SRAM API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result InvitationStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetCollaborationInvitations retrieves all invitations for a collaboration
func (c *Client) GetCollaborationInvitations(collaborationID string) ([]*InvitationStatusResponse, error) {
	url := fmt.Sprintf("%s/api/invitations/v1/invitations/%s", c.baseURL, collaborationID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SRAM API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result []*InvitationStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// ConnectCollaborationToService connects a collaboration to a service
func (c *Client) ConnectCollaborationToService(collaborationIdentifier, serviceIdentifier string) error {
	log.Printf("[SRAM] Making API call to connect service %s to collaboration %s", serviceIdentifier, collaborationIdentifier)

	url := fmt.Sprintf("%s/api/collaborations_services/v1/connect_collaboration_service/%s", c.baseURL, collaborationIdentifier)

	req := ServiceConnectionRequest{
		ServiceEntityID: serviceIdentifier,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest("PUT", url, body, "ConnectCollaborationToService")
	if err != nil {
		log.Printf("[SRAM] API call failed for service connection: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("[SRAM] API call returned status %d for service connection", resp.StatusCode)
		return fmt.Errorf("SRAM API returned status %d", resp.StatusCode)
	}

	log.Printf("[SRAM] Service connection API call completed successfully")
	return nil
}

// IsCollaborationConnectedToService checks if a collaboration is already connected to a specific service
func (c *Client) IsCollaborationConnectedToService(collaboration *CollaborationResponse, serviceIdentifier string) (bool, error) {
	if collaboration == nil {
		return false, nil
	}

	for _, service := range collaboration.Services {
		if service.EntityID == serviceIdentifier {
			return true, nil
		}
	}

	return false, nil
}

// ensureServiceConnectionIfAdminsActive connects a service to a collaboration if active admins exist
// This is called automatically during GetCollaboration to ensure services are connected as early as possible
func (c *Client) ensureServiceConnectionIfAdminsActive(collaboration *CollaborationResponse, serviceIdentifier string) error {
	if collaboration == nil || serviceIdentifier == "" {
		return nil
	}

	log.Printf("[SRAM] Checking service connection for collaboration %s, service %s", collaboration.Identifier, serviceIdentifier)

	// Check if there are any active admins
	adminActive := false
	adminCount := 0
	for _, membership := range collaboration.Memberships {
		if membership.Role == "admin" && membership.Status == "active" {
			adminActive = true
			adminCount++
		}
	}

	log.Printf("[SRAM] Found %d active admin(s) in collaboration %s", adminCount, collaboration.Identifier)

	if !adminActive {
		log.Printf("[SRAM] No active admins found, skipping service connection for collaboration %s", collaboration.Identifier)
		return nil
	}

	// Check if the service is already connected
	isConnected := false
	for _, service := range collaboration.Services {
		if service.EntityID == serviceIdentifier {
			isConnected = true
			break
		}
	}

	if isConnected {
		log.Printf("[SRAM] Service %s already connected to collaboration %s", serviceIdentifier, collaboration.Identifier)
		return nil
	}

	log.Printf("[SRAM] Connecting service %s to collaboration %s (has %d active admins)", serviceIdentifier, collaboration.Identifier, adminCount)

	// Connect the service since we have active admins but service is not connected
	err := c.ConnectCollaborationToService(collaboration.Identifier, serviceIdentifier)
	if err != nil {
		log.Printf("[SRAM] Failed to connect service %s to collaboration %s: %v", serviceIdentifier, collaboration.Identifier, err)
		return err
	}

	log.Printf("[SRAM] Successfully connected service %s to collaboration %s", serviceIdentifier, collaboration.Identifier)
	return nil
}

// EnsureServiceConnectionIfAdminsActive connects a service to a collaboration if an active admin exists
func (c *Client) EnsureServiceConnectionIfAdminsActive(collaborationIdentifier string, collaboration *CollaborationResponse, serviceIdentifier string) error {
	if collaboration == nil || serviceIdentifier == "" {
		return nil
	}

	adminActive := false
	for _, membership := range collaboration.Memberships {
		if membership.Role == "admin" && membership.Status == "active" {
			adminActive = true
			break
		}
	}

	if !adminActive {
		return nil
	}

	isConnected, err := c.IsCollaborationConnectedToService(collaboration, serviceIdentifier)
	if err != nil {
		return err
	}

	if isConnected {
		return nil
	}

	return c.ConnectCollaborationToService(collaborationIdentifier, serviceIdentifier)
}

// DeleteCollaboration deletes a SRAM collaboration
func (c *Client) DeleteCollaboration(collaborationIdentifier string) error {
	url := fmt.Sprintf("%s/api/collaborations/v1/%s", c.baseURL, collaborationIdentifier)

	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SRAM API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
