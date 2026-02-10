package sram

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateCollaboration(t *testing.T) {
	// Mock SRAM API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/collaborations/v1" {
			t.Errorf("Expected path /api/collaborations/v1, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("Expected Authorization header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Parse request body
		var req CollaborationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		// Verify request data
		if req.Name == "" {
			t.Error("Expected name in request")
		}
		if req.ShortName == "" {
			t.Error("Expected short_name in request")
		}
		if len(req.Administrators) == 0 {
			t.Error("Expected administrators in request")
		}

		// Send response
		response := CollaborationResponse{
			ID:          FlexibleString("collab-123"),
			Name:        req.Name,
			ShortName:   req.ShortName,
			Description: req.Description,
			CreatedAt:   FlexibleTime{Time: time.Now()},
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-api-key")

	// Test collaboration creation
	req := CollaborationRequest{
		Name:           "Test Collaboration",
		ShortName:      "test-collab",
		Description:    "Test collaboration for unit testing",
		Administrators: []string{"admin@example.com"},
	}

	resp, err := client.CreateCollaboration(req)
	if err != nil {
		t.Fatalf("CreateCollaboration failed: %v", err)
	}

	// Verify response
	if resp.ID != "collab-123" {
		t.Errorf("Expected ID collab-123, got %s", resp.ID)
	}
	if resp.Name != req.Name {
		t.Errorf("Expected name %s, got %s", req.Name, resp.Name)
	}
	if resp.ShortName != req.ShortName {
		t.Errorf("Expected short_name %s, got %s", req.ShortName, resp.ShortName)
	}
}

func TestSendInvitation(t *testing.T) {
	// Mock SRAM API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "PUT" {
			t.Errorf("Expected PUT request, got %s", r.Method)
		}
		if r.URL.Path != "/api/invitations/v1/collaboration_invites" {
			t.Errorf("Expected path /api/invitations/v1/collaboration_invites, got %s", r.URL.Path)
		}

		// Parse request body
		var req InvitationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		// Verify request data
		if req.CollaborationIdentifier == "" {
			t.Error("Expected collaboration_identifier in request")
		}
		if len(req.Invites) == 0 {
			t.Error("Expected invites in request")
		}
		if req.IntendedRole == "" {
			t.Error("Expected intended_role in request")
		}

		// Send response (one invitation per invitee)
		var responses []*InvitationResponse
		for _, email := range req.Invites {
			responses = append(responses, &InvitationResponse{
				Email:                email,
				InvitationExpiryDate: req.InvitationExpiryDate,
				InvitationID:         "invite-" + email,
				Status:               "open",
			})
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(responses)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-api-key")

	// Test invitation sending
	req := InvitationRequest{
		ShortName:               "test-collab",
		CollaborationIdentifier: "collab-123-uuid",
		Message:                 "Welcome to the collaboration",
		IntendedRole:            "admin",
		SenderName:              "Test Organization",
		InvitationExpiryDate:    1743014227174,
		MembershipExpiryDate:    1743014227174,
		Invites: []string{
			"user1@example.com",
			"user2@example.com",
		},
		Groups: []string{},
	}

	resp, err := client.SendInvitation(req)
	if err != nil {
		t.Fatalf("SendInvitation failed: %v", err)
	}

	// Verify response
	if len(resp) != 2 {
		t.Errorf("Expected 2 invitations, got %d", len(resp))
	}
	for i, inv := range resp {
		if inv.Email != req.Invites[i] {
			t.Errorf("Expected email %s, got %s", req.Invites[i], inv.Email)
		}
		if inv.Status != "open" {
			t.Errorf("Expected status open, got %s", inv.Status)
		}
		if inv.InvitationID != "invite-"+req.Invites[i] {
			t.Errorf("Expected invitation_id %s, got %s", "invite-"+req.Invites[i], inv.InvitationID)
		}
		if inv.InvitationExpiryDate != req.InvitationExpiryDate {
			t.Errorf("Expected expiry date %d, got %d", req.InvitationExpiryDate, inv.InvitationExpiryDate)
		}
	}
}

func TestGetInvitationStatus(t *testing.T) {
	// Mock SRAM API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/invitations/v1/invite-123" {
			t.Errorf("Expected path /api/invitations/v1/invite-123, got %s", r.URL.Path)
		}

		// Send response
		response := InvitationStatusResponse{
			ID:     "invite-123",
			Email:  "user@example.com",
			Status: "accepted",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-api-key")

	// Test invitation status retrieval
	resp, err := client.GetInvitationStatus("invite-123")
	if err != nil {
		t.Fatalf("GetInvitationStatus failed: %v", err)
	}

	// Verify response
	if resp.ID != "invite-123" {
		t.Errorf("Expected ID invite-123, got %s", resp.ID)
	}
	if resp.Email != "user@example.com" {
		t.Errorf("Expected email user@example.com, got %s", resp.Email)
	}
	if resp.Status != "accepted" {
		t.Errorf("Expected status accepted, got %s", resp.Status)
	}
}

func TestGetCollaborationInvitations(t *testing.T) {
	// Mock SRAM API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/invitations/v1/invitations/collab-123" {
			t.Errorf("Expected path /api/invitations/v1/invitations/collab-123, got %s", r.URL.Path)
		}

		// Send response
		response := []*InvitationStatusResponse{
			{
				ID:     "invite-1",
				Email:  "user1@example.com",
				Status: "accepted",
			},
			{
				ID:     "invite-2",
				Email:  "user2@example.com",
				Status: "pending",
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-api-key")

	// Test collaboration invitations retrieval
	resp, err := client.GetCollaborationInvitations("collab-123")
	if err != nil {
		t.Fatalf("GetCollaborationInvitations failed: %v", err)
	}

	// Verify response
	if len(resp) != 2 {
		t.Errorf("Expected 2 invitations, got %d", len(resp))
	}
	if resp[0].Email != "user1@example.com" {
		t.Errorf("Expected email user1@example.com, got %s", resp[0].Email)
	}
	if resp[0].Status != "accepted" {
		t.Errorf("Expected status accepted, got %s", resp[0].Status)
	}
	if resp[1].Status != "pending" {
		t.Errorf("Expected status pending, got %s", resp[1].Status)
	}
}

func TestAPIErrors(t *testing.T) {
	// Mock SRAM API server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Unauthorized"}`))
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "invalid-api-key")

	// Test that errors are properly handled
	_, err := client.CreateCollaboration(CollaborationRequest{
		Name:      "Test",
		ShortName: "test",
	})
	if err == nil {
		t.Error("Expected error for unauthorized request")
	}
}

func TestConnectCollaborationToService(t *testing.T) {
	// Mock SRAM API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "PUT" {
			t.Errorf("Expected PUT request, got %s", r.Method)
		}
		if r.URL.Path != "/api/collaborations_services/v1/connect_collaboration_service/test-collab" {
			t.Errorf("Expected path /api/collaborations_services/v1/connect_collaboration_service/test-collab, got %s", r.URL.Path)
		}

		// Verify authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-api-key" {
			t.Errorf("Expected Bearer test-api-key, got %s", authHeader)
		}

		// Verify request body
		var req ServiceConnectionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}
		if req.ServiceEntityID != "test-service" {
			t.Errorf("Expected service_entity_id test-service, got %s", req.ServiceEntityID)
		}

		// Send response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-api-key")

	// Test connect to service
	err := client.ConnectCollaborationToService("test-collab", "test-service")
	if err != nil {
		t.Fatalf("ConnectCollaborationToService failed: %v", err)
	}
}

func TestIsCollaborationConnectedToService(t *testing.T) {
	// Create mock collaboration response with connected services
	collaboration := &CollaborationResponse{
		Services: []CollaborationService{
			{
				EntityID: "service-1",
				Name:     "Test Service 1",
			},
			{
				EntityID: "global-client",
				Name:     "Global Client Service",
			},
		},
	}

	// Create client
	client := NewClient("http://dummy-url", "test-api-key")

	// Test connected service
	isConnected, err := client.IsCollaborationConnectedToService(collaboration, "global-client")
	if err != nil {
		t.Fatalf("IsCollaborationConnectedToService failed: %v", err)
	}
	if !isConnected {
		t.Error("Expected collaboration to be connected to global-client")
	}

	// Test non-connected service
	isConnected, err = client.IsCollaborationConnectedToService(collaboration, "other-service")
	if err != nil {
		t.Fatalf("IsCollaborationConnectedToService failed: %v", err)
	}
	if isConnected {
		t.Error("Expected collaboration to NOT be connected to other-service")
	}

	// Test nil collaboration
	isConnected, err = client.IsCollaborationConnectedToService(nil, "global-client")
	if err != nil {
		t.Fatalf("IsCollaborationConnectedToService failed: %v", err)
	}
	if isConnected {
		t.Error("Expected nil collaboration to return false")
	}
}
