# SRAM Service Connection Feature

## Overview

When a SRAM collaboration is created for a tenant, it is automatically connected to the configured OIDC service. This enables proper integration between the S3 Gateway and SRAM authentication.

## Implementation

### Configuration

The service identifier is taken from `oidc.client_id` in the configuration file:

```yaml
oidc:
  client_id: "global-client"  # Used as service identifier
```

### Automatic Connection

When a tenant is created with SRAM enabled, the gateway creates the collaboration but does NOT immediately connect it to the service. Service connection happens later during the admin sync process:

1. **Tenant Creation**: Creates SRAM collaboration (no service connection yet)
2. **Invitation Acceptance**: Tenant admins accept invitations 
3. **Admin Sync**: Global admin clicks "Sync Accepted Admins" 
4. **Service Connection**: Gateway connects collaboration to service (only if accepted admins exist)
5. **Logs the connection status**

This ensures the service is only connected after at least one tenant administrator has accepted their invitation.

### API Endpoints

#### Get Collaboration Services
```
GET /api/collaborations_services/v1/{collaboration_identifier}
```

Returns a list of services connected to the collaboration:
```json
[
  {
    "service_identifier": "global-client",
    "service_name": "S3 Gateway Service"
  }
]
```

#### Connect Collaboration to Service
```
PUT /api/collaborations_services/v1/connect_collaboration_service/{collaboration_identifier}
```

Request body:
```json
{
  "service_identifier": "global-client"
}
```

## Code Structure

### Go Client Methods

Three new methods added to `internal/sram/client.go`:

1. **GetCollaborationServices(collaborationIdentifier string)**
   - Retrieves all services connected to a collaboration
   - Returns `[]*ServiceConnection`

2. **ConnectCollaborationToService(collaborationIdentifier, serviceIdentifier string)**
   - Connects a collaboration to a service
   - Returns error if connection fails

3. **IsCollaborationConnectedToService(collaborationIdentifier, serviceIdentifier string)**
   - Helper method to check if already connected
   - Returns bool and error
   - Prevents duplicate connections

### Gateway Integration

In `cmd/gateway/main.go`, the tenant creation flow now includes:

```go
// After creating collaboration
if services.Cfg.OIDC.ClientID != "" {
    serviceIdentifier := services.Cfg.OIDC.ClientID
    
    // Check if already connected
    isConnected, err := sramClient.IsCollaborationConnectedToService(
        collabResp.ShortName, 
        serviceIdentifier
    )
    
    if !isConnected {
        // Connect to service
        err = sramClient.ConnectCollaborationToService(
            collabResp.ShortName, 
            serviceIdentifier
        )
    }
}
```

### Test Script

The `test-sram-api.sh` script now includes:

**Test 1.5: Connect Collaboration to Service**
- Checks existing service connections
- Only connects if not already connected
- Uses `SERVICE_IDENTIFIER` environment variable (defaults to "global-client")

## Usage

### Environment Variable

Set the service identifier in the test script:

```bash
export SERVICE_IDENTIFIER="global-client"
./test-sram-api.sh
```

### Configuration

Ensure `oidc.client_id` is set in `config.yaml`:

```yaml
oidc:
  client_id: "your-service-identifier"
```

## Testing

### Unit Tests

Three new unit tests added to `internal/sram/client_test.go`:

1. **TestGetCollaborationServices** - Tests retrieving service list
2. **TestConnectCollaborationToService** - Tests connecting to service
3. **TestIsCollaborationConnectedToService** - Tests connection check

All tests pass: **8/8 ✅**

```bash
go test ./internal/sram/... -v
```

### Integration Test

Run the SRAM API test script:

```bash
export SRAM_API_KEY="your-api-key"
export SERVICE_IDENTIFIER="global-client"
./test-sram-api.sh
```

Expected output:
```
Test 1.5: Connect Collaboration to Service
Service: global-client

Current services (Status: 200):
[
  {
    "service_identifier": "global-client",
    "service_name": "S3 Gateway Service"
  }
]

Collaboration is already connected to service: global-client
```

## Error Handling

The implementation includes graceful error handling:

- **Check connection fails**: Logs warning, continues
- **Connection fails**: Logs warning, doesn't fail tenant creation
- **Already connected**: Logs info, skips connection attempt
- **Service identifier missing**: Skips service connection entirely

## Benefits

1. **Automatic Setup**: No manual service connection required
2. **Idempotent**: Safe to run multiple times, checks before connecting
3. **Configurable**: Uses existing OIDC configuration
4. **Non-blocking**: Tenant creation succeeds even if service connection fails
5. **Well-tested**: Complete unit test coverage

## Future Enhancements

Potential improvements:

1. Support multiple service identifiers per tenant
2. Add service disconnection functionality
3. Expose service connection status in tenant API
4. Add service connection management UI
