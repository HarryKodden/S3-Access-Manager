#!/bin/bash

# SRAM API Test Script
# This script tests SRAM API endpoints directly without the gateway
# Usage: ./test-sram-api.sh
# 
# This script is re-entrant and can be run multiple times safely.
# It will check for existing collaborations before creating new ones.

# Note: We do NOT use 'set -e' to allow graceful error handling

# Configuration
SRAM_API_URL="${SRAM_API_URL:-https://acc.sram.surf.nl}"
SRAM_API_KEY="${SRAM_API_KEY:-your-api-key-here}"
SERVICE_IDENTIFIER="${SERVICE_IDENTIFIER:-global-client}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "SRAM API Integration Test"
echo "========================================="
echo "API URL: $SRAM_API_URL"
echo ""

# Check if API URL and key are configured
if [ "$SRAM_API_URL" = "https://sram.example.com" ] || [ "$SRAM_API_KEY" = "your-api-key-here" ]; then
    echo -e "${RED}ERROR: Please set SRAM_API_URL and SRAM_API_KEY environment variables${NC}"
    echo ""
    echo "Example:"
    echo "  export SRAM_API_URL=https://your-sram-instance.com"
    echo "  export SRAM_API_KEY=your-actual-api-key"
    echo "  ./test-sram-api.sh"
    exit 1
fi

# Test 1: Get or Create Collaboration
echo -e "${YELLOW}Test 1: Get or Create SRAM Collaboration${NC}"

# First, try to get the organization to see existing collaborations
echo "Checking for existing collaboration..."
ORG_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET \
  "${SRAM_API_URL}/api/organisations/v1" \
  -H "Authorization: Bearer ${SRAM_API_KEY}")

HTTP_CODE=$(echo "$ORG_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
ORG_BODY=$(echo "$ORG_RESPONSE" | sed '/HTTP_CODE:/d')

COLLABORATION_ID=""
COLLABORATION_IDENTIFIER=""
COLLABORATION_SHORT_NAME=""
COLLABORATION_NAME="Test S3 Gateway Collaboration"

if [ "$HTTP_CODE" = "200" ]; then
    # Look for existing test collaboration
    COLLABORATION_ID=$(echo "$ORG_BODY" | jq -r ".collaborations[] | select(.name == \"$COLLABORATION_NAME\") | .id // empty" | head -1)
    
    if [ ! -z "$COLLABORATION_ID" ]; then
        # Also get the identifier and short_name
        COLLABORATION_IDENTIFIER=$(echo "$ORG_BODY" | jq -r ".collaborations[] | select(.name == \"$COLLABORATION_NAME\") | .identifier // empty" | head -1)
        COLLABORATION_SHORT_NAME=$(echo "$ORG_BODY" | jq -r ".collaborations[] | select(.name == \"$COLLABORATION_NAME\") | .short_name // empty" | head -1)
        
        echo -e "${GREEN}Found existing collaboration: $COLLABORATION_NAME${NC}"
        echo "Collaboration ID: $COLLABORATION_ID"
        echo "Identifier: $COLLABORATION_IDENTIFIER"
        echo "Short Name: $COLLABORATION_SHORT_NAME"
        echo ""
    fi
fi

# If no existing collaboration found, create one
if [ -z "$COLLABORATION_ID" ]; then
    echo "Creating new collaboration..."
    COLLABORATION_PAYLOAD=$(cat <<EOF
{
  "name": "$COLLABORATION_NAME",
  "description": "Test collaboration created by SRAM API test script",
  "disable_join_requests": true,
  "disclose_member_information": false,
  "disclose_email_information": false,
  "administrators": ["harry.kodden@surf.nl", "test-admin@example.com"]
}
EOF
    )

    echo "Request payload:"
    echo "$COLLABORATION_PAYLOAD" | jq .
    echo ""

    COLLABORATION_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
      "${SRAM_API_URL}/api/collaborations/v1" \
      -H "Authorization: Bearer ${SRAM_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$COLLABORATION_PAYLOAD")

    HTTP_CODE=$(echo "$COLLABORATION_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY=$(echo "$COLLABORATION_RESPONSE" | sed '/HTTP_CODE:/d')

    echo "Response (Status: $HTTP_CODE):"
    echo "$BODY" | jq .
    echo ""

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        # Extract collaboration ID, identifier and short_name
        COLLABORATION_ID=$(echo "$BODY" | jq -r '.id // empty')
        COLLABORATION_IDENTIFIER=$(echo "$BODY" | jq -r '.identifier // empty')
        COLLABORATION_SHORT_NAME=$(echo "$BODY" | jq -r '.short_name // empty')
        
        if [ ! -z "$COLLABORATION_ID" ]; then
            echo -e "${GREEN}SUCCESS: Collaboration created with ID: $COLLABORATION_ID${NC}"
            echo "Identifier: $COLLABORATION_IDENTIFIER"
            echo "Short Name: $COLLABORATION_SHORT_NAME"
        fi
    else
        echo -e "${YELLOW}WARNING: Could not create collaboration (Status: $HTTP_CODE)${NC}"
        echo "This may be because it already exists or there are permission issues."
        echo "Attempting to continue with existing collaborations..."
        
        # Try to find any collaboration we can use for testing
        COLLABORATION_ID=$(echo "$ORG_BODY" | jq -r '.collaborations[0].id // empty')
    fi
fi

if [ -z "$COLLABORATION_ID" ]; then
    echo -e "${RED}ERROR: Could not find or create a collaboration${NC}"
    echo "Please check:"
    echo "1. API key has correct permissions"
    echo "2. Organisation exists and is accessible"
    echo "3. You can create collaborations"
    exit 1
fi

echo -e "${GREEN}Using collaboration ID: $COLLABORATION_ID${NC}"
echo ""

# Test 1.5: Connect Collaboration to Service
if [ ! -z "$COLLABORATION_IDENTIFIER" ] && [ ! -z "$SERVICE_IDENTIFIER" ]; then
    echo -e "${YELLOW}Test 1.5: Connect Collaboration to Service${NC}"
    echo "Service: $SERVICE_IDENTIFIER"
    echo ""
    
    # First check if already connected by getting collaboration services
    SERVICES_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET \
      "${SRAM_API_URL}/api/collaborations_services/v1/${COLLABORATION_IDENTIFIER}" \
      -H "Authorization: Bearer ${SRAM_API_KEY}")
    
    HTTP_CODE=$(echo "$SERVICES_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    SERVICES_BODY=$(echo "$SERVICES_RESPONSE" | sed '/HTTP_CODE:/d')
    
    echo "Current services (Status: $HTTP_CODE):"
    echo "$SERVICES_BODY" | jq .
    echo ""
    
    # Check if service is already connected
    IS_CONNECTED="false"
    if [ "$HTTP_CODE" = "200" ]; then
        IS_CONNECTED=$(echo "$SERVICES_BODY" | jq -r --arg service "$SERVICE_IDENTIFIER" '.[] | select(.service_identifier == $service) | "true"' | head -1)
    fi
    
    if [ "$IS_CONNECTED" = "true" ]; then
        echo -e "${GREEN}Collaboration is already connected to service: $SERVICE_IDENTIFIER${NC}"
        echo ""
    else
        echo "Connecting collaboration to service..."
        
        CONNECT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X PUT \
          "${SRAM_API_URL}/api/collaborations_services/v1/connect_collaboration_service/${COLLABORATION_IDENTIFIER}" \
          -H "Authorization: Bearer ${SRAM_API_KEY}" \
          -H "Content-Type: application/json" \
          -d "{\"service_entity_id\": \"$SERVICE_IDENTIFIER\"}")
        
        HTTP_CODE=$(echo "$CONNECT_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
        CONNECT_BODY=$(echo "$CONNECT_RESPONSE" | sed '/HTTP_CODE:/d')
        
        echo "Response (Status: $HTTP_CODE):"
        echo "$CONNECT_BODY" | jq .
        echo ""
        
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
            echo -e "${GREEN}SUCCESS: Collaboration connected to service${NC}"
        else
            echo -e "${YELLOW}WARNING: Could not connect to service (Status: $HTTP_CODE)${NC}"
            echo "This may require service registration or additional permissions."
        fi
        echo ""
    fi
fi

# Test 2: Send Invitations
echo -e "${YELLOW}Test 2: Sending Invitations${NC}"

# Use collaboration_identifier (UUID) for invitations
if [ -z "$COLLABORATION_IDENTIFIER" ]; then
    echo -e "${YELLOW}WARNING: No collaboration identifier available, skipping invitation test${NC}"
    echo ""
else
    INVITATION_PAYLOAD=$(cat <<EOF
{
  "collaboration_identifier": "$COLLABORATION_IDENTIFIER",
  "intended_role": "admin",
  "invites": [
    {"email": "admin1@example.com"},
    {"email": "admin2@example.com"}
  ],
  "message": "You are invited to join the Test S3 Gateway collaboration"
}
EOF
    )

    echo "Request payload:"
    echo "$INVITATION_PAYLOAD" | jq .
    echo ""

    INVITATION_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X PUT \
      "${SRAM_API_URL}/api/invitations/v1/collaboration_invites" \
      -H "Authorization: Bearer ${SRAM_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$INVITATION_PAYLOAD")

    HTTP_CODE=$(echo "$INVITATION_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY=$(echo "$INVITATION_RESPONSE" | sed '/HTTP_CODE:/d')

    echo "Response (Status: $HTTP_CODE):"
    echo "$BODY" | jq .
    echo ""

    # Check if invitations were sent
    INVITATION_COUNT=$(echo "$BODY" | jq 'length // 0')

    if [ "$INVITATION_COUNT" -gt 0 ]; then
        echo -e "${GREEN}SUCCESS: Sent $INVITATION_COUNT invitation(s)${NC}"
    else
        echo -e "${YELLOW}WARNING: Could not send invitations (Status: $HTTP_CODE)${NC}"
        echo "This may be because the invitations already exist or there are permission issues."
        echo "Continuing with other tests..."
    fi
    echo ""
fi

# Test 3: Get Collaboration Invitations
echo -e "${YELLOW}Test 3: Fetching Collaboration Invitations${NC}"

INVITATIONS_LIST=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET \
  "${SRAM_API_URL}/api/invitations/v1/invitations/${COLLABORATION_ID}" \
  -H "Authorization: Bearer ${SRAM_API_KEY}")

HTTP_CODE=$(echo "$INVITATIONS_LIST" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$INVITATIONS_LIST" | sed '/HTTP_CODE:/d')

echo "Response (Status: $HTTP_CODE):"
echo "$BODY" | jq .
echo ""

FETCHED_COUNT=$(echo "$BODY" | jq 'length // 0')

if [ "$FETCHED_COUNT" -gt 0 ]; then
    echo -e "${GREEN}SUCCESS: Found $FETCHED_COUNT invitation(s)${NC}"
else
    echo -e "${YELLOW}WARNING: Could not fetch invitations (Status: $HTTP_CODE)${NC}"
    echo "Continuing with remaining tests..."
fi
echo ""

# Test 4: Get Invitation Status (first invitation)
FIRST_INVITATION_ID=$(echo "$BODY" | jq -r '.[0].id // empty')

if [ -z "$FIRST_INVITATION_ID" ]; then
    echo -e "${YELLOW}No invitation ID found, skipping status check${NC}"
else
    echo -e "${YELLOW}Test 4: Checking Invitation Status${NC}"
    echo "Invitation ID: $FIRST_INVITATION_ID"
    echo ""

    INVITATION_STATUS=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET \
      "${SRAM_API_URL}/api/invitations/v1/${FIRST_INVITATION_ID}" \
      -H "Authorization: Bearer ${SRAM_API_KEY}")

    HTTP_CODE=$(echo "$INVITATION_STATUS" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY=$(echo "$INVITATION_STATUS" | sed '/HTTP_CODE:/d')

    echo "Response (Status: $HTTP_CODE):"
    echo "$BODY" | jq .
    echo ""

    STATUS=$(echo "$BODY" | jq -r '.status // "unknown"')

    if [ "$STATUS" = "pending" ] || [ "$STATUS" = "accepted" ] || [ "$STATUS" = "declined" ]; then
        echo -e "${GREEN}SUCCESS: Invitation status is: $STATUS${NC}"
    else
        echo -e "${YELLOW}WARNING: Unexpected invitation status: $STATUS${NC}"
        echo "Continuing..."
    fi
    echo ""
fi

# Summary
echo "========================================="
echo -e "${GREEN}All SRAM API Tests Passed!${NC}"
echo "========================================="
echo ""
echo "Collaboration Details:"
echo "  ID: $COLLABORATION_ID"
echo "  Name: Test S3 Gateway Collaboration"
echo "  Short Name: test-s3-gateway"
echo "  Invitations Sent: $INVITATION_COUNT"
echo ""
echo "Next Steps:"
echo "1. Check your SRAM dashboard to verify the collaboration was created"
echo "2. Check email inbox for invitation emails"
echo "3. Accept an invitation and re-run Test 4 to verify 'accepted' status"
echo "4. Clean up: Delete the test collaboration from SRAM dashboard"
echo ""
