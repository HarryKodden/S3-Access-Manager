#!/bin/bash
# End-to-End Test Script for S3 Proxy Functionality
# Tests: Gateway S3 Proxy for both Web UI and AWS CLI
#
# This test validates:
#   1. Web UI S3 operations via gateway (OIDC token + X-S3-Credential-AccessKey)
#   2. AWS CLI S3 operations via gateway (AWS4-HMAC-SHA256 auth)
#   3. Policy enforcement during S3 proxy operations
#   4. Read-only vs read-write credential permissions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GATEWAY_URL="http://localhost:9000"
OIDC_URL="http://localhost:8888"
TEST_USER="testuser@example.com"
TEST_GROUPS="developer-group"
PROFILE_NAME="s3-gateway-proxy-test-$$"
CREDENTIAL_NAME_RW="test-cred-rw-$$"
CREDENTIAL_NAME_RO="test-cred-ro-$$"
FAILED_TESTS=0
TOTAL_TESTS=0

# Test data
TEST_BUCKET="test-bucket"
TEST_FILE="test-proxy-file.txt"
TEST_CONTENT="Hello from S3 Gateway Proxy Test!"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    
    # Clean up AWS profile
    if [ -f ~/.aws/credentials ]; then
        sed -i.bak "/\[$PROFILE_NAME\]/,/^$/d" ~/.aws/credentials 2>/dev/null || true
    fi
    if [ -f ~/.aws/config ]; then
        sed -i.bak "/\[profile $PROFILE_NAME\]/,/^$/d" ~/.aws/config 2>/dev/null || true
    fi
    
    # Clean up test files
    rm -f "/tmp/$TEST_FILE" "/tmp/downloaded-$TEST_FILE"
    
    # Delete test bucket via gateway if it exists
    if [ ! -z "$ACCESS_TOKEN" ] && [ ! -z "$RW_ACCESS_KEY" ]; then
        echo "Cleaning up test bucket..."
        # Try to delete all objects first
        curl -s -X DELETE "$GATEWAY_URL/$TEST_BUCKET/$TEST_FILE" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            -H "X-S3-Credential-AccessKey: $RW_ACCESS_KEY" > /dev/null 2>&1 || true
        sleep 1
        # Delete bucket
        curl -s -X DELETE "$GATEWAY_URL/settings/buckets/$TEST_BUCKET" \
            -H "Authorization: Bearer $ACCESS_TOKEN" > /dev/null 2>&1 || true
    fi
    
    # Delete test credentials
    if [ ! -z "$ACCESS_TOKEN" ]; then
        if [ ! -z "$RW_ACCESS_KEY" ]; then
            echo "Deleting read-write credential..."
            curl -s -X DELETE "$GATEWAY_URL/settings/credentials/$RW_ACCESS_KEY" \
                -H "Authorization: Bearer $ACCESS_TOKEN" > /dev/null 2>&1 || true
        fi
        if [ ! -z "$RO_ACCESS_KEY" ]; then
            echo "Deleting read-only credential..."
            curl -s -X DELETE "$GATEWAY_URL/settings/credentials/$RO_ACCESS_KEY" \
                -H "Authorization: Bearer $ACCESS_TOKEN" > /dev/null 2>&1 || true
        fi
    fi
    
    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Check prerequisites
print_header "Checking Prerequisites"

command -v curl >/dev/null 2>&1 || { print_error "curl not found"; exit 1; }
command -v jq >/dev/null 2>&1 || { print_error "jq not found"; exit 1; }
command -v aws >/dev/null 2>&1 || { print_error "aws CLI not found"; exit 1; }

print_info "All required tools are available"

# Check services
print_info "Checking gateway health..."
if ! curl -s -f "$GATEWAY_URL/health" > /dev/null; then
    print_error "Gateway is not responding at $GATEWAY_URL"
    exit 1
fi
print_info "Gateway is healthy"

print_info "Checking OIDC provider..."
if ! curl -s -f "$OIDC_URL/.well-known/openid-configuration" > /dev/null; then
    print_error "OIDC provider is not responding at $OIDC_URL"
    exit 1
fi
print_info "OIDC provider is available"

# Step 1: Get OIDC Token
print_header "Step 1: OIDC Authentication"

print_info "Requesting token from OIDC test-token endpoint..."
TOKEN_RESPONSE=$(curl -s "$OIDC_URL/test-token/$TEST_USER?groups=$TEST_GROUPS")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    print_error "Failed to get access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

print_success "Obtained access token for user $TEST_USER"

# Step 2: Create Credentials with Different Policies
print_header "Step 2: Create Test Credentials"

# Create read-write credential
print_info "Creating read-write credential..."
RW_CRED_REQUEST="{
    \"name\": \"$CREDENTIAL_NAME_RW\",
    \"description\": \"Read-Write test credential\",
    \"groups\": [\"developer-group\"]
}"

RW_CRED_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/settings/credentials" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$RW_CRED_REQUEST")

RW_ACCESS_KEY=$(echo "$RW_CRED_RESPONSE" | jq -r '.credential.access_key // .credential.AccessKey // .credential.accessKey // .accessKey // empty')
RW_SECRET_KEY=$(echo "$RW_CRED_RESPONSE" | jq -r '.credential.secret_key // .credential.SecretKey // .credential.secretKey // .secretKey // empty')

if [ -z "$RW_ACCESS_KEY" ] || [ -z "$RW_SECRET_KEY" ]; then
    print_error "Failed to create read-write credential"
    echo "$RW_CRED_RESPONSE" | jq '.'
    exit 1
fi

print_success "Read-write credential created: $RW_ACCESS_KEY"

# Create read-only credential (if read-only group exists)
print_info "Creating read-only credential..."
RO_CRED_REQUEST="{
    \"name\": \"$CREDENTIAL_NAME_RO\",
    \"description\": \"Read-Only test credential\",
    \"groups\": [\"readonly\"]
}"

RO_CRED_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/settings/credentials" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$RO_CRED_REQUEST")

RO_ACCESS_KEY=$(echo "$RO_CRED_RESPONSE" | jq -r '.credential.access_key // .credential.AccessKey // .credential.accessKey // .accessKey // empty')
RO_SECRET_KEY=$(echo "$RO_CRED_RESPONSE" | jq -r '.credential.secret_key // .credential.SecretKey // .credential.secretKey // .secretKey // empty')

if [ -z "$RO_ACCESS_KEY" ] || [ "$RO_ACCESS_KEY" = "null" ]; then
    print_info "Read-only group not available, skipping RO tests"
    SKIP_RO_TESTS=true
else
    print_success "Read-only credential created: $RO_ACCESS_KEY"
fi

# Step 3: Create Test Bucket
print_header "Step 3: Create Test Bucket"

print_info "Creating bucket '$TEST_BUCKET' via S3 proxy..."
BUCKET_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$GATEWAY_URL/$TEST_BUCKET" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-S3-Credential-AccessKey: $RW_ACCESS_KEY")

HTTP_CODE=$(echo "$BUCKET_RESPONSE" | tail -1)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    print_success "Test bucket created"
else
    print_error "Failed to create bucket (HTTP $HTTP_CODE)"
    echo "Response: $BUCKET_RESPONSE" | head -n -1
    exit 1
fi

# Step 4: Test Web UI S3 Operations via Gateway
print_header "Step 4: Test Web UI S3 Operations (via Gateway Proxy)"

# Create test file
echo "$TEST_CONTENT" > "/tmp/$TEST_FILE"

# Test 4.1: Upload via Web UI (PUT with OIDC + credential header)
print_info "Test 4.1: Upload file via Web UI proxy..."
UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$GATEWAY_URL/$TEST_BUCKET/$TEST_FILE" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-S3-Credential-AccessKey: $RW_ACCESS_KEY" \
    -H "Content-Type: text/plain" \
    --data "$TEST_CONTENT")

# Extract HTTP code more safely
HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | awk 'END {print $NF}')
RESPONSE_BODY=$(echo "$UPLOAD_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    print_success "Web UI upload succeeded (HTTP $HTTP_CODE)"
    FILE_UPLOADED=true
else
    print_error "Web UI upload failed (HTTP $HTTP_CODE)"
    echo "Response body: $RESPONSE_BODY"
fi

# Test 4.2: Download via Web UI (GET with OIDC + credential header)
if [ "$FILE_UPLOADED" = true ]; then
    print_info "Test 4.2: Download file via Web UI proxy..."
    DOWNLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL/$TEST_BUCKET/$TEST_FILE" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-S3-Credential-AccessKey: $RW_ACCESS_KEY" \
        -o "/tmp/downloaded-$TEST_FILE")
    
    HTTP_CODE=$(echo "$DOWNLOAD_RESPONSE" | tail -1)
    if [ "$HTTP_CODE" = "200" ]; then
        DOWNLOADED_CONTENT=$(cat "/tmp/downloaded-$TEST_FILE")
        if [ "$DOWNLOADED_CONTENT" = "$TEST_CONTENT" ]; then
            print_success "Web UI download succeeded (content matches)"
        else
            print_error "Web UI download content mismatch"
        fi
    else
        print_error "Web UI download failed (HTTP $HTTP_CODE)"
    fi
fi

# Test 4.3: List bucket via Web UI (GET with OIDC + credential header)
print_info "Test 4.3: List bucket via Web UI proxy..."
LIST_RESPONSE=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL/$TEST_BUCKET" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-S3-Credential-AccessKey: $RW_ACCESS_KEY")

# Extract HTTP code more safely
HTTP_CODE=$(echo "$LIST_RESPONSE" | awk 'END {print $NF}')
BODY=$(echo "$LIST_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    if echo "$BODY" | grep -q "$TEST_FILE"; then
        print_success "Web UI list bucket succeeded (found $TEST_FILE)"
    else
        print_error "Web UI list bucket succeeded but file not found in: $BODY"
    fi
else
    print_error "Web UI list bucket failed (HTTP $HTTP_CODE)"
    echo "Response body: $BODY"
fi

# Test 4.4: Read-only credential should fail on upload
if [ "$SKIP_RO_TESTS" != true ]; then
    print_info "Test 4.4: Read-only credential upload (should fail)..."
    RO_UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$GATEWAY_URL/$TEST_BUCKET/readonly-test.txt" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-S3-Credential-AccessKey: $RO_ACCESS_KEY" \
        -H "Content-Type: text/plain" \
        --data "test")
    
    HTTP_CODE=$(echo "$RO_UPLOAD_RESPONSE" | awk 'END {print $NF}')
    if [ "$HTTP_CODE" = "403" ]; then
        print_success "Read-only credential correctly denied upload (HTTP 403)"
    else
        print_error "Read-only credential upload should have failed (HTTP $HTTP_CODE)"
    fi
fi

# Step 5: Test AWS CLI S3 Operations via Gateway
print_header "Step 5: Test AWS CLI S3 Operations (via Gateway Proxy)"

# Configure AWS CLI to point to gateway
print_info "Configuring AWS CLI profile to use gateway endpoint..."
mkdir -p ~/.aws

cat >> ~/.aws/credentials << EOF

[$PROFILE_NAME]
aws_access_key_id = $RW_ACCESS_KEY
aws_secret_access_key = $RW_SECRET_KEY
EOF

cat >> ~/.aws/config << EOF

[profile $PROFILE_NAME]
region = us-east-1
endpoint_url = $GATEWAY_URL
s3 =
  signature_version = s3v4
  addressing_style = path
EOF

print_info "AWS CLI configured to use gateway at $GATEWAY_URL"

# Test 5.1: List buckets via CLI through gateway
print_info "Test 5.1: List buckets via AWS CLI (through gateway)..."
echo "Running: aws --profile $PROFILE_NAME s3 ls"
aws --profile $PROFILE_NAME s3 ls
if aws --profile $PROFILE_NAME s3 ls | grep -q "$TEST_BUCKET"; then
    print_success "AWS CLI list buckets succeeded (found $TEST_BUCKET)"
else
    print_error "AWS CLI list buckets failed or bucket not found"
fi

# Test 5.2: List objects via CLI through gateway
print_info "Test 5.2: List objects via AWS CLI (through gateway)..."
if aws --profile "$PROFILE_NAME" s3 ls "s3://$TEST_BUCKET/" 2>/dev/null | grep -q "$TEST_FILE"; then
    print_success "AWS CLI list objects succeeded (found $TEST_FILE)"
else
    print_error "AWS CLI list objects failed or file not found"
fi

# Test 5.3: Upload via CLI through gateway
print_info "Test 5.3: Upload file via AWS CLI (through gateway)..."
CLI_TEST_FILE="cli-test-file.txt"
echo "CLI Upload Test" > "/tmp/$CLI_TEST_FILE"
if aws --profile "$PROFILE_NAME" s3 cp "/tmp/$CLI_TEST_FILE" "s3://$TEST_BUCKET/$CLI_TEST_FILE" 2>/dev/null; then
    print_success "AWS CLI upload succeeded"
    CLI_FILE_UPLOADED=true
else
    print_error "AWS CLI upload failed"
fi

# Test 5.4: Download via CLI through gateway
if [ "$CLI_FILE_UPLOADED" = true ]; then
    print_info "Test 5.4: Download file via AWS CLI (through gateway)..."
    CLI_DOWNLOAD_FILE="/tmp/cli-downloaded-$CLI_TEST_FILE"
    if aws --profile "$PROFILE_NAME" s3 cp "s3://$TEST_BUCKET/$CLI_TEST_FILE" "$CLI_DOWNLOAD_FILE" 2>/dev/null; then
        CLI_DOWNLOADED_CONTENT=$(cat "$CLI_DOWNLOAD_FILE")
        if [ "$CLI_DOWNLOADED_CONTENT" = "CLI Upload Test" ]; then
            print_success "AWS CLI download succeeded (content matches)"
        else
            print_error "AWS CLI download content mismatch"
        fi
        rm -f "$CLI_DOWNLOAD_FILE"
    else
        print_error "AWS CLI download failed"
    fi
fi

# Test 5.5: Delete via CLI through gateway
if [ "$CLI_FILE_UPLOADED" = true ]; then
    print_info "Test 5.5: Delete file via AWS CLI (through gateway)..."
    if aws --profile "$PROFILE_NAME" s3 rm "s3://$TEST_BUCKET/$CLI_TEST_FILE" 2>/dev/null; then
        print_success "AWS CLI delete succeeded"
    else
        print_error "AWS CLI delete failed"
    fi
fi

rm -f "/tmp/$CLI_TEST_FILE"

# Step 6: Test Authentication Requirements
print_header "Step 6: Test Authentication Requirements"

# Test 6.1: Request without auth should fail
print_info "Test 6.1: Request without authentication (should fail)..."
NO_AUTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL/$TEST_BUCKET")
HTTP_CODE=$(echo "$NO_AUTH_RESPONSE" | awk 'END {print $NF}')
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    print_success "Request without auth correctly denied (HTTP $HTTP_CODE)"
else
    print_error "Request without auth should have failed (HTTP $HTTP_CODE)"
fi

# Test 6.2: Request with OIDC token but no credential header should fail
print_info "Test 6.2: Request with OIDC token only (should fail)..."
NO_CRED_RESPONSE=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL/$TEST_BUCKET" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
HTTP_CODE=$(echo "$NO_CRED_RESPONSE" | awk 'END {print $NF}')
if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "401" ]; then
    print_success "Request without credential header correctly denied (HTTP $HTTP_CODE)"
else
    print_error "Request without credential header should have failed (HTTP $HTTP_CODE)"
fi

# Test 6.3: Request with invalid credential should fail
print_info "Test 6.3: Request with invalid credential (should fail)..."
INVALID_CRED_RESPONSE=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL/$TEST_BUCKET" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-S3-Credential-AccessKey: INVALID_KEY_12345")
HTTP_CODE=$(echo "$INVALID_CRED_RESPONSE" | awk 'END {print $NF}')
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "404" ]; then
    print_success "Request with invalid credential correctly denied (HTTP $HTTP_CODE)"
else
    print_error "Request with invalid credential should have failed (HTTP $HTTP_CODE)"
fi

# Final Summary
print_header "Test Summary"

PASSED_TESTS=$((TOTAL_TESTS - FAILED_TESTS))

echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
else
    echo -e "Failed: 0"
fi
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    print_success "All tests passed! ✓"
    echo ""
    echo -e "${GREEN}S3 Gateway Proxy is working correctly:${NC}"
    echo "  • Web UI S3 operations via gateway proxy work"
    echo "  • AWS CLI S3 operations via gateway proxy work"
    echo "  • Policy enforcement works correctly"
    echo "  • Authentication requirements are enforced"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
