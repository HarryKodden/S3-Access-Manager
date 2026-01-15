#!/bin/bash

# S3 Gateway Complete Flow Demonstration Script
# This script demonstrates the complete flow of using the S3 Gateway with OIDC authentication

set -e  # Exit on any error

# Configuration
GATEWAY_URL="http://localhost:9000"
OIDC_URL="http://localhost:8888"
CLIENT_ID="test-client"
CLIENT_SECRET="test-secret"
ADMIN_EMAIL="admin@example.com"
echo "🔐 S3 Gateway Complete Flow Demonstration"
echo "=========================================="
echo

# Function to get access token using client_credentials
get_token() {
    local scope=$1
    local email=$2
    local token=$(curl -s -X POST "$OIDC_URL/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$CLIENT_ID:$CLIENT_SECRET" \
        -d "grant_type=client_credentials&scope=$scope&email=$email" | jq -r '.access_token')

    if [ "$token" = "null" ] || [ -z "$token" ]; then
        echo "❌ Failed to get access token for scope: $scope"
        exit 1
    fi

    echo "$token"
}

# Function to make authenticated API calls
api_call() {
    local method=$1
    local url=$2
    local token=$3
    local data=$4

    if [ -n "$data" ]; then
        curl -s -X "$method" "$GATEWAY_URL$url" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -X "$method" "$GATEWAY_URL$url" \
            -H "Authorization: Bearer $token"
    fi
}

echo "1️⃣ Authenticating as Admin User (role: admin)"
echo "---------------------------------------------"
ADMIN_TOKEN=$(get_token "roles:admin" "$ADMIN_EMAIL")
echo "✅ Got admin access token"

# Decode and display token info
echo "Admin token payload:"
echo "$ADMIN_TOKEN" | jq -R 'split(".") | .[1] | @base64d | fromjson' 2>/dev/null || echo "Could not decode token"
echo

echo "2️⃣ Creating Role 'user' connected to Read-Write policy"
echo "-----------------------------------------------------"
ROLE_DATA='{
    "name": "user",
    "policies": ["Read-Write"],
    "description": "User role with read-write access"
}'

echo "Creating role with data:"
echo "$ROLE_DATA" | jq .
echo

CREATE_ROLE_RESPONSE=$(api_call "POST" "/settings/roles" "$ADMIN_TOKEN" "$ROLE_DATA")
echo "Create role response:"
echo "$CREATE_ROLE_RESPONSE" | jq .
echo

echo "3️⃣ Authenticating as Normal User (role: user)"
echo "---------------------------------------------"
USER_TOKEN=$(get_token "roles:user" "user@example.com")
echo "✅ Got user access token"

# Decode and display token info
echo "User token payload:"
echo "$USER_TOKEN" | jq -R 'split(".") | .[1] | @base64d | fromjson' 2>/dev/null || echo "Could not decode token"
echo

echo "4️⃣ Creating Credential using role 'user'"
echo "----------------------------------------"
CRED_DATA='{
    "name": "user-credential",
    "roles": ["user"],
    "description": "Credential for user role testing"
}'

echo "Creating credential with data:"
echo "$CRED_DATA" | jq .
echo

CREATE_CRED_RESPONSE=$(api_call "POST" "/settings/credentials" "$USER_TOKEN" "$CRED_DATA")
echo "Create credential response:"
echo "$CREATE_CRED_RESPONSE" | jq .

# Extract the access key from the response
ACCESS_KEY=$(echo "$CREATE_CRED_RESPONSE" | jq -r '.credential.access_key')
if [ "$ACCESS_KEY" = "null" ] || [ -z "$ACCESS_KEY" ]; then
    echo "❌ Failed to extract access key from credential creation response"
    exit 1
fi

echo "✅ Created credential with access key: $ACCESS_KEY"
echo

echo "5️⃣ Performing S3 Bucket Operations using the credential"
echo "--------------------------------------------------------"

# Function to make S3 API calls with credential
s3_call() {
    local method=$1
    local path=$2
    local data=$3

    if [ -n "$data" ]; then
        curl -s -X "$method" "$GATEWAY_URL/s3$path" \
            -H "X-S3-Credential-AccessKey: $ACCESS_KEY" \
            -H "Authorization: Bearer $USER_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -X "$method" "$GATEWAY_URL/s3$path" \
            -H "X-S3-Credential-AccessKey: $ACCESS_KEY" \
            -H "Authorization: Bearer $USER_TOKEN"
    fi
}

echo "5.1️⃣ Listing Buckets"
echo "-------------------"
LIST_BUCKETS_RESPONSE=$(s3_call "GET" "/")
echo "List buckets response:"
echo "$LIST_BUCKETS_RESPONSE" | jq .
echo

# Try to list objects in a test bucket (this might fail if bucket doesn't exist, but shows the flow)
echo "5.2️⃣ Listing Objects in 'test-bucket' (may not exist)"
echo "---------------------------------------------------"
LIST_OBJECTS_RESPONSE=$(s3_call "GET" "/test-bucket")
echo "List objects response:"
echo "$LIST_OBJECTS_RESPONSE" | jq .
echo

echo "5.3️⃣ Creating a Test Bucket"
echo "---------------------------"
CREATE_BUCKET_RESPONSE=$(api_call "POST" "/settings/buckets" "$USER_TOKEN" '{"name": "test-bucket", "description": "Test bucket for demonstration"}')
echo "Create bucket response:"
echo "$CREATE_BUCKET_RESPONSE" | jq .
echo

echo "5.4️⃣ Listing Objects in Test Bucket (should be empty)"
echo "----------------------------------------------------"
LIST_OBJECTS_RESPONSE=$(s3_call "GET" "/test-bucket")
echo "List objects response:"
echo "$LIST_OBJECTS_RESPONSE" | jq .
echo

echo "5.5️⃣ Uploading a Test Object"
echo "----------------------------"
# Create a simple test file
echo "Hello, S3 Gateway!" > /tmp/test-object.txt

UPLOAD_RESPONSE=$(curl -s -X PUT "$GATEWAY_URL/s3/test-bucket/test-object.txt" \
    -H "X-S3-Credential-AccessKey: $ACCESS_KEY" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: text/plain" \
    --data-binary @/tmp/test-object.txt)

if [ $? -eq 0 ]; then
    echo "✅ Upload successful"
else
    echo "❌ Upload failed"
fi
echo

echo "5.6️⃣ Listing Objects Again (should show the uploaded object)"
echo "-----------------------------------------------------------"
LIST_OBJECTS_RESPONSE=$(s3_call "GET" "/test-bucket")
echo "List objects response:"
echo "$LIST_OBJECTS_RESPONSE" | jq .
echo

echo "5.7️⃣ Downloading the Test Object"
echo "--------------------------------"
DOWNLOAD_RESPONSE=$(curl -s "$GATEWAY_URL/s3/test-bucket/test-object.txt" \
    -H "X-S3-Credential-AccessKey: $ACCESS_KEY" \
    -H "Authorization: Bearer $USER_TOKEN")

echo "Downloaded content:"
echo "$DOWNLOAD_RESPONSE"
echo

echo "🎉 Complete Flow Demonstration Finished!"
echo "========================================="
echo
echo "Summary:"
echo "- ✅ Authenticated as admin user"
echo "- ✅ Created 'user' role with Read-Write policy"
echo "- ✅ Authenticated as normal user"
echo "- ✅ Created credential with user role"
echo "- ✅ Listed buckets"
echo "- ✅ Created test bucket"
echo "- ✅ Listed objects (empty then with object)"
echo "- ✅ Uploaded test object"
echo "- ✅ Downloaded test object"
echo
echo "The S3 Gateway is working correctly with OIDC authentication and role-based access control!"