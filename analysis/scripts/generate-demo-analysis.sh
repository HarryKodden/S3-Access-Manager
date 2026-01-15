#!/bin/bash

# Generate Demo Flow Analysis Script
# This script runs demo-flow.sh and automatically generates the gap analysis document

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_SCRIPT="$SCRIPT_DIR/demo-flow.sh"
TEMPLATE_FILE="$SCRIPT_DIR/../templates/demo-flow-template.md"
OUTPUT_FILE="$SCRIPT_DIR/../output/demo-flow.md"

echo "🔄 Running demo-flow.sh and generating gap analysis..."

# Run the demo script and capture all output
# Note: Don't exit on demo failure - we still want to analyze partial results
set +e
DEMO_OUTPUT=$(bash "$DEMO_SCRIPT" 2>&1)
DEMO_EXIT_CODE=$?
set -e

if [ $DEMO_EXIT_CODE -ne 0 ]; then
    echo "⚠️ Demo script completed with warnings (exit code $DEMO_EXIT_CODE) - proceeding with partial analysis"
else
    echo "✅ Demo script completed successfully"
fi

# Function to extract JSON from demo output
extract_json() {
    local section=$1
    local output="$2"

    # Extract the JSON response for a specific section
    case $section in
        "admin_token")
            echo "$output" | sed -n '/Admin token payload:/,/^$/p' | grep -A 20 "{" | head -20 | jq . 2>/dev/null || echo "$output" | sed -n '/Admin token payload:/,/^$/p' | grep -A 20 "{" | head -20
            ;;
        "create_role")
            echo "$output" | sed -n '/Create role response:/,/^$/p' | grep -A 10 "{" | head -10 | jq . 2>/dev/null || echo "$output" | sed -n '/Create role response:/,/^$/p' | grep -A 10 "{" | head -10
            ;;
        "user_token")
            echo "$output" | sed -n '/User token payload:/,/^$/p' | grep -A 20 "{" | head -20 | jq . 2>/dev/null || echo "$output" | sed -n '/User token payload:/,/^$/p' | grep -A 20 "{" | head -20
            ;;
        "create_credential")
            echo "$output" | sed -n '/Create credential response:/,/^$/p' | grep -A 20 "{" | head -20 | jq . 2>/dev/null || echo "$output" | sed -n '/Create credential response:/,/^$/p' | grep -A 20 "{" | head -20
            ;;
        "list_buckets")
            echo "$output" | sed -n '/List buckets response:/,/^$/p' | grep -A 10 "{" | head -10 | jq . 2>/dev/null || echo "$output" | sed -n '/List buckets response:/,/^$/p' | grep -A 10 "{" | head -10
            ;;
        "list_objects_nonexist")
            # First occurrence after "5.2️⃣"
            echo "$output" | sed -n '/5.2️⃣ List/,/5.3️⃣/p' | sed -n '/List objects response:/,/^$/p' | grep -A 15 "{" | head -15 | jq . 2>/dev/null || echo "$output" | sed -n '/5.2️⃣ List/,/5.3️⃣/p' | sed -n '/List objects response:/,/^$/p' | grep -A 15 "{" | head -15
            ;;
        "create_bucket")
            echo "$output" | sed -n '/Create bucket response:/,/^$/p' | grep -A 10 "{" | head -10 | jq . 2>/dev/null || echo "$output" | sed -n '/Create bucket response:/,/^$/p' | grep -A 10 "{" | head -10
            ;;
        "list_objects_empty")
            # Second occurrence after create bucket
            echo "$output" | sed -n '/5.4️⃣ List/,/5.5️⃣/p' | sed -n '/List objects response:/,/^$/p' | grep -A 15 "{" | head -15 | jq . 2>/dev/null || echo "$output" | sed -n '/5.4️⃣ List/,/5.5️⃣/p' | sed -n '/List objects response:/,/^$/p' | grep -A 15 "{" | head -15
            ;;
        "upload_object")
            # Check if upload was successful
            if echo "$output" | grep -q "✅ Upload successful"; then
                echo '"✅ Upload successful"'
            else
                echo '"❌ Upload failed"'
            fi
            ;;
        "list_objects_after_upload")
            # Third occurrence after upload
            echo "$output" | sed -n '/5.6️⃣ List/,/5.7️⃣/p' | sed -n '/List objects response:/,/^$/p' | grep -A 15 "{" | head -15 | jq . 2>/dev/null || echo "$output" | sed -n '/5.6️⃣ List/,/5.7️⃣/p' | sed -n '/List objects response:/,/^$/p' | grep -A 15 "{" | head -15
            ;;
        "download_object")
            # Extract the downloaded content
            echo "$output" | sed -n '/Downloaded content:/,/^🎉/p' | grep -v "Downloaded content:" | grep -v "^🎉" | grep -v "^$" | jq -R . 2>/dev/null || echo "$output" | sed -n '/Downloaded content:/,/^🎉/p' | grep -v "Downloaded content:" | grep -v "^🎉" | grep -v "^$" | tr -d '\n' | sed 's/^/"/;s/$/"/'
            ;;
    esac
}

# Function to extract commands from demo output
extract_command() {
    local section=$1
    local output="$2"

    # Extract the command for a specific section
    case $section in
        "admin_token")
            echo "curl -s -X POST \"http://localhost:8888/token\" -H \"Content-Type: application/x-www-form-urlencoded\" -u \"test-client:test-secret\" -d \"grant_type=client_credentials&scope=roles:admin&email=admin@example.com\""
            ;;
        "create_role")
            echo "curl -s -X POST \"http://localhost:9000/settings/roles\" -H \"Authorization: Bearer <admin-token>\" -H \"Content-Type: application/json\" -d '{\"name\": \"user\", \"policies\": [\"Read-Write\"], \"description\": \"User role with read-write access\"}'"
            ;;
        "user_token")
            echo "curl -s -X POST \"http://localhost:8888/token\" -H \"Content-Type: application/x-www-form-urlencoded\" -u \"test-client:test-secret\" -d \"grant_type=client_credentials&scope=roles:user&email=user@example.com\""
            ;;
        "create_credential")
            echo "curl -s -X POST \"http://localhost:9000/settings/credentials\" -H \"Authorization: Bearer <user-token>\" -H \"Content-Type: application/json\" -d '{\"name\": \"user-credential\", \"roles\": [\"user\"], \"description\": \"Credential for user role testing\"}'"
            ;;
        "list_buckets")
            echo "curl -s -X GET \"http://localhost:9000/s3/\" -H \"X-S3-Credential-AccessKey: <access-key>\" -H \"Authorization: Bearer <user-token>\""
            ;;
        "list_objects_nonexist")
            echo "curl -s -X GET \"http://localhost:9000/s3/test-bucket\" -H \"X-S3-Credential-AccessKey: <access-key>\" -H \"Authorization: Bearer <user-token>\""
            ;;
        "create_bucket")
            echo "curl -s -X POST \"http://localhost:9000/settings/buckets\" -H \"Authorization: Bearer <user-token>\" -H \"Content-Type: application/json\" -d '{\"name\": \"test-bucket\", \"description\": \"Test bucket for demonstration\"}'"
            ;;
        "list_objects_empty")
            echo "curl -s -X GET \"http://localhost:9000/s3/test-bucket\" -H \"X-S3-Credential-AccessKey: <access-key>\" -H \"Authorization: Bearer <user-token>\""
            ;;
        "upload_object")
            echo "curl -s -X PUT \"http://localhost:9000/s3/test-bucket/test-object.txt\" -H \"X-S3-Credential-AccessKey: <access-key>\" -H \"Authorization: Bearer <user-token>\" -H \"Content-Type: text/plain\" --data-binary @/tmp/test-object.txt"
            ;;
        "list_objects_after_upload")
            echo "curl -s -X GET \"http://localhost:9000/s3/test-bucket\" -H \"X-S3-Credential-AccessKey: <access-key>\" -H \"Authorization: Bearer <user-token>\""
            ;;
        "download_object")
            echo "curl -s \"http://localhost:9000/s3/test-bucket/test-object.txt\" -H \"X-S3-Credential-AccessKey: <access-key>\" -H \"Authorization: Bearer <user-token>\""
            ;;
    esac
}

# Extract actual outputs
ADMIN_TOKEN_JSON=$(extract_json "admin_token" "$DEMO_OUTPUT")
CREATE_ROLE_JSON=$(extract_json "create_role" "$DEMO_OUTPUT")
USER_TOKEN_JSON=$(extract_json "user_token" "$DEMO_OUTPUT")
CREATE_CREDENTIAL_JSON=$(extract_json "create_credential" "$DEMO_OUTPUT")
LIST_BUCKETS_JSON=$(extract_json "list_buckets" "$DEMO_OUTPUT")
LIST_OBJECTS_NONEXIST_JSON=$(extract_json "list_objects_nonexist" "$DEMO_OUTPUT")
CREATE_BUCKET_JSON=$(extract_json "create_bucket" "$DEMO_OUTPUT")
LIST_OBJECTS_EMPTY_JSON=$(extract_json "list_objects_empty" "$DEMO_OUTPUT")
UPLOAD_OBJECT_JSON=$(extract_json "upload_object" "$DEMO_OUTPUT")
LIST_OBJECTS_AFTER_UPLOAD_JSON=$(extract_json "list_objects_after_upload" "$DEMO_OUTPUT")
DOWNLOAD_OBJECT_JSON=$(extract_json "download_object" "$DEMO_OUTPUT")

# Extract commands
ADMIN_TOKEN_COMMAND=$(extract_command "admin_token" "$DEMO_OUTPUT")
CREATE_ROLE_COMMAND=$(extract_command "create_role" "$DEMO_OUTPUT")
USER_TOKEN_COMMAND=$(extract_command "user_token" "$DEMO_OUTPUT")
CREATE_CREDENTIAL_COMMAND=$(extract_command "create_credential" "$DEMO_OUTPUT")
LIST_BUCKETS_COMMAND=$(extract_command "list_buckets" "$DEMO_OUTPUT")
LIST_OBJECTS_NONEXIST_COMMAND=$(extract_command "list_objects_nonexist" "$DEMO_OUTPUT")
CREATE_BUCKET_COMMAND=$(extract_command "create_bucket" "$DEMO_OUTPUT")
LIST_OBJECTS_EMPTY_COMMAND=$(extract_command "list_objects_empty" "$DEMO_OUTPUT")
UPLOAD_OBJECT_COMMAND=$(extract_command "upload_object" "$DEMO_OUTPUT")
LIST_OBJECTS_AFTER_UPLOAD_COMMAND=$(extract_command "list_objects_after_upload" "$DEMO_OUTPUT")
DOWNLOAD_OBJECT_COMMAND=$(extract_command "download_object" "$DEMO_OUTPUT")

# Function to determine status based on actual output
get_status() {
    local section=$1
    local actual_json=$2

    case $section in
        "admin_token")
            # Check if admin token contains correct email and admin entitlement
            if echo "$actual_json" | grep -q '"email": "admin@example.com"' && echo "$actual_json" | grep -q '"admin"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "create_role")
            if echo "$actual_json" | jq -e '.error' >/dev/null 2>&1; then
                echo "❌ NOT OK"
            else
                echo "✅ OK"
            fi
            ;;
        "user_token")
            # Check if user token contains correct email and user entitlement
            if echo "$actual_json" | grep -q '"email": "user@example.com"' && echo "$actual_json" | grep -q '"user"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "create_credential")
            if echo "$actual_json" | jq -e '.credential.access_key' >/dev/null 2>&1; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "list_buckets")
            if echo "$actual_json" | jq -e '.error' >/dev/null 2>&1; then
                echo "❌ NOT OK"
            else
                echo "✅ OK"
            fi
            ;;
        "list_objects_nonexist")
            if echo "$actual_json" | jq -e '.bucket' >/dev/null 2>&1; then
                echo "⚠️ PARTIALLY OK"
            else
                echo "✅ OK"
            fi
            ;;
        "create_bucket")
            if echo "$actual_json" | jq -e '.bucket.name' >/dev/null 2>&1; then
                echo "⚠️ PARTIALLY OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "list_objects_empty")
            if echo "$actual_json" | jq -e '.count == 0' >/dev/null 2>&1; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "upload_object")
            if [[ "$actual_json" == *"✅ Upload successful"* ]]; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "list_objects_after_upload")
            if echo "$actual_json" | jq -e '.count == 1' >/dev/null 2>&1; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "download_object")
            if [[ "$actual_json" == *"Hello, S3 Gateway!"* ]]; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
    esac
}

# Get status for each section
ADMIN_TOKEN_STATUS=$(get_status "admin_token" "$ADMIN_TOKEN_JSON")
CREATE_ROLE_STATUS=$(get_status "create_role" "$CREATE_ROLE_JSON")
USER_TOKEN_STATUS=$(get_status "user_token" "$USER_TOKEN_JSON")
CREATE_CREDENTIAL_STATUS=$(get_status "create_credential" "$CREATE_CREDENTIAL_JSON")
LIST_BUCKETS_STATUS=$(get_status "list_buckets" "$LIST_BUCKETS_JSON")
LIST_OBJECTS_NONEXIST_STATUS=$(get_status "list_objects_nonexist" "$LIST_OBJECTS_NONEXIST_JSON")
CREATE_BUCKET_STATUS=$(get_status "create_bucket" "$CREATE_BUCKET_JSON")
LIST_OBJECTS_EMPTY_STATUS=$(get_status "list_objects_empty" "$LIST_OBJECTS_EMPTY_JSON")
UPLOAD_OBJECT_STATUS=$(get_status "upload_object" "$UPLOAD_OBJECT_JSON")
LIST_OBJECTS_AFTER_UPLOAD_STATUS=$(get_status "list_objects_after_upload" "$LIST_OBJECTS_AFTER_UPLOAD_JSON")
DOWNLOAD_OBJECT_STATUS=$(get_status "download_object" "$DOWNLOAD_OBJECT_JSON")

# Count statuses
CRITICAL_COUNT=$(echo "$ADMIN_TOKEN_STATUS $CREATE_ROLE_STATUS $USER_TOKEN_STATUS $LIST_BUCKETS_STATUS $LIST_OBJECTS_EMPTY_STATUS $LIST_OBJECTS_AFTER_UPLOAD_STATUS" | grep -o "❌ NOT OK" | wc -l)
PARTIAL_COUNT=$(echo "$LIST_OBJECTS_NONEXIST_STATUS $CREATE_BUCKET_STATUS" | grep -o "⚠️ PARTIALLY OK" | wc -l)
OK_COUNT=$(echo "$ADMIN_TOKEN_STATUS $USER_TOKEN_STATUS $CREATE_CREDENTIAL_STATUS $UPLOAD_OBJECT_STATUS $DOWNLOAD_OBJECT_STATUS" | grep -o "✅ OK" | wc -l)

# Export variables for envsubst
export CRITICAL_COUNT PARTIAL_COUNT OK_COUNT
export ADMIN_TOKEN_STATUS CREATE_ROLE_STATUS USER_TOKEN_STATUS CREATE_CREDENTIAL_STATUS
export LIST_BUCKETS_STATUS LIST_OBJECTS_NONEXIST_STATUS CREATE_BUCKET_STATUS
export LIST_OBJECTS_EMPTY_STATUS UPLOAD_OBJECT_STATUS LIST_OBJECTS_AFTER_UPLOAD_STATUS DOWNLOAD_OBJECT_STATUS
export ADMIN_TOKEN_JSON CREATE_ROLE_JSON USER_TOKEN_JSON CREATE_CREDENTIAL_JSON
export LIST_BUCKETS_JSON LIST_OBJECTS_NONEXIST_JSON CREATE_BUCKET_JSON
export LIST_OBJECTS_EMPTY_JSON UPLOAD_OBJECT_JSON LIST_OBJECTS_AFTER_UPLOAD_JSON DOWNLOAD_OBJECT_JSON
export ADMIN_TOKEN_COMMAND CREATE_ROLE_COMMAND USER_TOKEN_COMMAND CREATE_CREDENTIAL_COMMAND
export LIST_BUCKETS_COMMAND LIST_OBJECTS_NONEXIST_COMMAND CREATE_BUCKET_COMMAND
export LIST_OBJECTS_EMPTY_COMMAND UPLOAD_OBJECT_COMMAND LIST_OBJECTS_AFTER_UPLOAD_COMMAND DOWNLOAD_OBJECT_COMMAND
export DATE_STAMP="$(date)"

# Use envsubst to replace variables in the template
envsubst < "$TEMPLATE_FILE" > "$OUTPUT_FILE"

echo "✅ Gap analysis document generated: $OUTPUT_FILE"
echo "📊 Status: $CRITICAL_COUNT critical issues, $PARTIAL_COUNT partial issues, $OK_COUNT working steps"
