#!/bin/bash

# Generate CLI Demo Flow Analysis Script
# This script runs demo-flow-cli.sh and automatically generates the gap analysis document

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_SCRIPT="$SCRIPT_DIR/demo-flow-cli.sh"
TEMPLATE_FILE="$SCRIPT_DIR/../templates/demo-flow-cli-template.md"
OUTPUT_FILE="$SCRIPT_DIR/../output/demo-flow-cli.md"

echo "🔄 Running demo-flow-cli.sh and generating gap analysis..."

# Run the demo script and capture all output
DEMO_OUTPUT=$(bash "$DEMO_SCRIPT" 2>&1)
DEMO_EXIT_CODE=$?

if [ $DEMO_EXIT_CODE -ne 0 ]; then
    echo "❌ Demo script failed with exit code $DEMO_EXIT_CODE"
    echo "Demo output:"
    echo "$DEMO_OUTPUT"
    exit 1
fi

echo "✅ Demo script completed successfully"

# Function to extract JSON from demo output
extract_json() {
    local section=$1
    local output="$2"

    # Extract the JSON response for a specific section
    case $section in
        "create_user")
            echo "$output" | sed -n '/Creating IAM user:/,/✅ IAM user created/p' | grep -A 10 "{" | head -10 | jq . 2>/dev/null || echo "$output" | sed -n '/Creating IAM user:/,/✅ IAM user created/p' | grep -A 10 "{" | head -10
            ;;
        "create_access_key")
            echo "$output" | sed -n '/3️⃣ Creating Access Key/,/✅ Access key created/p' | grep -A 15 "{" | head -15 | jq . 2>/dev/null || echo "$output" | sed -n '/3️⃣ Creating Access Key/,/✅ Access key created/p' | grep -A 15 "{" | head -15
            ;;
        "put_user_policy")
            # Check if policy attachment succeeded
            if echo "$output" | grep -q "✅ Policy attached successfully"; then
                echo '"✅ Policy attached successfully"'
            else
                echo '"❌ Policy attachment failed"'
            fi
            ;;
        "list_buckets")
            echo "$output" | sed -n '/5️⃣ Listing Buckets/,/✅ Listed buckets/p' | grep -A 10 "{" | head -10 | jq . 2>/dev/null || echo "$output" | sed -n '/5️⃣ Listing Buckets/,/✅ Listed buckets/p' | grep -A 10 "{" | head -10
            ;;
        "create_bucket")
            echo "$output" | sed -n '/6️⃣ Creating Bucket/,/✅ Bucket created/p' | grep -A 5 "{" | head -5 | jq . 2>/dev/null || echo "$output" | sed -n '/6️⃣ Creating Bucket/,/✅ Bucket created/p' | grep -A 5 "{" | head -5
            ;;
        "list_objects_empty")
            echo "$output" | sed -n '/7️⃣ Listing Objects/,/✅ Listed objects/p' | grep -A 10 "{" | head -10 | jq . 2>/dev/null || echo "$output" | sed -n '/7️⃣ Listing Objects/,/✅ Listed objects/p' | grep -A 10 "{" | head -10
            ;;
        "put_object")
            echo "$output" | sed -n '/8️⃣ Uploading Object/,/✅ Object uploaded/p' | grep -A 5 "{" | head -5 | jq . 2>/dev/null || echo "$output" | sed -n '/8️⃣ Uploading Object/,/✅ Object uploaded/p' | grep -A 5 "{" | head -5
            ;;
        "list_objects_with_content")
            echo "$output" | sed -n '/9️⃣ Listing Objects/,/✅ Listed objects/p' | grep -A 15 "{" | head -15 | jq . 2>/dev/null || echo "$output" | sed -n '/9️⃣ Listing Objects/,/✅ Listed objects/p' | grep -A 15 "{" | head -15
            ;;
        "get_object")
            # Check if download succeeded
            if echo "$output" | grep -q "Hello, S3 CLI!"; then
                echo '"Hello, S3 CLI!"'
            else
                echo '"❌ Download failed"'
            fi
            ;;
        "delete_object")
            echo "$output" | sed -n '/🔟 Deleting Object/,/✅ Object deleted/p' | grep -A 5 "{" | head -5 | jq . 2>/dev/null || echo "$output" | sed -n '/🔟 Deleting Object/,/✅ Object deleted/p' | grep -A 5 "{" | head -5
            ;;
        "delete_bucket")
            echo "$output" | sed -n '/1️⃣1️⃣ Deleting Bucket/,/✅ Bucket deleted/p' | grep -A 5 "{" | head -5 | jq . 2>/dev/null || echo "$output" | sed -n '/1️⃣1️⃣ Deleting Bucket/,/✅ Bucket deleted/p' | grep -A 5 "{" | head -5
            ;;
        "delete_user_policy")
            # Check if policy deletion succeeded
            if echo "$output" | grep -q "✅ Policy deleted successfully"; then
                echo '"✅ Policy deleted successfully"'
            else
                echo '"❌ Policy deletion failed"'
            fi
            ;;
        "delete_access_key")
            # Check if access key deletion succeeded
            if echo "$output" | grep -q "✅ Access key deleted successfully"; then
                echo '"✅ Access key deleted successfully"'
            else
                echo '"❌ Access key deletion failed"'
            fi
            ;;
        "delete_user")
            echo "$output" | sed -n '/1️⃣4️⃣ Deleting IAM User/,/✅ User deleted/p' | grep -A 5 "{" | head -5 | jq . 2>/dev/null || echo "$output" | sed -n '/1️⃣4️⃣ Deleting IAM User/,/✅ User deleted/p' | grep -A 5 "{" | head -5
            ;;
    esac
}

# Function to extract commands from demo output
extract_command() {
    local section=$1
    local output="$2"

    # Extract the command for a specific section
    case $section in
        "create_user")
            # Construct the command from the output
            local username=$(echo "$output" | grep "Creating IAM user:" | sed 's/.*Creating IAM user: //' | tr -d '\n')
            echo "aws iam create-user --user-name $username --output json"
            ;;
        "create_access_key")
            # Construct the command from the output
            local username=$(echo "$output" | grep "Creating IAM user:" | sed 's/.*Creating IAM user: //' | tr -d '\n')
            echo "aws iam create-access-key --user-name $username --output json"
            ;;
        "put_user_policy")
            # Construct the command from the output
            local username=$(echo "$output" | grep "Creating IAM user:" | sed 's/.*Creating IAM user: //' | tr -d '\n')
            echo "aws iam put-user-policy --user-name $username --policy-name ${username}-read-write-policy --policy-document file:///tmp/read-write-policy.json"
            ;;
        "list_buckets")
            echo "$output" | grep "Command: aws s3api list-buckets" | sed 's/Command: //' | head -1 || echo "aws s3api list-buckets --output json"
            ;;
        "create_bucket")
            echo "$output" | grep "Command: aws s3api create-bucket" | sed 's/Command: //' | head -1 || echo "aws s3api create-bucket --bucket <bucket-name> --output json"
            ;;
        "list_objects_empty")
            echo "$output" | grep -A 2 "5.3️⃣ Listing Objects" | grep "Command: aws s3api list-objects" | sed 's/Command: //' | head -1 || echo "aws s3api list-objects-v2 --bucket <bucket-name> --output json"
            ;;
        "put_object")
            echo "$output" | grep "Command: aws s3api put-object" | sed 's/Command: //' | head -1 || echo "aws s3api put-object --bucket <bucket-name> --key <key> --body <file> --output json"
            ;;
        "list_objects_with_content")
            echo "$output" | grep -A 2 "5.5️⃣ Listing Objects" | grep "Command: aws s3api list-objects" | sed 's/Command: //' | head -1 || echo "aws s3api list-objects-v2 --bucket <bucket-name> --output json"
            ;;
        "get_object")
            echo "$output" | grep "Command: aws s3api get-object" | sed 's/Command: //' | head -1 || echo "aws s3api get-object --bucket <bucket-name> --key <key> <output-file>"
            ;;
        "delete_object")
            echo "$output" | grep "Command: aws s3api delete-object" | sed 's/Command: //' | head -1 || echo "aws s3api delete-object --bucket <bucket-name> --key <key> --output json"
            ;;
        "delete_bucket")
            echo "$output" | grep "Command: aws s3api delete-bucket" | sed 's/Command: //' | head -1 || echo "aws s3api delete-bucket --bucket <bucket-name> --output json"
            ;;
        "delete_user_policy")
            echo "$output" | grep "Command: aws iam delete-user-policy" | sed 's/Command: //' | head -1 || echo "aws iam delete-user-policy --user-name <username> --policy-name <policy-name> --output json"
            ;;
        "delete_access_key")
            echo "$output" | grep "Command: aws iam delete-access-key" | sed 's/Command: //' | head -1 || echo "aws iam delete-access-key --user-name <username> --access-key-id <access-key-id> --output json"
            ;;
        "delete_user")
            echo "$output" | grep "Command: aws iam delete-user" | sed 's/Command: //' | head -1 || echo "aws iam delete-user --user-name <username> --output json"
            ;;
    esac
}

# Extract actual outputs
CREATE_USER_JSON=$(extract_json "create_user" "$DEMO_OUTPUT")
CREATE_ACCESS_KEY_JSON=$(extract_json "create_access_key" "$DEMO_OUTPUT")
PUT_USER_POLICY_JSON=$(extract_json "put_user_policy" "$DEMO_OUTPUT")
LIST_BUCKETS_JSON=$(extract_json "list_buckets" "$DEMO_OUTPUT")
CREATE_BUCKET_JSON=$(extract_json "create_bucket" "$DEMO_OUTPUT")
LIST_OBJECTS_EMPTY_JSON=$(extract_json "list_objects_empty" "$DEMO_OUTPUT")
PUT_OBJECT_JSON=$(extract_json "put_object" "$DEMO_OUTPUT")
LIST_OBJECTS_WITH_CONTENT_JSON=$(extract_json "list_objects_with_content" "$DEMO_OUTPUT")
GET_OBJECT_JSON=$(extract_json "get_object" "$DEMO_OUTPUT")
DELETE_OBJECT_JSON=$(extract_json "delete_object" "$DEMO_OUTPUT")
DELETE_BUCKET_JSON=$(extract_json "delete_bucket" "$DEMO_OUTPUT")
DELETE_USER_POLICY_JSON=$(extract_json "delete_user_policy" "$DEMO_OUTPUT")
DELETE_ACCESS_KEY_JSON=$(extract_json "delete_access_key" "$DEMO_OUTPUT")
DELETE_USER_JSON=$(extract_json "delete_user" "$DEMO_OUTPUT")

# Extract commands
CREATE_USER_COMMAND=$(extract_command "create_user" "$DEMO_OUTPUT")
CREATE_ACCESS_KEY_COMMAND=$(extract_command "create_access_key" "$DEMO_OUTPUT")
PUT_USER_POLICY_COMMAND=$(extract_command "put_user_policy" "$DEMO_OUTPUT")
LIST_BUCKETS_COMMAND=$(extract_command "list_buckets" "$DEMO_OUTPUT")
CREATE_BUCKET_COMMAND=$(extract_command "create_bucket" "$DEMO_OUTPUT")
LIST_OBJECTS_EMPTY_COMMAND=$(extract_command "list_objects_empty" "$DEMO_OUTPUT")
PUT_OBJECT_COMMAND=$(extract_command "put_object" "$DEMO_OUTPUT")
LIST_OBJECTS_WITH_CONTENT_COMMAND=$(extract_command "list_objects_with_content" "$DEMO_OUTPUT")
GET_OBJECT_COMMAND=$(extract_command "get_object" "$DEMO_OUTPUT")
DELETE_OBJECT_COMMAND=$(extract_command "delete_object" "$DEMO_OUTPUT")
DELETE_BUCKET_COMMAND=$(extract_command "delete_bucket" "$DEMO_OUTPUT")
DELETE_USER_POLICY_COMMAND=$(extract_command "delete_user_policy" "$DEMO_OUTPUT")
DELETE_ACCESS_KEY_COMMAND=$(extract_command "delete_access_key" "$DEMO_OUTPUT")
DELETE_USER_COMMAND=$(extract_command "delete_user" "$DEMO_OUTPUT")

# Function to determine status based on actual output
get_status() {
    local section=$1
    local actual_json=$2

    case $section in
        "create_user")
            if echo "$actual_json" | grep -q '"User"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "create_access_key")
            if echo "$actual_json" | grep -q '"AccessKey"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "put_user_policy")
            if [[ "$actual_json" == *"✅ Policy attached successfully"* ]]; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "list_buckets")
            if echo "$actual_json" | grep -q '"Buckets"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "create_bucket")
            if echo "$actual_json" | grep -q '"Location"'; then
                echo "✅ OK"
            else
                echo "⚠️ PARTIALLY OK"
            fi
            ;;
        "list_objects_empty")
            if echo "$actual_json" | grep -q '"Contents"' && echo "$actual_json" | grep -q '"Key"'; then
                echo "❌ NOT OK"
            else
                echo "✅ OK"
            fi
            ;;
        "put_object")
            if echo "$actual_json" | grep -q '"ETag"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "list_objects_with_content")
            if echo "$actual_json" | grep -q '"Contents"' && echo "$actual_json" | grep -q '"test-object.txt"'; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "get_object")
            if [[ "$actual_json" == *"Hello, S3 CLI!"* ]]; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "delete_object")
            # Delete operations often return empty or minimal responses
            if echo "$actual_json" | grep -q "{}" || echo "$actual_json" | grep -q '"delete"'; then
                echo "✅ OK"
            else
                echo "⚠️ PARTIALLY OK"
            fi
            ;;
        "delete_bucket")
            if echo "$actual_json" | grep -q "{}" || echo "$actual_json" | grep -q '"delete"'; then
                echo "✅ OK"
            else
                echo "⚠️ PARTIALLY OK"
            fi
            ;;
        "delete_user_policy")
            if [[ "$actual_json" == *"✅ Policy deleted successfully"* ]]; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "delete_access_key")
            if [[ "$actual_json" == *"✅ Access key deleted successfully"* ]]; then
                echo "✅ OK"
            else
                echo "❌ NOT OK"
            fi
            ;;
        "delete_user")
            if echo "$actual_json" | grep -q "{}" || echo "$actual_json" | grep -q '"delete"'; then
                echo "✅ OK"
            else
                echo "⚠️ PARTIALLY OK"
            fi
            ;;
    esac
}

# Get status for each section
CREATE_USER_STATUS=$(get_status "create_user" "$CREATE_USER_JSON")
CREATE_ACCESS_KEY_STATUS=$(get_status "create_access_key" "$CREATE_ACCESS_KEY_JSON")
PUT_USER_POLICY_STATUS=$(get_status "put_user_policy" "$PUT_USER_POLICY_JSON")
LIST_BUCKETS_STATUS=$(get_status "list_buckets" "$LIST_BUCKETS_JSON")
CREATE_BUCKET_STATUS=$(get_status "create_bucket" "$CREATE_BUCKET_JSON")
LIST_OBJECTS_EMPTY_STATUS=$(get_status "list_objects_empty" "$LIST_OBJECTS_EMPTY_JSON")
PUT_OBJECT_STATUS=$(get_status "put_object" "$PUT_OBJECT_JSON")
LIST_OBJECTS_WITH_CONTENT_STATUS=$(get_status "list_objects_with_content" "$LIST_OBJECTS_WITH_CONTENT_JSON")
GET_OBJECT_STATUS=$(get_status "get_object" "$GET_OBJECT_JSON")
DELETE_OBJECT_STATUS=$(get_status "delete_object" "$DELETE_OBJECT_JSON")
DELETE_BUCKET_STATUS=$(get_status "delete_bucket" "$DELETE_BUCKET_JSON")
DELETE_USER_POLICY_STATUS=$(get_status "delete_user_policy" "$DELETE_USER_POLICY_JSON")
DELETE_ACCESS_KEY_STATUS=$(get_status "delete_access_key" "$DELETE_ACCESS_KEY_JSON")
DELETE_USER_STATUS=$(get_status "delete_user" "$DELETE_USER_JSON")

# Count statuses
CRITICAL_COUNT=$(echo "$LIST_BUCKETS_STATUS $LIST_OBJECTS_EMPTY_STATUS $LIST_OBJECTS_WITH_CONTENT_STATUS" | grep -o "❌ NOT OK" | wc -l)
PARTIAL_COUNT=$(echo "$CREATE_BUCKET_STATUS $DELETE_OBJECT_STATUS $DELETE_BUCKET_STATUS $DELETE_USER_STATUS" | grep -o "⚠️ PARTIALLY OK" | wc -l)
OK_COUNT=$(echo "$CREATE_USER_STATUS $CREATE_ACCESS_KEY_STATUS $PUT_USER_POLICY_STATUS $PUT_OBJECT_STATUS $GET_OBJECT_STATUS $DELETE_USER_POLICY_STATUS $DELETE_ACCESS_KEY_STATUS" | grep -o "✅ OK" | wc -l)

# Export variables for envsubst
export CRITICAL_COUNT PARTIAL_COUNT OK_COUNT
export CREATE_USER_STATUS CREATE_ACCESS_KEY_STATUS PUT_USER_POLICY_STATUS
export LIST_BUCKETS_STATUS CREATE_BUCKET_STATUS LIST_OBJECTS_EMPTY_STATUS
export PUT_OBJECT_STATUS LIST_OBJECTS_WITH_CONTENT_STATUS GET_OBJECT_STATUS
export DELETE_OBJECT_STATUS DELETE_BUCKET_STATUS DELETE_USER_POLICY_STATUS
export DELETE_ACCESS_KEY_STATUS DELETE_USER_STATUS
export CREATE_USER_JSON CREATE_ACCESS_KEY_JSON PUT_USER_POLICY_JSON
export LIST_BUCKETS_JSON CREATE_BUCKET_JSON LIST_OBJECTS_EMPTY_JSON
export PUT_OBJECT_JSON LIST_OBJECTS_WITH_CONTENT_JSON GET_OBJECT_JSON
export DELETE_OBJECT_JSON DELETE_BUCKET_JSON DELETE_USER_POLICY_JSON
export DELETE_ACCESS_KEY_JSON DELETE_USER_JSON
export CREATE_USER_COMMAND CREATE_ACCESS_KEY_COMMAND PUT_USER_POLICY_COMMAND
export LIST_BUCKETS_COMMAND CREATE_BUCKET_COMMAND LIST_OBJECTS_EMPTY_COMMAND
export PUT_OBJECT_COMMAND LIST_OBJECTS_WITH_CONTENT_COMMAND GET_OBJECT_COMMAND
export DELETE_OBJECT_COMMAND DELETE_BUCKET_COMMAND DELETE_USER_POLICY_COMMAND
export DELETE_ACCESS_KEY_COMMAND DELETE_USER_COMMAND
export DATE_STAMP="$(date)"

# Use envsubst to replace variables in the template
envsubst < "$TEMPLATE_FILE" > "$OUTPUT_FILE"

echo "✅ CLI gap analysis document generated: $OUTPUT_FILE"
echo "📊 Status: $CRITICAL_COUNT critical issues, $PARTIAL_COUNT partial issues, $OK_COUNT working steps"