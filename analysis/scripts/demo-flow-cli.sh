#!/bin/bash

# S3 Gateway CLI Demonstration Script
# This script demonstrates the same flow as demo-flow.sh but using AWS CLI commands directly
# instead of calling the Gateway API

set -e  # Exit on any error

# Configuration - read from .env file
if [ -f "../../.env" ]; then
    source ../../.env
elif [ -f "../.env" ]; then
    source ../.env
elif [ -f ".env" ]; then
    source .env
else
    echo "❌ .env file not found. Please create it with your SURF credentials."
    exit 1
fi

S3_ENDPOINT="${S3_ENDPOINT:-https://object-acc.data.surf.nl}"
S3_REGION="${S3_REGION:-default}"
IAM_ACCESS_KEY="${IAM_ACCESS_KEY}"
IAM_SECRET_KEY="${IAM_SECRET_KEY}"

echo "🔧 S3 Gateway CLI Flow Demonstration"
echo "===================================="
echo "This script demonstrates the backend operations using AWS CLI directly"
echo

# Set up AWS CLI configuration
echo "1️⃣ Setting up AWS CLI Configuration"
echo "-----------------------------------"
export AWS_ACCESS_KEY_ID="$IAM_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$IAM_SECRET_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

# Create AWS config for custom endpoint
mkdir -p ~/.aws
cat > ~/.aws/config << EOF
[default]
region = $S3_REGION
endpoint_url = $S3_ENDPOINT
signature_version = s3v4
payload_signing_enabled = true
addressing_style = path
EOF

cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = $IAM_ACCESS_KEY
aws_secret_access_key = $IAM_SECRET_KEY
EOF

echo "✅ AWS CLI configured for SURF object store"
echo

echo "2️⃣ Creating IAM User"
echo "--------------------"
USER_NAME="demo-user-$(date +%s)"

echo "Creating IAM user: $USER_NAME"
aws iam create-user --user-name "$USER_NAME" --output json | jq .
echo "✅ IAM user created"
echo

echo "3️⃣ Creating Access Key for User"
echo "-------------------------------"
ACCESS_KEY_RESPONSE=$(aws iam create-access-key --user-name "$USER_NAME" --output json)
ACCESS_KEY=$(echo "$ACCESS_KEY_RESPONSE" | jq -r '.AccessKey.AccessKeyId')
SECRET_KEY=$(echo "$ACCESS_KEY_RESPONSE" | jq -r '.AccessKey.SecretAccessKey')

echo "✅ Access key created for user $USER_NAME"
echo "Access Key ID: $ACCESS_KEY"
echo

echo "4️⃣ Attaching Read-Write Policy to User"
echo "--------------------------------------"
# Create a temporary policy file
POLICY_FILE="/tmp/read-write-policy.json"
cat > "$POLICY_FILE" << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:CreateBucket"
            ],
            "Resource": "*"
        }
    ]
}
EOF

POLICY_NAME="${USER_NAME}-read-write-policy"
aws iam put-user-policy \
    --user-name "$USER_NAME" \
    --policy-name "$POLICY_NAME" \
    --policy-document "file://$POLICY_FILE" \
    --output json | jq .

echo "✅ Read-Write policy attached to user"
echo

echo "5️⃣ Testing S3 Operations with User Credentials"
echo "----------------------------------------------"
# Switch to user credentials for S3 operations
export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"

echo "5.1️⃣ Listing Buckets"
echo "-------------------"
echo "Command: aws s3api list-buckets --output json"
aws s3api list-buckets --output json | jq .
echo

echo "5.2️⃣ Creating a Test Bucket"
echo "---------------------------"
BUCKET_NAME="demo-bucket-$(date +%s)"

echo "Command: aws s3api create-bucket --bucket $BUCKET_NAME --output json"
aws s3api create-bucket --bucket "$BUCKET_NAME" --output json | jq .
echo "✅ Bucket created: $BUCKET_NAME"
echo

echo "5.3️⃣ Listing Objects in Bucket (should be empty)"
echo "------------------------------------------------"
echo "Command: aws s3api list-objects-v2 --bucket $BUCKET_NAME --output json"
aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --output json | jq .
echo

echo "5.4️⃣ Uploading a Test Object"
echo "----------------------------"
# Create a test file
echo "Hello, S3 CLI Demo!" > /tmp/cli-test-object.txt

echo "Command: aws s3api put-object --bucket $BUCKET_NAME --key test-object.txt --body /tmp/cli-test-object.txt --output json"
aws s3api put-object --bucket "$BUCKET_NAME" --key "test-object.txt" --body "/tmp/cli-test-object.txt" --output json | jq .
echo "✅ Object uploaded"
echo

echo "5.5️⃣ Listing Objects Again (should show the uploaded object)"
echo "-----------------------------------------------------------"
echo "Command: aws s3api list-objects-v2 --bucket $BUCKET_NAME --output json"
aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --output json | jq .
echo

echo "5.6️⃣ Downloading the Test Object"
echo "--------------------------------"
echo "Command: aws s3api get-object --bucket $BUCKET_NAME --key test-object.txt /tmp/downloaded-object.txt --output json"
aws s3api get-object --bucket "$BUCKET_NAME" --key "test-object.txt" "/tmp/downloaded-object.txt" --output json > /dev/null

echo "Downloaded content:"
cat /tmp/downloaded-object.txt
echo
echo "✅ Object downloaded successfully"
echo

echo "6️⃣ Cleanup Operations"
echo "---------------------"
# Switch back to admin credentials for cleanup
export AWS_ACCESS_KEY_ID="$IAM_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$IAM_SECRET_KEY"

echo "6.1️⃣ Deleting Test Object"
echo "-------------------------"
echo "Command: aws s3api delete-object --bucket $BUCKET_NAME --key test-object.txt --output json"
aws s3api delete-object --bucket "$BUCKET_NAME" --key "test-object.txt" --output json | jq .
echo "✅ Object deleted"
echo

echo "6.2️⃣ Deleting Test Bucket"
echo "-------------------------"
echo "Command: aws s3api delete-bucket --bucket $BUCKET_NAME --output json"
aws s3api delete-bucket --bucket "$BUCKET_NAME" --output json | jq .
echo "✅ Bucket deleted"
echo

echo "6.3️⃣ Removing User Policy"
echo "-------------------------"
echo "Command: aws iam delete-user-policy --user-name $USER_NAME --policy-name $POLICY_NAME --output json"
aws iam delete-user-policy --user-name "$USER_NAME" --policy-name "$POLICY_NAME" --output json | jq .
echo "✅ User policy removed"
echo

echo "6.4️⃣ Deleting Access Key"
echo "------------------------"
echo "Command: aws iam delete-access-key --user-name $USER_NAME --access-key-id $ACCESS_KEY --output json"
aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$ACCESS_KEY" --output json | jq .
echo "✅ Access key deleted"
echo

echo "6.5️⃣ Deleting IAM User"
echo "----------------------"
echo "Command: aws iam delete-user --user-name $USER_NAME --output json"
aws iam delete-user --user-name "$USER_NAME" --output json | jq .
echo "✅ IAM user deleted"
echo

echo "🎉 CLI Flow Demonstration Finished!"
echo "==================================="
echo
echo "Summary:"
echo "- ✅ Configured AWS CLI for SURF object store"
echo "- ✅ Created IAM user: $USER_NAME"
echo "- ✅ Created access key for user"
echo "- ✅ Attached Read-Write policy to user"
echo "- ✅ Listed buckets"
echo "- ✅ Created bucket: $BUCKET_NAME"
echo "- ✅ Listed objects (empty then with object)"
echo "- ✅ Uploaded test object"
echo "- ✅ Downloaded test object"
echo "- ✅ Cleaned up all resources"
echo
echo "The AWS CLI operations work correctly with SURF object store!"
echo "This demonstrates the backend operations that the S3 Gateway performs."