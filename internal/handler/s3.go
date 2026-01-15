package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/harrykodden/s3-gateway/internal/policy"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// S3Handler handles S3 proxy requests
type S3Handler struct {
	s3Client     *s3client.Client // Root client for admin operations only
	s3Config     config.S3Config  // S3 configuration for endpoint/region
	credStore    *store.CredentialStore
	policyEngine *policy.Engine
	logger       *logrus.Logger
}

// NewS3Handler creates a new S3 handler
func NewS3Handler(client *s3client.Client, s3Cfg config.S3Config, credStore *store.CredentialStore, policyEngine *policy.Engine, logger *logrus.Logger) *S3Handler {
	return &S3Handler{
		s3Client:     client,
		s3Config:     s3Cfg,
		credStore:    credStore,
		policyEngine: policyEngine,
		logger:       logger,
	}
}

// createUserS3Client creates an S3 client using user's delegated credentials
func (h *S3Handler) createUserS3Client(ctx context.Context, cred *store.Credential) (*s3.Client, error) {
	// Load AWS config with user's delegated credentials
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(h.s3Config.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cred.AccessKey,
			cred.SecretKey,
			cred.SessionToken,
		)),
	}

	// Add custom endpoint resolver for non-AWS S3
	if h.s3Config.Endpoint != "" && h.s3Config.Endpoint != "https://s3.amazonaws.com" {
		loadOpts = append(loadOpts, awsconfig.WithEndpointResolver(aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			if service == "S3" {
				return aws.Endpoint{
					URL:           h.s3Config.Endpoint,
					SigningRegion: h.s3Config.Region,
				}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config with user credentials: %w", err)
	}

	// Create S3 client with path style
	s3ClientOpts := func(o *s3.Options) {
		o.UsePathStyle = h.s3Config.ForcePathStyle
	}

	return s3.NewFromConfig(awsCfg, s3ClientOpts), nil
}

// getActionFromMethod converts HTTP method and path to S3 action
func (h *S3Handler) getActionFromMethod(method, bucket, key string) string {
	switch method {
	case http.MethodGet:
		if key == "" {
			return "s3:ListBucket"
		}
		return "s3:GetObject"
	case http.MethodPut:
		return "s3:PutObject"
	case http.MethodDelete:
		if key == "" {
			return "s3:DeleteBucket"
		}
		return "s3:DeleteObject"
	case http.MethodHead:
		return "s3:GetObject"
	case http.MethodPost:
		// POST can be used for various operations, default to ListBucket
		return "s3:ListBucket"
	default:
		return "s3:GetObject"
	}
}

// ProxyRequest proxies S3 requests after authorization
func (h *S3Handler) ProxyRequest(c *gin.Context) {
	startTime := time.Now()

	// Extract user info from context (set by OIDC auth middleware)
	userInfoValue, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userInfo := userInfoValue.(*auth.UserInfo)

	// Get selected credential from header
	accessKey := c.GetHeader("X-S3-Credential-AccessKey")
	if accessKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing X-S3-Credential-AccessKey header",
			"hint":  "Select a credential in the UI before performing S3 operations",
		})
		return
	}

	// Get credential from store
	cred, err := h.credStore.Get(accessKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
		return
	}

	// Validate credential belongs to authenticated user
	if cred.UserID != userInfo.Email {
		h.logger.WithFields(logrus.Fields{
			"user_email":   userInfo.Email,
			"cred_user_id": cred.UserID,
			"access_key":   accessKey,
			"user_subject": userInfo.Subject,
			"user_roles":   userInfo.Roles,
		}).Warn("User attempted to use credential belonging to another user")
		c.JSON(http.StatusForbidden, gin.H{"error": "Credential does not belong to you"})
		return
	}

	// Parse S3 path: /{bucket}/{key...}
	proxyPath := c.Param("proxyPath")
	proxyPath = strings.TrimPrefix(proxyPath, "/")

	parts := strings.SplitN(proxyPath, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid S3 path"})
		return
	}

	bucket := parts[0]
	key := ""
	if len(parts) > 1 {
		key = parts[1]
	}

	// Log the request
	h.logger.WithFields(logrus.Fields{
		"user":       userInfo.Subject,
		"email":      userInfo.Email,
		"access_key": accessKey,
		"cred_name":  cred.Name,
		"roles":      userInfo.Roles,
		"method":     c.Request.Method,
		"bucket":     bucket,
		"key":        key,
		"duration":   time.Since(startTime).Milliseconds(),
	}).Info("S3 request with policy enforcement - using admin credentials for backend")

	// Evaluate policies for this request
	action := h.getActionFromMethod(c.Request.Method, bucket, key)
	resource := fmt.Sprintf("arn:aws:s3:::%s", bucket)
	if key != "" {
		resource = fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, key)
	}

	policyCtx := &policy.EvaluationContext{
		Action:   action,
		Bucket:   bucket,
		Key:      key,
		Resource: resource,
		UserID:   userInfo.Email,
		Roles:    userInfo.Roles,
	}

	decision := h.policyEngine.Evaluate(policyCtx)
	if !decision.Allowed {
		h.logger.WithFields(logrus.Fields{
			"user":     userInfo.Email,
			"action":   action,
			"resource": resource,
			"reason":   decision.Reason,
		}).Warn("Policy evaluation denied S3 operation")
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "Access denied",
			"reason": decision.Reason,
		})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user":     userInfo.Email,
		"action":   action,
		"resource": resource,
		"allowed":  true,
	}).Debug("Policy evaluation allowed S3 operation")

	// Always use root S3 client with admin credentials for backend operations
	// (SURF and other S3-compatible services may not support IAM user credentials)
	s3Client := h.s3Client.GetClient()

	h.logger.WithFields(logrus.Fields{
		"access_key": accessKey,
		"cred_name":  cred.Name,
	}).Debug("Using root S3 client with admin credentials for backend operation")

	// Proxy the request to S3
	h.proxyToS3(c, s3Client, bucket, key, userInfo)
}

// proxyToS3 forwards the request to S3 using the provided client
func (h *S3Handler) proxyToS3(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
	method := c.Request.Method

	switch method {
	case http.MethodGet:
		h.handleGet(c, s3Client, bucket, key)
	case http.MethodPut:
		h.handlePut(c, s3Client, bucket, key)
	case http.MethodDelete:
		h.handleDelete(c, s3Client, bucket, key)
	case http.MethodHead:
		h.handleHead(c, s3Client, bucket, key)
	case http.MethodPost:
		h.handlePost(c, s3Client, bucket, key)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

// handleGet handles GET requests (download)
func (h *S3Handler) handleGet(c *gin.Context, s3Client *s3.Client, bucket, key string) {
	if key == "" {
		// List objects in bucket
		h.handleListObjects(c, s3Client, bucket)
		return
	}

	// Get object
	ctx := c.Request.Context()
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		h.logger.WithError(err).Error("Failed to get object from S3")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get object"})
		return
	}
	defer func() {
		if err := result.Body.Close(); err != nil {
			h.logger.WithError(err).Warn("Failed to close S3 object body")
		}
	}()

	// Set headers
	if result.ContentType != nil {
		c.Header("Content-Type", *result.ContentType)
	}
	if result.ContentLength != nil {
		c.Header("Content-Length", fmt.Sprintf("%d", *result.ContentLength))
	}
	if result.ETag != nil {
		c.Header("ETag", *result.ETag)
	}
	if result.LastModified != nil {
		c.Header("Last-Modified", result.LastModified.Format(http.TimeFormat))
	}

	// Copy body
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, result.Body); err != nil {
		h.logger.WithError(err).Error("Failed to copy S3 object to response")
	}
}

// handlePut handles PUT requests (upload)
func (h *S3Handler) handlePut(c *gin.Context, s3Client *s3.Client, bucket, key string) {
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Key is required for PUT"})
		return
	}

	// Read request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	// Upload to S3
	ctx := c.Request.Context()
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(c.GetHeader("Content-Type")),
	})

	if err != nil {
		h.logger.WithError(err).Error("Failed to put object to S3")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload object"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "uploaded"})
}

// handleDelete handles DELETE requests
func (h *S3Handler) handleDelete(c *gin.Context, s3Client *s3.Client, bucket, key string) {
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Key is required for DELETE"})
		return
	}

	ctx := c.Request.Context()
	_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		h.logger.WithError(err).Error("Failed to delete object from S3")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete object"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// handleHead handles HEAD requests
func (h *S3Handler) handleHead(c *gin.Context, s3Client *s3.Client, bucket, key string) {
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Key is required for HEAD"})
		return
	}

	ctx := c.Request.Context()
	result, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		h.logger.WithError(err).Error("Failed to head object from S3")
		c.Status(http.StatusNotFound)
		return
	}

	// Set headers
	if result.ContentType != nil {
		c.Header("Content-Type", *result.ContentType)
	}
	if result.ContentLength != nil {
		c.Header("Content-Length", fmt.Sprintf("%d", *result.ContentLength))
	}
	if result.ETag != nil {
		c.Header("ETag", *result.ETag)
	}
	if result.LastModified != nil {
		c.Header("Last-Modified", result.LastModified.Format(http.TimeFormat))
	}

	c.Status(http.StatusOK)
}

// handlePost handles POST requests (multipart upload initiation, etc.)
func (h *S3Handler) handlePost(c *gin.Context, s3Client *s3.Client, bucket, key string) {
	// For simplicity, we'll return not implemented
	// You can extend this to handle multipart uploads
	c.JSON(http.StatusNotImplemented, gin.H{"error": "POST operations not yet implemented"})
}

// handleListObjects lists objects in a bucket
func (h *S3Handler) handleListObjects(c *gin.Context, s3Client *s3.Client, bucket string) {
	prefix := c.Query("prefix")
	delimiter := c.Query("delimiter")

	ctx := c.Request.Context()
	result, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String(delimiter),
	})

	if err != nil {
		h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to list objects from S3")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list objects"})
		return
	}

	// Build response
	objects := make([]map[string]interface{}, 0)
	for _, obj := range result.Contents {
		objects = append(objects, map[string]interface{}{
			"key":           *obj.Key,
			"size":          *obj.Size,
			"last_modified": obj.LastModified.Format(time.RFC3339),
			"etag":          *obj.ETag,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"bucket":  bucket,
		"prefix":  prefix,
		"objects": objects,
		"count":   len(objects),
	})
}
