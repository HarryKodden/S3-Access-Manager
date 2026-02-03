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
	groupStore   *store.GroupStore
	userStore    *store.UserStore
	policyEngine *policy.Engine
	logger       *logrus.Logger
}

// NewS3Handler creates a new S3 handler
func NewS3Handler(client *s3client.Client, s3Cfg config.S3Config, credStore *store.CredentialStore, groupStore *store.GroupStore, userStore *store.UserStore, policyEngine *policy.Engine, logger *logrus.Logger) *S3Handler {
	return &S3Handler{
		s3Client:     client,
		s3Config:     s3Cfg,
		credStore:    credStore,
		groupStore:   groupStore,
		userStore:    userStore,
		policyEngine: policyEngine,
		logger:       logger,
	}
}

// CreateUserS3Client creates an S3 client using user's delegated credentials
func (h *S3Handler) CreateUserS3Client(ctx context.Context, cred *store.Credential) (*s3.Client, error) {
	// For S3 operations, use admin credentials since user access keys may not be valid on remote backends
	// The policy enforcement happens at the gateway level, not at the S3 backend level
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(h.s3Config.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			h.s3Config.IAM.AccessKey, // Use admin access key for S3 operations
			h.s3Config.IAM.SecretKey, // Use admin secret key for S3 operations
			"",
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

	// Extract user info from context (set by auth middleware)
	userInfoValue, exists := c.Get("userInfo")
	if !exists {
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusUnauthorized, gin.H{
			"Error": gin.H{
				"Code":    "AccessDenied",
				"Message": "Unauthorized",
			},
		})
		return
	}
	userInfo := userInfoValue.(*auth.UserInfo)

	// Get selected credential - check context first (for access key auth), then header (for OIDC auth)
	var cred *store.Credential
	var accessKey string

	// Check if credential was set by access key authentication
	selectedCredValue, hasSelectedCred := c.Get("selectedCredential")
	if hasSelectedCred {
		cred = selectedCredValue.(*store.Credential)
		accessKey = cred.AccessKey
		h.logger.WithFields(logrus.Fields{
			"user":        userInfo.Subject,
			"email":       userInfo.Email,
			"access_key":  accessKey,
			"auth_method": "access_key",
		}).Debug("Using credential from access key authentication")
	} else {
		// Fall back to header-based credential selection (OIDC auth)
		accessKey = c.GetHeader("X-S3-Credential-AccessKey")
		if accessKey == "" {
			c.Header("Content-Type", "application/xml")
			c.XML(http.StatusBadRequest, gin.H{
				"Error": gin.H{
					"Code":    "InvalidRequest",
					"Message": "Missing X-S3-Credential-AccessKey header",
				},
			})
			return
		}

		// Get credential from store
		var err error
		cred, err = h.credStore.Get(accessKey)
		if err != nil {
			c.Header("Content-Type", "application/xml")
			c.XML(http.StatusNotFound, gin.H{
				"Error": gin.H{
					"Code":    "InvalidAccessKeyId",
					"Message": "Credential not found",
				},
			})
			return
		}

		// Validate credential belongs to authenticated user
		if cred.UserID != userInfo.Email {
			h.logger.WithFields(logrus.Fields{
				"user_email":   userInfo.Email,
				"cred_user_id": cred.UserID,
				"access_key":   accessKey,
				"user_subject": userInfo.Subject,
				"user_groups":  userInfo.Groups,
			}).Warn("User attempted to use credential belonging to another user")
			c.Header("Content-Type", "application/xml")
			c.XML(http.StatusForbidden, gin.H{
				"Error": gin.H{
					"Code":    "AccessDenied",
					"Message": "Credential does not belong to you",
				},
			})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"user":        userInfo.Subject,
			"email":       userInfo.Email,
			"access_key":  accessKey,
			"auth_method": "oidc",
		}).Debug("Using credential from header selection")
	}

	// Parse S3 path: /{bucket}/{key...}
	proxyPath := c.Param("proxyPath")
	proxyPath = strings.TrimPrefix(proxyPath, "/")

	parts := strings.SplitN(proxyPath, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusBadRequest, gin.H{
			"Error": gin.H{
				"Code":    "InvalidBucketName",
				"Message": "Invalid S3 path",
			},
		})
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
		"groups":     userInfo.Groups,
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

	// Resolve user's groups to applicable policies
	applicablePolicies := make([]string, 0)
	for _, groupName := range userInfo.Groups {
		// Group name is now the SCIM group ID
		scimGroupId := groupName

		if scimGroupId != "" {
			group, err := h.groupStore.Get(scimGroupId)
			if err != nil {
				h.logger.WithError(err).WithField("group", groupName).Warn("Failed to get group definition")
				continue
			}
			applicablePolicies = append(applicablePolicies, group.Policies...)
		}
	}

	policyCtx := &policy.EvaluationContext{
		Action:   action,
		Bucket:   bucket,
		Key:      key,
		Resource: resource,
		UserID:   userInfo.Email,
		Groups:   userInfo.Groups,
		Policies: applicablePolicies,
	}

	decision := h.policyEngine.Evaluate(policyCtx)
	if !decision.Allowed {
		h.logger.WithFields(logrus.Fields{
			"user":     userInfo.Email,
			"action":   action,
			"resource": resource,
			"reason":   decision.Reason,
		}).Warn("Policy evaluation denied S3 operation")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusForbidden, gin.H{
			"Error": gin.H{
				"Code":    "AccessDenied",
				"Message": fmt.Sprintf("Access denied: %s", decision.Reason),
			},
		})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user":     userInfo.Email,
		"action":   action,
		"resource": resource,
		"allowed":  true,
	}).Debug("Policy evaluation allowed S3 operation")

	// Create S3 client using user's delegated credentials
	s3Client, err := h.CreateUserS3Client(c.Request.Context(), cred)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"user":       userInfo.Email,
			"access_key": accessKey,
			"cred_name":  cred.Name,
		}).Error("Failed to create S3 client with user credentials")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusInternalServerError, gin.H{
			"Error": gin.H{
				"Code":    "InternalError",
				"Message": "Failed to initialize S3 client",
			},
		})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"access_key": accessKey,
		"cred_name":  cred.Name,
	}).Debug("Using S3 client with user credentials for backend operation")

	// Proxy the request to S3
	h.ProxyToS3(c, s3Client, bucket, key, userInfo)
}

// ListBuckets handles S3 list buckets operation for AWS CLI compatibility
func (h *S3Handler) ListBuckets(c *gin.Context) {
	// Extract user info from context (set by auth middleware)
	userInfoValue, exists := c.Get("userInfo")
	if !exists {
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusUnauthorized, gin.H{
			"Error": gin.H{
				"Code":    "AccessDenied",
				"Message": "Unauthorized",
			},
		})
		return
	}
	userInfo := userInfoValue.(*auth.UserInfo)

	// Check if credential was set by access key authentication
	_, hasSelectedCred := c.Get("selectedCredential")
	if hasSelectedCred {
		// Credential is available, proceed
	} else {
		// This shouldn't happen for CLI requests, but handle it just in case
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusBadRequest, gin.H{
			"Error": gin.H{
				"Code":    "InvalidRequest",
				"Message": "No credential available for list buckets",
			},
		})
		return
	}

	// Get all buckets from the S3 backend
	ctx := c.Request.Context()
	result, err := h.s3Client.GetClient().ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		h.logger.WithError(err).Error("Failed to list buckets from S3 backend")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusInternalServerError, gin.H{
			"Error": gin.H{
				"Code":    "InternalError",
				"Message": "Failed to list buckets",
			},
		})
		return
	}

	// Filter buckets based on user policies
	// For list buckets, we check if the user has any access to each bucket
	allowedBuckets := make([]gin.H, 0)

	// Resolve user's groups to applicable policies
	applicablePolicies := make([]string, 0)
	for _, groupName := range userInfo.Groups {
		scimGroupId := groupName
		if scimGroupId != "" {
			group, err := h.groupStore.Get(scimGroupId)
			if err != nil {
				h.logger.WithError(err).WithField("group", groupName).Warn("Failed to get group definition")
				continue
			}
			applicablePolicies = append(applicablePolicies, group.Policies...)
		}
	}

	for _, bucket := range result.Buckets {
		bucketName := *bucket.Name

		// Check if user has any access to this bucket
		// We check for s3:ListBucket permission on the bucket
		resource := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
		policyCtx := &policy.EvaluationContext{
			Action:   "s3:ListBucket",
			Bucket:   bucketName,
			Resource: resource,
			UserID:   userInfo.Email,
			Groups:   userInfo.Groups,
			Policies: applicablePolicies,
		}

		decision := h.policyEngine.Evaluate(policyCtx)
		if decision.Allowed {
			allowedBuckets = append(allowedBuckets, gin.H{
				"Name":         bucketName,
				"CreationDate": bucket.CreationDate.Format(time.RFC3339),
			})
		}
	}

	// Return S3-compatible XML response
	xmlResponse := gin.H{
		"Buckets": gin.H{
			"Bucket": allowedBuckets,
		},
		"Owner": gin.H{
			"ID":          userInfo.Subject,
			"DisplayName": userInfo.Email,
		},
	}

	c.Header("Content-Type", "application/xml")
	c.XML(http.StatusOK, gin.H{"ListAllMyBucketsResponse": xmlResponse})
}

// ProxyToS3 forwards the request to S3 using the provided client
func (h *S3Handler) ProxyToS3(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
	method := c.Request.Method

	switch method {
	case http.MethodGet:
		h.handleGet(c, s3Client, bucket, key, userInfo)
	case http.MethodPut:
		h.handlePut(c, s3Client, bucket, key, userInfo)
	case http.MethodDelete:
		h.handleDelete(c, s3Client, bucket, key, userInfo)
	case http.MethodHead:
		h.handleHead(c, s3Client, bucket, key, userInfo)
	case http.MethodPost:
		h.handlePost(c, s3Client, bucket, key, userInfo)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

// handleGet handles GET requests (download)
func (h *S3Handler) handleGet(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
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
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusInternalServerError, gin.H{
			"Error": gin.H{
				"Code":    "NoSuchKey",
				"Message": "Failed to get object",
			},
		})
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
func (h *S3Handler) handlePut(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
	if key == "" {
		// This is a bucket creation request
		ctx := c.Request.Context()
		_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		})

		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"user":   userInfo.Email,
			}).Error("Failed to create bucket in S3")
			c.Header("Content-Type", "application/xml")
			c.XML(http.StatusInternalServerError, gin.H{
				"Error": gin.H{
					"Code":    "InternalError",
					"Message": "Failed to create bucket",
				},
			})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"user":   userInfo.Email,
		}).Info("Bucket created successfully")

		c.Status(http.StatusOK)
		return
	}

	// Read request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read request body")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusBadRequest, gin.H{
			"Error": gin.H{
				"Code":    "InvalidRequest",
				"Message": "Failed to read request body",
			},
		})
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
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"user":   userInfo.Email,
		}).Error("Failed to put object to S3")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusInternalServerError, gin.H{
			"Error": gin.H{
				"Code":    "InternalError",
				"Message": "Failed to upload object",
			},
		})
		return
	}

	// S3 PUT operations return 200 OK with no body for success
	c.Status(http.StatusOK)
}

// handleDelete handles DELETE requests
func (h *S3Handler) handleDelete(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
	if key == "" {
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusBadRequest, gin.H{
			"Error": gin.H{
				"Code":    "InvalidRequest",
				"Message": "Key is required for DELETE",
			},
		})
		return
	}

	ctx := c.Request.Context()
	_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		h.logger.WithError(err).Error("Failed to delete object from S3")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusInternalServerError, gin.H{
			"Error": gin.H{
				"Code":    "InternalError",
				"Message": "Failed to delete object",
			},
		})
		return
	}

	// S3 DELETE operations return 204 No Content for success
	c.Status(http.StatusNoContent)
}

// handleHead handles HEAD requests
func (h *S3Handler) handleHead(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
	if key == "" {
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusBadRequest, gin.H{
			"Error": gin.H{
				"Code":    "InvalidRequest",
				"Message": "Key is required for HEAD",
			},
		})
		return
	}

	ctx := c.Request.Context()
	result, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		h.logger.WithError(err).Error("Failed to head object from S3")
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusNotFound, gin.H{
			"Error": gin.H{
				"Code":    "NoSuchKey",
				"Message": "The specified key does not exist",
			},
		})
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
func (h *S3Handler) handlePost(c *gin.Context, s3Client *s3.Client, bucket, key string, userInfo *auth.UserInfo) {
	// For simplicity, we'll return not implemented
	// You can extend this to handle multipart uploads
	c.Header("Content-Type", "application/xml")
	c.XML(http.StatusNotImplemented, gin.H{
		"Error": gin.H{
			"Code":    "NotImplemented",
			"Message": "POST operations not yet implemented",
		},
	})
}

// handleListObjects lists objects in a bucket
func (h *S3Handler) handleListObjects(c *gin.Context, s3Client *s3.Client, bucket string) {
	prefix := c.Query("prefix")
	delimiter := c.Query("delimiter")
	maxKeys := c.Query("max-keys")
	if maxKeys == "" {
		maxKeys = "1000"
	}

	contentType := c.GetHeader("Content-Type")
	h.logger.WithFields(logrus.Fields{
		"bucket":      bucket,
		"contentType": contentType,
		"path":        c.Request.URL.Path,
	}).Debug("handleListObjects called")

	ctx := c.Request.Context()
	result, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String(delimiter),
		MaxKeys:   aws.Int32(1000), // Default max keys
	})

	if err != nil {
		h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to list objects from S3")
		// Check if this is a web UI request (expects JSON)
		if c.GetHeader("Content-Type") == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list objects"})
			return
		}
		// Return S3-compatible error XML
		c.Header("Content-Type", "application/xml")
		c.XML(http.StatusInternalServerError, gin.H{
			"Error": gin.H{
				"Code":    "InternalError",
				"Message": "Failed to list objects",
			},
		})
		return
	}

	// Check if this is a web UI request (expects JSON response)
	if c.GetHeader("Content-Type") == "application/json" {
		// Return JSON response for web UI
		objects := []gin.H{}

		// Add contents
		for _, obj := range result.Contents {
			content := gin.H{
				"key":          *obj.Key,
				"lastModified": obj.LastModified.Format(time.RFC3339),
				"etag":         *obj.ETag,
				"size":         *obj.Size,
				"storageClass": "STANDARD", // Default storage class
			}
			objects = append(objects, content)
		}

		// Add common prefixes (for directory-like listing)
		folders := []string{}
		for _, prefix := range result.CommonPrefixes {
			if prefix.Prefix != nil {
				folders = append(folders, *prefix.Prefix)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"objects":     objects,
			"folders":     folders,
			"isTruncated": result.IsTruncated,
			"keyCount":    len(result.Contents),
			"maxKeys":     maxKeys,
			"prefix":      prefix,
			"name":        bucket,
		})
		return
	}

	// Build S3-compatible XML response
	xmlResponse := gin.H{
		"Name":           bucket,
		"Prefix":         prefix,
		"KeyCount":       len(result.Contents),
		"MaxKeys":        maxKeys,
		"IsTruncated":    result.IsTruncated,
		"Contents":       []gin.H{},
		"CommonPrefixes": []gin.H{},
	}

	// Add contents
	for _, obj := range result.Contents {
		content := gin.H{
			"Key":          *obj.Key,
			"LastModified": obj.LastModified.Format(time.RFC3339),
			"ETag":         *obj.ETag,
			"Size":         *obj.Size,
			"StorageClass": "STANDARD", // Default storage class
		}
		xmlResponse["Contents"] = append(xmlResponse["Contents"].([]gin.H), content)
	}

	// Add common prefixes (for directory-like listing)
	for _, prefix := range result.CommonPrefixes {
		if prefix.Prefix != nil {
			commonPrefix := gin.H{
				"Prefix": *prefix.Prefix,
			}
			xmlResponse["CommonPrefixes"] = append(xmlResponse["CommonPrefixes"].([]gin.H), commonPrefix)
		}
	}

	c.Header("Content-Type", "application/xml")
	c.XML(http.StatusOK, xmlResponse)
}
