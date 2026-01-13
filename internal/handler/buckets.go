package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/s3client"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// BucketHandler handles bucket management endpoints
type BucketHandler struct {
	s3Client *s3client.Client
	logger   *logrus.Logger
}

// NewBucketHandler creates a new bucket handler
func NewBucketHandler(s3Client *s3client.Client, logger *logrus.Logger) *BucketHandler {
	return &BucketHandler{
		s3Client: s3Client,
		logger:   logger,
	}
}

// CreateBucketRequest represents a request to create a bucket
type CreateBucketRequest struct {
	Name string `json:"name" binding:"required"`
}

// BucketResponse represents a bucket in API responses
type BucketResponse struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// ListBuckets lists all buckets for the authenticated user
func (h *BucketHandler) ListBuckets(c *gin.Context) {
	// Get user info from context
	userInfo, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	user := userInfo.(*auth.UserInfo)

	h.logger.WithFields(logrus.Fields{
		"user": user.Subject,
	}).Info("Listing buckets")

	// Create S3 client for user
	ctx := context.Background()
	client := h.s3Client.GetClient()

	// List buckets
	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		h.logger.WithError(err).Error("Failed to list buckets")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list buckets"})
		return
	}

	// Convert to response format
	buckets := make([]BucketResponse, 0, len(result.Buckets))
	for _, bucket := range result.Buckets {
		buckets = append(buckets, BucketResponse{
			Name:      aws.ToString(bucket.Name),
			CreatedAt: bucket.CreationDate.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"buckets": buckets,
	})
}

// CreateBucket creates a new bucket
func (h *BucketHandler) CreateBucket(c *gin.Context) {
	// Get user info from context
	userInfo, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	user := userInfo.(*auth.UserInfo)

	// Parse request
	var req CreateBucketRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user":   user.Subject,
		"bucket": req.Name,
	}).Info("Creating bucket")

	// Create S3 client for user
	ctx := context.Background()
	client := h.s3Client.GetClient()

	// Create bucket
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(req.Name),
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to create bucket")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create bucket: " + err.Error()})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user":   user.Subject,
		"bucket": req.Name,
	}).Info("Bucket created successfully")

	c.JSON(http.StatusCreated, gin.H{
		"bucket": BucketResponse{
			Name:      req.Name,
			CreatedAt: time.Now().Format(time.RFC3339),
		},
	})
}

// DeleteBucket deletes a bucket
func (h *BucketHandler) DeleteBucket(c *gin.Context) {
	// Get user info from context
	userInfo, exists := c.Get("userInfo")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	user := userInfo.(*auth.UserInfo)
	bucketName := c.Param("name")

	h.logger.WithFields(logrus.Fields{
		"user":   user.Subject,
		"bucket": bucketName,
	}).Info("Deleting bucket")

	// Create S3 client for user
	ctx := context.Background()
	client := h.s3Client.GetClient()

	// Check if bucket is empty
	listResult, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to check bucket contents")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check bucket contents"})
		return
	}

	if len(listResult.Contents) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bucket must be empty before deletion"})
		return
	}

	// Delete bucket
	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// Check if it's a NoSuchBucket error
		var noSuchBucket *types.NoSuchBucket
		if fmt.Sprintf("%T", err) == fmt.Sprintf("%T", noSuchBucket) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Bucket not found"})
			return
		}

		h.logger.WithError(err).Error("Failed to delete bucket")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete bucket: " + err.Error()})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"user":   user.Subject,
		"bucket": bucketName,
	}).Info("Bucket deleted successfully")

	c.JSON(http.StatusOK, gin.H{
		"message": "Bucket deleted successfully",
	})
}
