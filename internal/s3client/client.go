package s3client

import (
	"context"
	"fmt"

	"github.com/harrykodden/s3-gateway/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
)

// Client wraps S3 client operations
type Client struct {
	s3Client  *s3.Client
	awsConfig aws.Config
	config    config.IAMConfig
	logger    *logrus.Logger
}

// NewClient creates a new S3 client
func NewClient(cfg config.IAMConfig, logger *logrus.Logger) (*Client, error) {
	ctx := context.Background()

	// Use IAM credentials for S3 operations
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKey,
			cfg.SecretKey,
			"",
		)),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with optional endpoint override
	s3ClientOpts := func(o *s3.Options) {
		if cfg.Endpoint != "" && cfg.Endpoint != "https://s3.amazonaws.com" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		// IAM clients typically don't use path style
		o.UsePathStyle = false
	}

	s3Client := s3.NewFromConfig(awsCfg, s3ClientOpts)

	logger.WithFields(logrus.Fields{
		"region":           cfg.Region,
		"endpoint":         cfg.Endpoint,
		"force_path_style": false, // IAM clients don't use path style
	}).Info("S3 client initialized with IAM credentials")

	return &Client{
		s3Client:  s3Client,
		awsConfig: awsCfg,
		config:    cfg,
		logger:    logger,
	}, nil
}

// GetClient returns the underlying S3 client
func (c *Client) GetClient() *s3.Client {
	return c.s3Client
}

// GetAWSConfig returns the AWS SDK configuration
func (c *Client) GetAWSConfig() aws.Config {
	return c.awsConfig
}
