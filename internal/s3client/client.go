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
	config    config.S3Config
	logger    *logrus.Logger
}

// NewClient creates a new S3 client
func NewClient(cfg config.S3Config, logger *logrus.Logger) (*Client, error) {
	ctx := context.Background()

	// Use IAM credentials for S3 operations
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.IAM.AccessKey,
			cfg.IAM.SecretKey,
			"",
		)),
	}

	// Add custom endpoint resolver for non-AWS S3
	if cfg.Endpoint != "" && cfg.Endpoint != "https://s3.amazonaws.com" {
		loadOpts = append(loadOpts, awsconfig.WithEndpointResolver(aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			if service == "S3" {
				return aws.Endpoint{
					URL:           cfg.Endpoint,
					SigningRegion: cfg.Region,
				}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with path style
	s3ClientOpts := func(o *s3.Options) {
		o.UsePathStyle = cfg.ForcePathStyle
	}

	s3Client := s3.NewFromConfig(awsCfg, s3ClientOpts)

	logger.WithFields(logrus.Fields{
		"region":           cfg.Region,
		"endpoint":         cfg.Endpoint,
		"force_path_style": cfg.ForcePathStyle,
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
