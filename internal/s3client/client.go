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
	s3Config  config.S3GlobalConfig
	iamConfig config.IAMConfig
	logger    *logrus.Logger
}

// NewClient creates a new S3 client
func NewClient(s3Cfg config.S3GlobalConfig, iamCfg config.IAMConfig, logger *logrus.Logger) (*Client, error) {
	ctx := context.Background()

	// Use IAM credentials for S3 operations
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(s3Cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			iamCfg.AccessKey,
			iamCfg.SecretKey,
			"",
		)),
	}

	// Add custom endpoint resolver for non-AWS S3
	if s3Cfg.Endpoint != "" && s3Cfg.Endpoint != "https://s3.amazonaws.com" {
		loadOpts = append(loadOpts, awsconfig.WithEndpointResolver(aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			if service == "S3" {
				return aws.Endpoint{
					URL:           s3Cfg.Endpoint,
					SigningRegion: s3Cfg.Region,
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
		o.UsePathStyle = s3Cfg.ForcePathStyle
	}

	s3Client := s3.NewFromConfig(awsCfg, s3ClientOpts)

	logger.WithFields(logrus.Fields{
		"region":           s3Cfg.Region,
		"endpoint":         s3Cfg.Endpoint,
		"force_path_style": s3Cfg.ForcePathStyle,
	}).Info("S3 client initialized with IAM credentials")

	return &Client{
		s3Client:  s3Client,
		awsConfig: awsCfg,
		s3Config:  s3Cfg,
		iamConfig: iamCfg,
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
