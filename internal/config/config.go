package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	OIDC       OIDCConfig       `yaml:"oidc"`
	S3         S3Config         `yaml:"s3"`
	IAM        IAMConfig        `yaml:"iam"`
	Policies   PoliciesConfig   `yaml:"policies"`
	Roles      RolesConfig      `yaml:"roles"`
	Logging    LoggingConfig    `yaml:"logging"`
	Security   SecurityConfig   `yaml:"security"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Admin      AdminConfig      `yaml:"admin"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// OIDCConfig contains OIDC authentication settings
type OIDCConfig struct {
	Issuer          string        `yaml:"issuer"`
	ClientID        string        `yaml:"client_id"`
	ClientSecret    string        `yaml:"client_secret"`
	RolesClaim      string        `yaml:"roles_claim"`
	UserClaim       string        `yaml:"user_claim"`
	EmailClaim      string        `yaml:"email_claim"`
	SessionCacheTTL time.Duration `yaml:"session_cache_ttl"` // Time before revalidating token, default 15 minutes
}

// S3Config contains S3 backend settings
type S3Config struct {
	Endpoint            string `yaml:"endpoint"`
	Region              string `yaml:"region"`
	DisableAutoCreation bool   `yaml:"disable_auto_creation"` // If true, users must manually add pre-created credentials
	AccessKey           string `yaml:"access_key"`
	SecretKey           string `yaml:"secret_key"`
	UseIAMRole          bool   `yaml:"use_iam_role"`
	ForcePathStyle      bool   `yaml:"force_path_style"`
}

// IAMConfig contains IAM admin credentials for user/policy management
type IAMConfig struct {
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Endpoint  string `yaml:"endpoint"`
	Region    string `yaml:"region"`
}

// PoliciesConfig contains policy engine settings
type PoliciesConfig struct {
	Directory    string        `yaml:"directory"`
	DefaultDeny  bool          `yaml:"default_deny"`
	CacheEnabled bool          `yaml:"cache_enabled"`
	CacheTTL     time.Duration `yaml:"cache_ttl"`
}

// RolesConfig contains role management settings
type RolesConfig struct {
	Directory string `yaml:"directory"` // Directory for role definitions
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level     string `yaml:"level"`
	Format    string `yaml:"format"`
	File      string `yaml:"file"`
	AccessLog bool   `yaml:"access_log"`
	AuditLog  bool   `yaml:"audit_log"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	ValidateSignatures bool     `yaml:"validate_signatures"`
	AllowedMethods     []string `yaml:"allowed_methods"`
	CORSEnabled        bool     `yaml:"cors_enabled"`
	CORSOrigins        []string `yaml:"cors_origins"`
	RateLimit          int      `yaml:"rate_limit"`
}

// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	MetricsEnabled bool `yaml:"metrics_enabled"`
	MetricsPort    int  `yaml:"metrics_port"`
}

// AdminConfig contains admin user settings
type AdminConfig struct {
	Username string `yaml:"username"` // Admin user's email/username
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	// Load .env file if it exists (silently ignore if not present)
	_ = godotenv.Load()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Override sensitive settings from environment variables if present
	// Environment variables take precedence over YAML config for security
	if err := loadOIDCEnvVars(&cfg.OIDC); err != nil {
		return nil, fmt.Errorf("failed to load OIDC environment variables: %w", err)
	}
	if err := loadS3EnvVars(&cfg.S3); err != nil {
		return nil, fmt.Errorf("failed to load S3 environment variables: %w", err)
	}
	if err := loadIAMEnvVars(&cfg.IAM, &cfg.S3); err != nil {
		return nil, fmt.Errorf("failed to load IAM environment variables: %w", err)
	}
	if err := loadAdminEnvVars(&cfg.Admin); err != nil {
		return nil, fmt.Errorf("failed to load admin environment variables: %w", err)
	}

	// Set defaults
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 30 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 * time.Second
	}
	if cfg.OIDC.RolesClaim == "" {
		cfg.OIDC.RolesClaim = "Roles"
	}
	if cfg.OIDC.UserClaim == "" {
		cfg.OIDC.UserClaim = "sub"
	}
	if cfg.OIDC.EmailClaim == "" {
		cfg.OIDC.EmailClaim = "email"
	}
	if cfg.OIDC.SessionCacheTTL == 0 {
		cfg.OIDC.SessionCacheTTL = 15 * time.Minute
	}
	if cfg.Policies.Directory == "" {
		cfg.Policies.Directory = "./policies"
	}
	if cfg.Policies.CacheTTL == 0 {
		cfg.Policies.CacheTTL = 5 * time.Minute
	}
	if cfg.Roles.Directory == "" {
		cfg.Roles.Directory = "./data/roles"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}
	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc.client_id is required")
	}
	if c.S3.Region == "" {
		return fmt.Errorf("s3.region is required")
	}
	if !c.S3.UseIAMRole && (c.S3.AccessKey == "" || c.S3.SecretKey == "") {
		return fmt.Errorf("s3.access_key and s3.secret_key are required when not using IAM role")
	}
	return nil
}

// loadOIDCEnvVars loads OIDC configuration from environment variables
// Environment variables take precedence over YAML config
func loadOIDCEnvVars(oidcCfg *OIDCConfig) error {
	if issuer := os.Getenv("OIDC_ISSUER"); issuer != "" {
		oidcCfg.Issuer = issuer
	}
	if clientID := os.Getenv("OIDC_CLIENT_ID"); clientID != "" {
		oidcCfg.ClientID = clientID
	}
	if clientSecret := os.Getenv("OIDC_CLIENT_SECRET"); clientSecret != "" {
		oidcCfg.ClientSecret = clientSecret
	}
	if rolesClaim := os.Getenv("OIDC_ROLES_CLAIM"); rolesClaim != "" {
		oidcCfg.RolesClaim = rolesClaim
	}
	if userClaim := os.Getenv("OIDC_USER_CLAIM"); userClaim != "" {
		oidcCfg.UserClaim = userClaim
	}
	if emailClaim := os.Getenv("OIDC_EMAIL_CLAIM"); emailClaim != "" {
		oidcCfg.EmailClaim = emailClaim
	}
	if sessionCacheTTL := os.Getenv("OIDC_SESSION_CACHE_TTL"); sessionCacheTTL != "" {
		duration, err := time.ParseDuration(sessionCacheTTL)
		if err != nil {
			return fmt.Errorf("invalid OIDC_SESSION_CACHE_TTL value: %w", err)
		}
		oidcCfg.SessionCacheTTL = duration
	}
	return nil
}

// loadS3EnvVars loads S3 configuration from environment variables
// Environment variables take precedence over YAML config
// Supports both custom (S3_*) and standard AWS (AWS_*) environment variables
func loadS3EnvVars(s3cfg *S3Config) error {
	if endpoint := os.Getenv("S3_ENDPOINT"); endpoint != "" {
		s3cfg.Endpoint = endpoint
	}
	if region := os.Getenv("S3_REGION"); region != "" {
		s3cfg.Region = region
	} else if region := os.Getenv("AWS_REGION"); region != "" {
		s3cfg.Region = region
	}

	// Support both S3_ACCESS_KEY and AWS_ACCESS_KEY_ID
	if accessKey := os.Getenv("S3_ACCESS_KEY"); accessKey != "" {
		s3cfg.AccessKey = accessKey
	} else if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		s3cfg.AccessKey = accessKey
	}

	// Support both S3_SECRET_KEY and AWS_SECRET_ACCESS_KEY
	if secretKey := os.Getenv("S3_SECRET_KEY"); secretKey != "" {
		s3cfg.SecretKey = secretKey
	} else if secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey != "" {
		s3cfg.SecretKey = secretKey
	}

	if useIAMRole := os.Getenv("S3_USE_IAM_ROLE"); useIAMRole != "" {
		val, err := strconv.ParseBool(useIAMRole)
		if err != nil {
			return fmt.Errorf("invalid S3_USE_IAM_ROLE value: %w", err)
		}
		s3cfg.UseIAMRole = val
	}
	if forcePathStyle := os.Getenv("S3_FORCE_PATH_STYLE"); forcePathStyle != "" {
		val, err := strconv.ParseBool(forcePathStyle)
		if err != nil {
			return fmt.Errorf("invalid S3_FORCE_PATH_STYLE value: %w", err)
		}
		s3cfg.ForcePathStyle = val
	}
	return nil
}

// loadIAMEnvVars loads IAM configuration from environment variables
func loadIAMEnvVars(iamcfg *IAMConfig, s3cfg *S3Config) error {
	if accessKey := os.Getenv("IAM_ACCESS_KEY"); accessKey != "" {
		iamcfg.AccessKey = accessKey
	}
	if secretKey := os.Getenv("IAM_SECRET_KEY"); secretKey != "" {
		iamcfg.SecretKey = secretKey
	}
	if endpoint := os.Getenv("IAM_ENDPOINT"); endpoint != "" {
		iamcfg.Endpoint = endpoint
	}
	if region := os.Getenv("IAM_REGION"); region != "" {
		iamcfg.Region = region
	}

	// Default to S3 config values if IAM-specific values not provided
	if iamcfg.AccessKey == "" {
		iamcfg.AccessKey = s3cfg.AccessKey
	}
	if iamcfg.SecretKey == "" {
		iamcfg.SecretKey = s3cfg.SecretKey
	}
	if iamcfg.Endpoint == "" {
		iamcfg.Endpoint = s3cfg.Endpoint
	}
	if iamcfg.Region == "" {
		iamcfg.Region = s3cfg.Region
	}

	return nil
}

// loadAdminEnvVars loads admin configuration from environment variables
func loadAdminEnvVars(adminCfg *AdminConfig) error {
	if admin := os.Getenv("ADMIN"); admin != "" {
		adminCfg.Username = admin
	}
	return nil
}
