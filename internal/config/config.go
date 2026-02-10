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
	Server       ServerConfig     `yaml:"server"`
	OIDC         OIDCConfig       `yaml:"oidc"`          // Global OIDC configuration
	SCIM         SCIMConfig       `yaml:"scim"`          // Global SCIM configuration
	SRAM         SRAMConfig       `yaml:"sram"`          // SRAM integration configuration
	GlobalAdmins []string         `yaml:"global_admins"` // Global administrator email addresses
	Tenants      []TenantConfig   `yaml:"-"`             // Auto-discovered tenants (not in YAML)
	S3           S3GlobalConfig   `yaml:"s3"`            // Global S3 settings
	Logging      LoggingConfig    `yaml:"logging"`
	Security     SecurityConfig   `yaml:"security"`
	Monitoring   MonitoringConfig `yaml:"monitoring"`
}

// TenantConfig contains tenant-specific configuration
type TenantConfig struct {
	Name                string            `yaml:"name"`                  // Tenant name/identifier
	TenantAdmins        []string          `yaml:"tenant_admins"`         // List of tenant admin email addresses
	SRAMCollaborationID string            `yaml:"sram_collaboration_id"` // SRAM Collaboration ID for this tenant
	IAM                 IAMConfig         `yaml:"iam"`                   // Tenant-specific IAM credentials
	DataDir             string            `yaml:"data_dir"`              // Tenant data directory (default: ./data/<name>)
	Credentials         CredentialsConfig `yaml:"credentials"`           // Tenant-specific credentials settings
	Policies            PoliciesConfig    `yaml:"policies"`              // Tenant-specific policy settings
	Roles               RolesConfig       `yaml:"roles"`                 // Tenant-specific role settings
}

// S3GlobalConfig contains global S3 settings (shared across tenants)
type S3GlobalConfig struct {
	Endpoint            string `yaml:"endpoint"`
	Region              string `yaml:"region"`
	DisableAutoCreation bool   `yaml:"disable_auto_creation"` // If true, users must manually add pre-created credentials
	ForcePathStyle      bool   `yaml:"force_path_style"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	MaxHeaderBytes int           `yaml:"max_header_bytes"` // Maximum header size in bytes
}

// OIDCConfig contains OIDC authentication settings
type OIDCConfig struct {
	Issuer          string        `yaml:"issuer"`
	ClientID        string        `yaml:"client_id"`
	ClientSecret    string        `yaml:"client_secret"`
	Scopes          string        `yaml:"scopes"`
	GroupsClaim     string        `yaml:"groups_claim"`
	UserClaim       string        `yaml:"user_claim"`
	EmailClaim      string        `yaml:"email_claim"`
	SessionCacheTTL time.Duration `yaml:"session_cache_ttl"` // Time before revalidating token, default 15 minutes
}

// IAMConfig contains IAM admin credentials for user/policy management
type IAMConfig struct {
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
}

// S3Config contains S3 backend settings
type S3Config struct {
	Endpoint            string    `yaml:"endpoint"`
	Region              string    `yaml:"region"`
	DisableAutoCreation bool      `yaml:"disable_auto_creation"` // If true, users must manually add pre-created credentials
	ForcePathStyle      bool      `yaml:"force_path_style"`
	IAM                 IAMConfig `yaml:"iam"` // IAM credentials for admin operations
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

// CredentialsConfig contains credential store settings
type CredentialsConfig struct {
	File string `yaml:"file"` // File path for credentials storage
}

// SCIMGroupsConfig contains SCIM group settings
type SCIMGroupsConfig struct {
	Directory string `yaml:"directory"` // Directory for SCIM group data
}

// UsersConfig contains user provisioning settings
type SCIMUsersConfig struct {
	Directory string `yaml:"directory"` // Directory for SCIM user data
}

// SCIMConfig contains SCIM server settings
type SCIMConfig struct {
	APIKey string `yaml:"api_key"` // API key for SCIM server authentication
}

// SRAMConfig contains SRAM (SURF Research Access Management) integration settings
type SRAMConfig struct {
	APIURL  string `yaml:"api_url"` // SRAM API base URL
	APIKey  string `yaml:"api_key"` // SRAM API key for authentication
	Enabled bool   `yaml:"enabled"` // Enable/disable SRAM integration
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
	Username  string   `yaml:"username"`            // Single admin user's email/username (for backward compatibility)
	Usernames []string `yaml:"usernames,omitempty"` // List of admin user emails/usernames
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

	// Override global S3 settings from environment variables if present
	if err := loadS3EnvVars(&cfg.S3); err != nil {
		return nil, fmt.Errorf("failed to load S3 environment variables: %w", err)
	}

	// Override global OIDC settings from environment variables if present
	if err := loadOIDCEnvVars(&cfg.OIDC); err != nil {
		return nil, fmt.Errorf("failed to load OIDC environment variables: %w", err)
	}

	// Override SRAM settings from environment variables if present
	if err := loadSRAMEnvVars(&cfg.SRAM); err != nil {
		return nil, fmt.Errorf("failed to load SRAM environment variables: %w", err)
	}

	// Auto-discover tenants from ./data directory
	if err := discoverTenants(&cfg); err != nil {
		return nil, fmt.Errorf("failed to discover tenants: %w", err)
	}

	// Set defaults
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 9000
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 15 * time.Second // Reduced from 30s for better concurrency
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 15 * time.Second // Reduced from 30s for better concurrency
	}
	if cfg.Server.MaxHeaderBytes == 0 {
		cfg.Server.MaxHeaderBytes = 1 << 20 // 1MB default max header size
	}

	// Set tenant-specific defaults for all discovered tenants
	for i := range cfg.Tenants {
		tenant := &cfg.Tenants[i]
		if tenant.DataDir == "" {
			tenant.DataDir = fmt.Sprintf("./data/tenants/%s", tenant.Name)
		}
		if tenant.Policies.Directory == "" {
			tenant.Policies.Directory = fmt.Sprintf("%s/policies", tenant.DataDir)
		}
		if tenant.Policies.CacheTTL == 0 {
			tenant.Policies.CacheTTL = 5 * time.Minute
		}
		if tenant.Roles.Directory == "" {
			tenant.Roles.Directory = fmt.Sprintf("%s/roles", tenant.DataDir)
		}
		if tenant.Credentials.File == "" {
			tenant.Credentials.File = fmt.Sprintf("%s/credentials.json", tenant.DataDir)
		}
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// discoverTenants auto-discovers tenants from the ./data directory
func discoverTenants(cfg *Config) error {
	dataDir := "./data/tenants"

	// Check if tenants directory exists
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		// Tenants directory doesn't exist yet, no tenants to load
		return nil
	}

	// Read all subdirectories in ./data/tenants
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return fmt.Errorf("failed to read tenants directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue // Skip files
		}

		tenantName := entry.Name()
		tenantConfigPath := fmt.Sprintf("%s/%s/config.yaml", dataDir, tenantName)

		// Check if config.yaml exists for this tenant
		if _, err := os.Stat(tenantConfigPath); os.IsNotExist(err) {
			continue // Skip directories without config.yaml
		}

		// Load tenant configuration
		data, err := os.ReadFile(tenantConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read tenant config for %s: %w", tenantName, err)
		}

		var tenantCfg TenantConfig
		if err := yaml.Unmarshal(data, &tenantCfg); err != nil {
			return fmt.Errorf("failed to parse tenant config for %s: %w", tenantName, err)
		}

		// Set tenant name and data directory
		tenantCfg.Name = tenantName
		tenantCfg.DataDir = fmt.Sprintf("./data/tenants/%s", tenantName)

		// Override with environment variables if present
		// Note: IAM credentials are tenant-specific and should not fall back to global env vars
		if err := loadAdminEnvVars(&tenantCfg); err != nil {
			return fmt.Errorf("failed to load admin env vars for tenant %s: %w", tenantName, err)
		}

		cfg.Tenants = append(cfg.Tenants, tenantCfg)
	}

	return nil
}
func (c *Config) Validate() error {
	// Validate global OIDC settings
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		return fmt.Errorf("global oidc.issuer and oidc.client_id are required")
	}

	// Allow starting without tenants - they can be created via API
	// Just log a warning instead of failing
	if len(c.Tenants) == 0 {
		// This is now allowed - tenants can be created dynamically
	}

	// Validate each tenant
	for _, tenant := range c.Tenants {
		if tenant.Name == "" {
			return fmt.Errorf("tenant name is required")
		}

		// IAM credentials are now optional per tenant
		// They can be added later via API
	}

	// Validate global S3 settings
	if c.S3.Region == "" {
		return fmt.Errorf("s3.region is required")
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
	if scopes := os.Getenv("OIDC_SCOPES"); scopes != "" {
		oidcCfg.Scopes = scopes
	}
	if groupsClaim := os.Getenv("OIDC_GROUPS_CLAIM"); groupsClaim != "" {
		oidcCfg.GroupsClaim = groupsClaim
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

// loadSRAMEnvVars loads SRAM configuration from environment variables
// Environment variables take precedence over YAML config
func loadSRAMEnvVars(sramCfg *SRAMConfig) error {
	if apiURL := os.Getenv("SRAM_API_URL"); apiURL != "" {
		sramCfg.APIURL = apiURL
	}
	if apiKey := os.Getenv("SRAM_API_KEY"); apiKey != "" {
		sramCfg.APIKey = apiKey
	}
	if enabled := os.Getenv("SRAM_ENABLED"); enabled != "" {
		val, err := strconv.ParseBool(enabled)
		if err != nil {
			return fmt.Errorf("invalid SRAM_ENABLED value: %w", err)
		}
		sramCfg.Enabled = val
	}
	return nil
}

// loadS3EnvVars loads S3 configuration from environment variables
// Environment variables take precedence over YAML config
// Supports both custom (S3_*) and standard AWS (AWS_*) environment variables
func loadS3EnvVars(s3cfg *S3GlobalConfig) error {
	if endpoint := os.Getenv("S3_ENDPOINT"); endpoint != "" {
		s3cfg.Endpoint = endpoint
	}
	if region := os.Getenv("S3_REGION"); region != "" {
		s3cfg.Region = region
	} else if region := os.Getenv("AWS_REGION"); region != "" {
		s3cfg.Region = region
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
func loadIAMEnvVars(iamcfg *IAMConfig, s3cfg *S3GlobalConfig) error {
	if accessKey := os.Getenv("IAM_ACCESS_KEY"); accessKey != "" {
		iamcfg.AccessKey = accessKey
	}
	if secretKey := os.Getenv("IAM_SECRET_KEY"); secretKey != "" {
		iamcfg.SecretKey = secretKey
	}

	return nil
}

// SaveToFile saves the configuration to a YAML file
func (c *Config) SaveToFile(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// loadAdminEnvVars loads admin configuration from environment variables
func loadAdminEnvVars(tenantCfg *TenantConfig) error {
	if admin := os.Getenv("ADMIN"); admin != "" {
		// For backward compatibility, add to tenant admins list if not already present
		found := false
		for _, existing := range tenantCfg.TenantAdmins {
			if existing == admin {
				found = true
				break
			}
		}
		if !found {
			tenantCfg.TenantAdmins = append(tenantCfg.TenantAdmins, admin)
		}
	}
	return nil
}

// LoadTenantConfig loads a tenant's specific configuration from data/tenants/<tenant>/config.yaml
func LoadTenantConfig(tenantName string) (*TenantConfig, error) {
	configPath := fmt.Sprintf("./data/tenants/%s/config.yaml", tenantName)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tenant config: %w", err)
	}

	var tenantCfg TenantConfig
	if err := yaml.Unmarshal(data, &tenantCfg); err != nil {
		return nil, fmt.Errorf("failed to parse tenant config: %w", err)
	}

	tenantCfg.Name = tenantName

	// Apply environment variable overrides for this tenant
	// Note: For tenant configs, we only load admin overrides
	// IAM credentials should be managed through the config file or API
	if err := loadAdminEnvVars(&tenantCfg); err != nil {
		return nil, err
	}

	return &tenantCfg, nil
}
