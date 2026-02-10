package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/backend"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/harrykodden/s3-gateway/internal/handler"
	"github.com/harrykodden/s3-gateway/internal/health"
	"github.com/harrykodden/s3-gateway/internal/logging"
	"github.com/harrykodden/s3-gateway/internal/middleware"
	"github.com/harrykodden/s3-gateway/internal/policy"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/sram"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/harrykodden/s3-gateway/internal/sync"
	"github.com/harrykodden/s3-gateway/internal/watcher"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	configPath  = flag.String("config", "config.yaml", "Path to configuration file")
	showVersion = flag.Bool("version", false, "Show version information")

	// Version information (set via ldflags during build)
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type ServiceContainer struct {
	Logger         *logrus.Logger
	Cfg            *config.Config
	Authenticator  *auth.Authenticator // Global OIDC authenticator
	S3Client       *s3client.Client
	IAMClients     map[string]*s3client.IAMClient    // tenant -> iam client
	AdminClients   map[string]backend.AdminClient    // tenant -> admin client
	UserManagers   map[string]backend.UserManager    // tenant -> user manager
	GroupManagers  map[string]interface{}            // tenant -> group manager
	CredStores     map[string]*store.CredentialStore // tenant -> cred store
	GroupStore     *store.GroupStore                 // Global SCIM group store
	UserStore      *store.UserStore                  // Global SCIM user store
	RoleStores     map[string]*store.GroupStore      // tenant -> role store
	PolicyStores   map[string]*store.PolicyStore     // tenant -> policy store
	PolicyEngines  map[string]*policy.Engine         // tenant -> policy engine
	SyncServices   map[string]*sync.SyncService      // tenant -> sync service
	AdminUsernames map[string]string                 // tenant -> admin username
	HealthChecker  *health.Checker                   // Health check service
}

func initializeServices(configPath string) (*ServiceContainer, context.CancelFunc, error) {
	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	logger := logging.NewLogger(cfg.Logging)
	logger.WithFields(logrus.Fields{
		"version":    version,
		"commit":     commit,
		"build_date": buildDate,
		"config":     configPath,
		"tenants":    len(cfg.Tenants),
	}).Info("Starting S3 Access Manager")

	// Initialize global services
	// Use first tenant's IAM config for global S3 client, or create a dummy one
	var globalIAMCfg config.IAMConfig
	if len(cfg.Tenants) > 0 {
		globalIAMCfg = cfg.Tenants[0].IAM
	} else {
		// Fallback dummy config - this shouldn't happen in normal operation
		globalIAMCfg = config.IAMConfig{
			AccessKey: "dummy",
			SecretKey: "dummy",
		}
	}
	s3Client, err := s3client.NewClient(cfg.S3, globalIAMCfg, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize S3 client: %w", err)
	}

	// Initialize global SCIM stores
	groupStore, err := store.NewGroupStore("./data/scim/Groups", logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize global group store: %w", err)
	}

	userStore, err := store.NewUserStore("./data/scim/Users", "./data/scim/Groups", logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize global user store: %w", err)
	}

	// Create tenant configs map for role determination
	tenantConfigs := make(map[string]config.TenantConfig)
	for _, tenant := range cfg.Tenants {
		tenantConfigs[tenant.Name] = tenant
	}

	// Initialize global OIDC authenticator
	authenticator, err := auth.NewOIDCAuthenticator(cfg.OIDC, logger, nil, nil, userStore, cfg.GlobalAdmins, tenantConfigs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize global OIDC authenticator: %w", err)
	}

	// Initialize tenant-specific services
	iamClients := make(map[string]*s3client.IAMClient)
	adminClients := make(map[string]backend.AdminClient)
	userManagers := make(map[string]backend.UserManager)
	groupManagers := make(map[string]interface{})
	credStores := make(map[string]*store.CredentialStore)
	roleStores := make(map[string]*store.GroupStore)
	policyStores := make(map[string]*store.PolicyStore)
	policyEngines := make(map[string]*policy.Engine)
	syncServices := make(map[string]*sync.SyncService)
	adminUsernames := make(map[string]string)

	for _, tenant := range cfg.Tenants {
		// Initialize role store for this tenant
		roleStore, err := store.NewGroupStore(tenant.Roles.Directory, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize role store for tenant %s: %w", tenant.Name, err)
		}
		roleStores[tenant.Name] = roleStore

		// Initialize policy store for this tenant
		policyStore, err := store.NewPolicyStore(tenant.Policies.Directory, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize policy store for tenant %s: %w", tenant.Name, err)
		}
		policyStores[tenant.Name] = policyStore

		// Initialize policy engine for this tenant
		policyEngine, err := policy.NewEngine(tenant.Policies, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize policy engine for tenant %s: %w", tenant.Name, err)
		}
		policyEngines[tenant.Name] = policyEngine

		// Initialize IAM client for this tenant
		iamClient, err := s3client.NewIAMClient(cfg.S3, tenant.IAM, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize IAM client for tenant %s: %w", tenant.Name, err)
		}
		iamClients[tenant.Name] = iamClient

		// Initialize AWS CLI client for this tenant
		awsCliClient, err := awscli.NewClient(cfg.S3.Endpoint, tenant.IAM.AccessKey, tenant.IAM.SecretKey, cfg.S3.Region, tenant.Name, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize AWS CLI client for tenant %s: %w", tenant.Name, err)
		}

		// Use the client as admin client
		adminClients[tenant.Name] = awsCliClient

		// Initialize user manager for this tenant
		userManagers[tenant.Name] = awscli.NewUserManager(awsCliClient)

		// Initialize group manager for this tenant
		groupManagers[tenant.Name] = awscli.NewGroupManager(awsCliClient)

		// Initialize credential store for this tenant
		credStore, err := store.NewCredentialStore(tenant.Credentials.File, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize credential store for tenant %s: %w", tenant.Name, err)
		}
		credStores[tenant.Name] = credStore

		// Set admin username for this tenant
		adminUsername := ""
		if len(tenant.TenantAdmins) > 0 {
			adminUsername = tenant.TenantAdmins[0] // Use first tenant admin as primary
		}
		adminUsernames[tenant.Name] = adminUsername

		// Initialize sync service for this tenant
		syncService := sync.NewSyncService(iamClient, groupStore, userStore, tenant.Policies.Directory, adminUsername, logger)
		syncServices[tenant.Name] = syncService

		logger.WithFields(logrus.Fields{
			"tenant":       tenant.Name,
			"policies_dir": tenant.Policies.Directory,
			"roles_dir":    tenant.Roles.Directory,
		}).Info("Initialized tenant services")
	}

	// Recreate AWS CLI profiles for existing user credentials
	for _, tenant := range cfg.Tenants {
		awsCliClient := adminClients[tenant.Name]
		credStore := credStores[tenant.Name]

		// Load all credentials for this tenant
		allCredentials, err := credStore.ListAll()
		if err != nil {
			logger.WithError(err).WithField("tenant", tenant.Name).Warn("Failed to list credentials for profile recreation")
			continue
		}

		for _, cred := range allCredentials {
			// Recreate AWS profile for this credential
			if awsCliClientTyped, ok := awsCliClient.(*awscli.Client); ok {
				if err := awsCliClientTyped.CreateUserProfile(cred.UserID, cred.Name, cred.AccessKey, cred.SecretKey, cred.SessionToken, cfg.S3.Region, cfg.S3.Endpoint); err != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"tenant":     tenant.Name,
						"user":       cred.UserID,
						"credential": cred.Name,
					}).Warn("Failed to recreate AWS profile for existing credential")
				} else {
					logger.WithFields(logrus.Fields{
						"tenant":     tenant.Name,
						"user":       cred.UserID,
						"credential": cred.Name,
					}).Info("Recreated AWS profile for existing credential")
				}
			}
		}
	}

	// Start file watchers for all tenants
	watcherCtx, cleanupCancel := context.WithCancel(context.Background())
	for _, tenant := range cfg.Tenants {
		fileWatcher, err := watcher.NewFileWatcher(syncServices[tenant.Name], logger)
		if err != nil {
			cleanupCancel()
			return nil, nil, fmt.Errorf("failed to create file watcher for tenant %s: %w", tenant.Name, err)
		}

		// Add directories to watch
		if err := fileWatcher.AddDirectory("./data/scim/Users"); err != nil {
			cleanupCancel()
			return nil, nil, fmt.Errorf("failed to watch users directory for tenant %s: %w", tenant.Name, err)
		}
		if err := fileWatcher.AddDirectory("./data/scim/Groups"); err != nil {
			cleanupCancel()
			return nil, nil, fmt.Errorf("failed to watch groups directory for tenant %s: %w", tenant.Name, err)
		}
		if err := fileWatcher.AddDirectory(tenant.Policies.Directory); err != nil {
			cleanupCancel()
			return nil, nil, fmt.Errorf("failed to watch policies directory for tenant %s: %w", tenant.Name, err)
		}

		fileWatcher.Start(watcherCtx)
	}

	// Initialize health checker with 5-minute refresh interval
	healthChecker := health.NewChecker(cfg, logger, 5*time.Minute)

	return &ServiceContainer{
		Logger:         logger,
		Cfg:            cfg,
		Authenticator:  authenticator,
		S3Client:       s3Client,
		IAMClients:     iamClients,
		AdminClients:   adminClients,
		UserManagers:   userManagers,
		GroupManagers:  groupManagers,
		CredStores:     credStores,
		GroupStore:     groupStore,
		UserStore:      userStore,
		RoleStores:     roleStores,
		PolicyStores:   policyStores,
		PolicyEngines:  policyEngines,
		SyncServices:   syncServices,
		AdminUsernames: adminUsernames,
		HealthChecker:  healthChecker,
	}, cleanupCancel, nil
}
func setupSettingsRoutes(router *gin.Engine, authMiddleware, syncMiddleware, adminMiddleware gin.HandlerFunc,
	credStores map[string]*store.CredentialStore, groupStore *store.GroupStore, userStore *store.UserStore,
	roleStores map[string]*store.GroupStore, policyStores map[string]*store.PolicyStore, iamClients map[string]*s3client.IAMClient, adminClients map[string]backend.AdminClient,
	groupManagers map[string]interface{}, syncServices map[string]*sync.SyncService, cfg *config.Config, logger *logrus.Logger, userManagers map[string]backend.UserManager, adminUsernames map[string]string) {

	// Build tenant admins map for tenant admin middleware
	tenantAdmins := make(map[string][]string)
	var tenantNames []string
	for _, tenant := range cfg.Tenants {
		tenantNames = append(tenantNames, tenant.Name)
		tenantAdmins[tenant.Name] = tenant.TenantAdmins
	}

	// Create tenant admin middleware
	tenantAdminMiddleware := middleware.RequireTenantAdmin(tenantAdmins, logger)

	tenantMiddleware := middleware.TenantAuth(tenantNames, logger)

	settingsRoutes := router.Group("/tenant/:tenant/settings")
	settingsRoutes.Use(tenantMiddleware)
	settingsRoutes.Use(authMiddleware)
	// Note: Sync middleware removed from group level - now applied only to mutation operations
	{
		// Get tenant from context (set by tenantMiddleware)
		credHandler := func(c *gin.Context) *handler.CredentialHandler {
			tenantName := c.GetString(middleware.TenantContextKey)
			return handler.NewCredentialHandler(credStores[tenantName], roleStores[tenantName], userStore, policyStores[tenantName], iamClients[tenantName], adminClients[tenantName], adminUsernames[tenantName], groupManagers[tenantName], cfg.S3, tenantAdmins[tenantName], logger)
		}

		// GET operations - no sync needed
		settingsRoutes.GET("/credentials", func(c *gin.Context) {
			credHandler(c).ListCredentials(c)
		})
		settingsRoutes.GET("/credentials/:accessKey", func(c *gin.Context) {
			credHandler(c).GetCredential(c)
		})
		// Mutation operations - sync user after changes
		settingsRoutes.POST("/credentials", syncMiddleware, func(c *gin.Context) {
			credHandler(c).CreateCredential(c)
		})
		settingsRoutes.POST("/credentials/update-all", syncMiddleware, func(c *gin.Context) {
			credHandler(c).UpdateCredentials(c)
		})
		settingsRoutes.DELETE("/credentials/:accessKey", syncMiddleware, func(c *gin.Context) {
			credHandler(c).DeleteCredential(c)
		})

		policyHandler := func(c *gin.Context) *handler.PolicyHandler {
			tenantName := c.GetString(middleware.TenantContextKey)
			return handler.NewPolicyHandlerWithSync(policyStores[tenantName], groupStore, syncServices[tenantName], logger)
		}
		// TENANT ADMIN ONLY - Policy management
		// GET operations - no sync needed
		settingsRoutes.GET("/policies", tenantAdminMiddleware, func(c *gin.Context) {
			policyHandler(c).ListPolicies(c)
		})
		settingsRoutes.GET("/policies/:name", tenantAdminMiddleware, func(c *gin.Context) {
			policyHandler(c).GetPolicy(c)
		})
		settingsRoutes.POST("/policies/validate", tenantAdminMiddleware, func(c *gin.Context) {
			policyHandler(c).ValidatePolicy(c)
		})
		// Mutation operations - no sync needed (handled in handler)
		settingsRoutes.POST("/policies", tenantAdminMiddleware, func(c *gin.Context) {
			policyHandler(c).CreatePolicy(c)
		})
		settingsRoutes.PUT("/policies/:name", tenantAdminMiddleware, func(c *gin.Context) {
			policyHandler(c).UpdatePolicy(c)
		})
		settingsRoutes.DELETE("/policies/:name", tenantAdminMiddleware, func(c *gin.Context) {
			policyHandler(c).DeletePolicy(c)
		})

		groupHandler := func(c *gin.Context) *handler.GroupHandler {
			tenantName := c.GetString(middleware.TenantContextKey)
			// Find tenant config for policies directory
			var policiesDir string
			for _, t := range cfg.Tenants {
				if t.Name == tenantName {
					policiesDir = t.Policies.Directory
					break
				}
			}
			return handler.NewGroupHandler(roleStores[tenantName], userStore, policyStores[tenantName], groupManagers[tenantName], policiesDir, syncServices[tenantName], adminUsernames[tenantName], logger)
		}
		// Role management
		// GET operations - no sync needed (authenticated users can list roles, filtered by groups for non-admin)
		settingsRoutes.GET("/roles", func(c *gin.Context) {
			groupHandler(c).ListRoles(c)
		})
		settingsRoutes.GET("/roles/:name", tenantAdminMiddleware, func(c *gin.Context) {
			groupHandler(c).GetGroup(c)
		})
		settingsRoutes.GET("/groups", tenantAdminMiddleware, func(c *gin.Context) {
			groupHandler(c).ListGroups(c)
		})
		// TENANT ADMIN ONLY - Mutation operations - sync handled in handler (SyncAllSCIM calls)
		settingsRoutes.POST("/roles", tenantAdminMiddleware, func(c *gin.Context) {
			groupHandler(c).CreateGroup(c)
		})
		settingsRoutes.PUT("/roles/:name", tenantAdminMiddleware, func(c *gin.Context) {
			groupHandler(c).UpdateGroup(c)
		})
		settingsRoutes.DELETE("/roles/:name", tenantAdminMiddleware, func(c *gin.Context) {
			groupHandler(c).DeleteGroup(c)
		})

		// GET /settings/sram-groups - Get SRAM groups for the tenant (for role creation)
		settingsRoutes.GET("/sram-groups", tenantAdminMiddleware, func(c *gin.Context) {
			tenantName := c.GetString(middleware.TenantContextKey)

			if !cfg.SRAM.Enabled {
				c.JSON(http.StatusOK, gin.H{"Resources": []interface{}{}})
				return
			}

			// Find tenant config
			var tenantCfg *config.TenantConfig
			for i := range cfg.Tenants {
				if cfg.Tenants[i].Name == tenantName {
					tenantCfg = &cfg.Tenants[i]
					break
				}
			}

			if tenantCfg == nil || tenantCfg.SRAMCollaborationID == "" {
				c.JSON(http.StatusOK, gin.H{"Resources": []interface{}{}})
				return
			}

			// Get collaboration details from SRAM
			sramClient := sram.NewClient(cfg.SRAM.APIURL, cfg.SRAM.APIKey)
			collaboration, err := sramClient.GetCollaboration(tenantCfg.SRAMCollaborationID, cfg.OIDC.ClientID)
			if err != nil {
				logger.WithError(err).Error("Failed to get SRAM collaboration details")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch SRAM groups"})
				return
			}

			// Service connection is now handled automatically in GetCollaboration

			// Convert SRAM groups to SCIM format for frontend compatibility
			scimGroups := make([]gin.H, 0, len(collaboration.Groups))
			for _, group := range collaboration.Groups {
				scimGroups = append(scimGroups, gin.H{
					"id":          group.Identifier, // Use UUID identifier
					"displayName": group.Name,
					"shortName":   group.ShortName,
					"description": group.Description,
					"globalUrn":   group.GlobalURN,
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"Resources":    scimGroups,
				"totalResults": len(scimGroups),
			})
		})

		userHandler := func(c *gin.Context) *handler.UserHandler {
			tenantName := c.GetString(middleware.TenantContextKey)
			return handler.NewUserHandler(userManagers[tenantName], userStore, adminUsernames[tenantName], logger)
		}
		// ADMIN ONLY - User management
		// GET operations - no sync needed
		settingsRoutes.GET("/users", adminMiddleware, func(c *gin.Context) {
			userHandler(c).ListUsers(c)
		})
		settingsRoutes.GET("/users/:username/details", adminMiddleware, func(c *gin.Context) {
			userHandler(c).GetUserDetails(c)
		})
		// DELETE operation - sync handled if needed
		settingsRoutes.DELETE("/users/:username", adminMiddleware, func(c *gin.Context) {
			userHandler(c).DeleteUser(c)
		})
	}
}

func setupRootSettingsRoutes(router *gin.Engine, authMiddleware, syncMiddleware, adminMiddleware gin.HandlerFunc,
	credStores map[string]*store.CredentialStore, groupStore *store.GroupStore, userStore *store.UserStore,
	roleStores map[string]*store.GroupStore, policyStores map[string]*store.PolicyStore, iamClients map[string]*s3client.IAMClient, adminClients map[string]backend.AdminClient,
	groupManagers map[string]interface{}, syncServices map[string]*sync.SyncService, cfg *config.Config, logger *logrus.Logger, userManagers map[string]backend.UserManager, adminUsernames map[string]string, tenantAdmins map[string][]string) {

	// Root-level settings routes for global admins (when tenant context is not available)
	// These routes assume the first tenant for global admins
	rootSettingsRoutes := router.Group("/settings")
	rootSettingsRoutes.Use(authMiddleware)
	// Note: No tenant middleware, but we use the first tenant for global admins
	{
		// Get tenant for global admin (use first tenant)
		getTenantForGlobalAdmin := func(c *gin.Context) string {
			userInfoValue, exists := c.Get("userInfo")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return ""
			}
			userInfo, ok := userInfoValue.(*auth.UserInfo)
			if !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user info"})
				return ""
			}
			if userInfo.Role != auth.UserRoleGlobalAdmin {
				c.JSON(http.StatusForbidden, gin.H{"error": "Global admin access required"})
				return ""
			}
			if len(cfg.Tenants) == 0 {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No tenants configured"})
				return ""
			}
			return cfg.Tenants[0].Name
		}

		credHandler := func(c *gin.Context) *handler.CredentialHandler {
			tenantName := getTenantForGlobalAdmin(c)
			if tenantName == "" {
				return nil // Error already sent
			}
			return handler.NewCredentialHandler(credStores[tenantName], roleStores[tenantName], userStore, policyStores[tenantName], iamClients[tenantName], adminClients[tenantName], adminUsernames[tenantName], groupManagers[tenantName], cfg.S3, tenantAdmins[tenantName], logger)
		}

		// GET operations - no sync needed
		rootSettingsRoutes.GET("/credentials", func(c *gin.Context) {
			h := credHandler(c)
			if h != nil {
				h.ListCredentials(c)
			}
		})
	}
}

func main() {
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("S3 Access Manager\n")
		fmt.Printf("Version:    %s\n", version)
		fmt.Printf("Commit:     %s\n", commit)
		fmt.Printf("Build Date: %s\n", buildDate)
		os.Exit(0)
	}

	// Initialize all services
	services, cleanupCancel, err := initializeServices(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize services: %v\n", err)
		os.Exit(1)
	}
	defer cleanupCancel()

	// Setup Gin router
	if services.Cfg.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()

	// Add middleware
	router.Use(middleware.RequestLogger(services.Logger))
	router.Use(middleware.Recovery(services.Logger))
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RateLimit(100, 200)) // Increased: 100 requests/sec, burst of 200
	router.Use(middleware.CORS(services.Cfg.Security))
	router.Use(middleware.PrometheusMetrics()) // Record metrics for all requests

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		healthStatus := services.HealthChecker.GetHealth()

		status := http.StatusOK
		if !healthStatus.Healthy {
			status = http.StatusServiceUnavailable
		}

		c.JSON(status, gin.H{
			"status":         map[bool]string{true: "healthy", false: "unhealthy"}[healthStatus.Healthy],
			"version":        version,
			"sram_connected": healthStatus.SRAMConnected,
			"sram_error":     healthStatus.SRAMError,
			"tenant_health":  healthStatus.TenantHealth,
			"last_checked":   healthStatus.LastChecked,
		})
	})

	// Serve static files from root path (for direct access to localhost:9000)
	router.GET("/app.js", func(c *gin.Context) {
		c.File("./frontend/app.js")
	})
	router.GET("/styles.css", func(c *gin.Context) {
		c.File("./frontend/styles.css")
	})
	router.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./frontend/favicon.ico")
	})

	// Root-level endpoints for global admins
	router.GET("/tenants", middleware.OIDCAuth(services.Authenticator, services.Logger), func(c *gin.Context) {
		// Get user info from context
		userInfoValue, exists := c.Get("userInfo")
		isGlobalAdmin := false
		var userEmail string

		if exists {
			if userInfo, ok := userInfoValue.(*auth.UserInfo); ok {
				isGlobalAdmin = userInfo.Role == auth.UserRoleGlobalAdmin
				userEmail = userInfo.Email
			}
		}

		tenants := make([]gin.H, 0, len(services.Cfg.Tenants))

		// If SRAM is enabled and user is not global admin, filter tenants by membership
		if services.Cfg.SRAM.Enabled && !isGlobalAdmin && userEmail != "" {
			sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)

			for _, tenant := range services.Cfg.Tenants {
				// Load tenant config to get collaboration ID
				tenantCfg, err := config.LoadTenantConfig(tenant.Name)
				if err != nil {
					services.Logger.WithError(err).WithField("tenant", tenant.Name).Warn("Failed to load tenant config")
					continue
				}

				if tenantCfg.SRAMCollaborationID == "" {
					// No SRAM collaboration, skip
					continue
				}

				// Get collaboration details
				collaboration, err := sramClient.GetCollaboration(tenantCfg.SRAMCollaborationID, services.Cfg.OIDC.ClientID)
				if err != nil {
					services.Logger.WithError(err).WithField("tenant", tenant.Name).Warn("Failed to get collaboration details")
					// For testing: if SRAM API fails, include tenant anyway for tenant admins
					// This allows the tenant switcher to work in test environments
					tenants = append(tenants, gin.H{
						"name":        tenant.Name,
						"description": "Manage S3 access and resources",
					})
					continue
				}

				// Check if user is a member (check collaboration_memberships)
				isMember := false
				for _, membership := range collaboration.Memberships {
					if membership.User.Email == userEmail {
						isMember = true
						break
					}
				}

				if isMember {
					tenants = append(tenants, gin.H{
						"name":        tenant.Name,
						"description": "Manage S3 access and resources",
					})
				}
			}

			// If no tenants were found (either no access or API failures),
			// fall back to showing all tenants for tenant admins in test environments
			if len(tenants) == 0 {
				services.Logger.Warn("No tenants accessible via SRAM, falling back to showing all tenants for tenant admin")
				for _, tenant := range services.Cfg.Tenants {
					tenants = append(tenants, gin.H{
						"name":        tenant.Name,
						"description": "Manage S3 access and resources",
					})
				}
			}
		} else {
			// Global admin or SRAM not enabled - show all tenants
			for _, tenant := range services.Cfg.Tenants {
				tenants = append(tenants, gin.H{
					"name":        tenant.Name,
					"description": "Manage S3 access and resources",
				})
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"tenants":         tenants,
			"is_global_admin": isGlobalAdmin,
		})
	})

	// POST /tenants - Create a new tenant (global admin only)
	router.POST("/tenants", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		var req struct {
			Name         string   `json:"name" binding:"required"`
			Description  string   `json:"description"`
			AdminEmails  []string `json:"admin_emails" binding:"required,min=1"`
			IamAccessKey string   `json:"iam_access_key"`
			IamSecretKey string   `json:"iam_secret_key"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		// Validate tenant name (basic validation)
		if len(req.Name) == 0 || len(req.Name) > 50 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant name must be 1-50 characters"})
			return
		}

		// Validate admin emails
		if len(req.AdminEmails) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "At least one admin email is required"})
			return
		}

		// IAM credentials are optional during tenant creation
		// They can be added later to make the tenant healthy

		// Check if tenant already exists
		for _, tenant := range services.Cfg.Tenants {
			if tenant.Name == req.Name {
				c.JSON(http.StatusConflict, gin.H{"error": "Tenant already exists"})
				return
			}
		}

		var sramCollaborationID string
		var invitationIDs []string

		// Create SRAM collaboration if enabled
		if services.Cfg.SRAM.Enabled {
			sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)

			// Build administrators list: include both platform admins and tenant admins
			administrators := make([]string, 0)
			administrators = append(administrators, req.AdminEmails...) // Add tenant administrators

			// Remove duplicates
			adminSet := make(map[string]bool)
			uniqueAdmins := make([]string, 0)
			for _, admin := range administrators {
				if admin != "" && !adminSet[admin] {
					adminSet[admin] = true
					uniqueAdmins = append(uniqueAdmins, admin)
				}
			}

			// Create collaboration
			collabReq := sram.CollaborationRequest{
				ShortName:                 req.Name,
				Name:                      fmt.Sprintf("S3 Gateway - %s", req.Name),
				Description:               fmt.Sprintf("S3 Access Manager tenant: %s", req.Description),
				DisableJoinRequests:       true,
				DiscloseMemberInformation: false,
				DiscloseEmailInformation:  false,
				Administrators:            []string{}, // empty here, we'll add admins via invitations
			}

			collabResp, err := sramClient.CreateCollaboration(collabReq)
			if err != nil {
				services.Logger.WithError(err).Warn("Failed to create SRAM collaboration")
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create SRAM collaboration: %v", err)})
				return
			}

			// Store the UUID identifier, not the numeric ID
			sramCollaborationID = collabResp.Identifier
			services.Logger.WithFields(logrus.Fields{
				"tenant":           req.Name,
				"collaboration_id": sramCollaborationID,
			}).Info("SRAM collaboration created")

			// Service connection will happen during admin sync after invitations are accepted
			// This ensures at least one tenant admin has accepted before connecting to the service

			// Send invitations to tenant admins
			invites := make([]string, 0, len(uniqueAdmins))
			for _, email := range uniqueAdmins {
				invites = append(invites, email)
			}

			// Set expiry dates to 30 days from now
			expiryTime := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

			inviteReq := sram.InvitationRequest{
				// ShortName:               req.Name,
				CollaborationIdentifier: collabResp.Identifier,
				Message:                 fmt.Sprintf("You have been invited to manage the %s tenant in S3 Access Manager.", req.Name),
				IntendedRole:            "admin",
				SenderName:              "S3 Access Manager",
				InvitationExpiryDate:    expiryTime,
				MembershipExpiryDate:    expiryTime,
				Invites:                 invites,
				Groups:                  []string{}, // Empty for now, can be populated if needed
			}

			inviteResp, err := sramClient.SendInvitation(inviteReq)
			if err != nil {
				services.Logger.WithError(err).Warn("Failed to send SRAM invitations")
				// Don't fail the tenant creation, just log the error
			} else {
				for _, invite := range inviteResp {
					invitationIDs = append(invitationIDs, invite.InvitationID)
				}
				services.Logger.WithFields(logrus.Fields{
					"tenant":         req.Name,
					"admin_emails":   req.AdminEmails,
					"invitation_ids": invitationIDs,
				}).Info("SRAM invitations sent")
			}
		}

		// Create tenant directory structure
		tenantDir := fmt.Sprintf("./data/tenants/%s", req.Name)
		if err := os.MkdirAll(tenantDir, 0755); err != nil {
			services.Logger.WithError(err).Error("Failed to create tenant directory")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant directory"})
			return
		}

		// Create subdirectories
		subdirs := []string{"policies", "roles"}
		for _, subdir := range subdirs {
			if err := os.MkdirAll(fmt.Sprintf("%s/%s", tenantDir, subdir), 0755); err != nil {
				services.Logger.WithError(err).Error("Failed to create tenant subdirectory")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant subdirectories"})
				return
			}
		}

		// Create default config.yaml with SRAM collaboration ID
		var configContent strings.Builder
		configContent.WriteString("tenant_admins:\n")
		for _, email := range req.AdminEmails {
			configContent.WriteString(fmt.Sprintf("- \"%s\"\n", email))
		}
		if sramCollaborationID != "" {
			configContent.WriteString(fmt.Sprintf("sram_collaboration_id: \"%s\"\n", sramCollaborationID))
		}
		if req.IamAccessKey != "" && req.IamSecretKey != "" {
			configContent.WriteString(fmt.Sprintf("iam:\n  access_key: \"%s\"\n  secret_key: \"%s\"\n", req.IamAccessKey, req.IamSecretKey))
		}

		configPath := fmt.Sprintf("%s/config.yaml", tenantDir)
		if err := os.WriteFile(configPath, []byte(configContent.String()), 0644); err != nil {
			services.Logger.WithError(err).Error("Failed to create tenant config file")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant config"})
			return
		}

		// Create default policies
		defaultPolicies := map[string]string{
			"Read-Only.json": `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
		"s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}`,
			"Read-Write.json": `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:ListAllMyBuckets",
        "s3:CreateBucket",
        "s3:DeleteBucket"
      ],
      "Resource": "*"
    }
  ]
}`,
		}

		for policyName, policyContent := range defaultPolicies {
			policyPath := fmt.Sprintf("%s/policies/%s", tenantDir, policyName)
			if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
				services.Logger.WithError(err).Error("Failed to create default policy")
				// Continue, don't fail the whole operation
			}
		}

		// Load the newly created tenant config into memory
		newTenantCfg, err := config.LoadTenantConfig(req.Name)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to load newly created tenant config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Tenant created but failed to load into memory"})
			return
		}

		// Add to in-memory config
		services.Cfg.Tenants = append(services.Cfg.Tenants, *newTenantCfg)

		response := gin.H{
			"name":        req.Name,
			"description": req.Description,
			"message":     "Tenant created successfully.",
		}

		if services.Cfg.SRAM.Enabled {
			response["sram_collaboration_id"] = sramCollaborationID
			response["invitation_ids"] = invitationIDs
			response["sram_message"] = "SRAM collaboration created and invitation sent to tenant admin."
		}

		services.Logger.WithField("tenant", req.Name).Info("Tenant created successfully")
		c.JSON(http.StatusCreated, response)
	})

	// PUT /tenants/:name - Update a tenant (global admin only)
	router.PUT("/tenants/:name", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		var req struct {
			Description  string   `json:"description"`
			AdminEmails  []string `json:"admin_emails" binding:"required,min=1"`
			IamAccessKey string   `json:"iam_access_key"`
			IamSecretKey string   `json:"iam_secret_key"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		// Validate admin emails
		if len(req.AdminEmails) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "At least one admin email is required"})
			return
		}

		// Check if tenant exists
		tenantIndex := -1
		for i, tenant := range services.Cfg.Tenants {
			if tenant.Name == tenantName {
				tenantIndex = i
				break
			}
		}

		if tenantIndex == -1 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		// Update tenant config
		tenantDir := fmt.Sprintf("./data/tenants/%s", tenantName)
		configPath := fmt.Sprintf("%s/config.yaml", tenantDir)

		// Read existing config to preserve other settings
		existingConfig, err := os.ReadFile(configPath)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to read existing tenant config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read tenant config"})
			return
		}

		// Parse existing config to update only the fields we want
		var config map[string]interface{}
		if err := yaml.Unmarshal(existingConfig, &config); err != nil {
			services.Logger.WithError(err).Error("Failed to parse existing tenant config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse tenant config"})
			return
		}

		// Update tenant_admins and iam fields
		config["tenant_admins"] = req.AdminEmails
		if len(req.IamAccessKey) > 0 && len(req.IamSecretKey) > 0 {
			config["iam"] = map[string]string{
				"access_key": req.IamAccessKey,
				"secret_key": req.IamSecretKey,
			}
		}

		// Write updated config
		updatedConfig, err := yaml.Marshal(config)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to marshal updated tenant config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant config"})
			return
		}

		if err := os.WriteFile(configPath, updatedConfig, 0644); err != nil {
			services.Logger.WithError(err).Error("Failed to write updated tenant config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant config"})
			return
		}

		services.Logger.WithField("tenant", tenantName).Info("Tenant updated successfully")
		c.JSON(http.StatusOK, gin.H{
			"name":        tenantName,
			"description": req.Description,
			"message":     "Tenant updated successfully",
		})
	})

	// DELETE /tenants/:name - Delete a tenant (global admin only)
	router.DELETE("/tenants/:name", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		// Check if tenant exists
		tenantIndex := -1
		var tenant *config.TenantConfig
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenantIndex = i
				tenant = &services.Cfg.Tenants[i]
				break
			}
		}

		if tenantIndex == -1 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		services.Logger.WithField("tenant", tenantName).Info("Starting tenant deletion process")

		// Step 1: Delete SRAM collaboration if it exists
		if services.Cfg.SRAM.Enabled && tenant.SRAMCollaborationID != "" {
			sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)
			if err := sramClient.DeleteCollaboration(tenant.SRAMCollaborationID); err != nil {
				services.Logger.WithError(err).Error("Failed to delete SRAM collaboration")
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete SRAM collaboration: %v", err)})
				return
			}
			services.Logger.WithField("collaboration_id", tenant.SRAMCollaborationID).Info("Deleted SRAM collaboration")
		}

		// Step 2: Delete all IAM users and their credentials
		if iamClient, exists := services.IAMClients[tenantName]; exists {
			ctx := context.Background()

			// Get all users
			users, err := iamClient.ListUsers(ctx)
			if err != nil {
				services.Logger.WithError(err).Warn("Failed to list IAM users for cleanup")
			} else {
				for _, username := range users {
					// Delete all access keys for this user
					accessKeys, err := iamClient.ListAccessKeys(ctx, username)
					if err != nil {
						services.Logger.WithError(err).WithField("username", username).Warn("Failed to list access keys for user")
					} else {
						for _, accessKeyID := range accessKeys {
							if err := iamClient.DeleteAccessKey(ctx, username, accessKeyID); err != nil {
								services.Logger.WithError(err).WithFields(logrus.Fields{
									"username":   username,
									"access_key": accessKeyID,
								}).Warn("Failed to delete access key")
							} else {
								services.Logger.WithFields(logrus.Fields{
									"username":   username,
									"access_key": accessKeyID,
								}).Info("Deleted IAM access key")
							}
						}
					}

					// Delete user policies
					policies, err := iamClient.ListUserPolicies(ctx, username)
					if err != nil {
						services.Logger.WithError(err).WithField("username", username).Warn("Failed to list user policies")
					} else {
						for _, policyName := range policies {
							if err := iamClient.DeleteUserPolicy(ctx, username, policyName); err != nil {
								services.Logger.WithError(err).WithFields(logrus.Fields{
									"username": username,
									"policy":   policyName,
								}).Warn("Failed to delete user policy")
							} else {
								services.Logger.WithFields(logrus.Fields{
									"username": username,
									"policy":   policyName,
								}).Info("Deleted IAM user policy")
							}
						}
					}

					// Delete the user
					if err := iamClient.DeleteUser(ctx, username); err != nil {
						services.Logger.WithError(err).WithField("username", username).Warn("Failed to delete IAM user")
					} else {
						services.Logger.WithField("username", username).Info("Deleted IAM user")
					}
				}
			}
		}

		// Step 3: Delete all IAM groups
		if groupManagerInterface, exists := services.GroupManagers[tenantName]; exists {
			if groupManager, ok := groupManagerInterface.(*awscli.GroupManager); ok {
				ctx := context.Background()

				// Get all groups
				groups, err := groupManager.ListGroups(ctx)
				if err != nil {
					services.Logger.WithError(err).Warn("Failed to list IAM groups for cleanup")
				} else {
					for _, groupName := range groups {
						// Note: AWS IAM requires groups to be empty before deletion
						// The group manager's DeleteGroup should handle removing users from groups first
						if err := groupManager.DeleteGroup(ctx, groupName); err != nil {
							services.Logger.WithError(err).WithField("group", groupName).Warn("Failed to delete IAM group")
						} else {
							services.Logger.WithField("group", groupName).Info("Deleted IAM group")
						}
					}
				}
			} else {
				services.Logger.Warn("Group manager is not of expected type for tenant cleanup")
			}
		}

		// Step 4: Delete all buckets (if possible)
		// Note: This is optional and may fail if buckets contain objects or have retention policies
		if s3Client := services.S3Client; s3Client != nil {
			// We would need to list and delete buckets, but this is complex and potentially destructive
			// For now, we'll log that manual cleanup may be needed
			services.Logger.WithField("tenant", tenantName).Warn("Manual bucket cleanup may be required - buckets are not automatically deleted")
		}

		// Step 5: Remove tenant from in-memory config
		services.Cfg.Tenants = append(services.Cfg.Tenants[:tenantIndex], services.Cfg.Tenants[tenantIndex+1:]...)

		// Clean up in-memory service maps
		delete(services.IAMClients, tenantName)
		delete(services.AdminClients, tenantName)
		delete(services.UserManagers, tenantName)
		delete(services.GroupManagers, tenantName)
		delete(services.CredStores, tenantName)
		delete(services.RoleStores, tenantName)
		delete(services.PolicyStores, tenantName)
		delete(services.PolicyEngines, tenantName)
		delete(services.SyncServices, tenantName)
		delete(services.AdminUsernames, tenantName)

		// Update tenantAdmins map
		// Recreate the tenantAdmins map since the original is not in scope
		updatedTenantAdmins := make(map[string][]string)
		for _, remainingTenant := range services.Cfg.Tenants {
			if remainingTenant.Name != tenantName { // Skip the deleted tenant
				updatedTenantAdmins[remainingTenant.Name] = remainingTenant.TenantAdmins
			}
		}
		// Note: We can't update the middleware's tenantAdmins map directly here
		// The middleware will need to be reinitialized on next restart

		// Step 6: Delete tenant directory
		tenantDir := fmt.Sprintf("./data/tenants/%s", tenantName)
		if err := os.RemoveAll(tenantDir); err != nil {
			services.Logger.WithError(err).Error("Failed to delete tenant directory")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant directory"})
			return
		}

		services.Logger.WithField("tenant", tenantName).Info("Tenant deletion completed successfully")
		c.JSON(http.StatusOK, gin.H{
			"message": "Tenant deleted successfully",
		})
	})

	// GET /tenants/:name - Get detailed tenant information (global admin only)
	router.GET("/tenants/:name", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		// Find tenant
		var tenant *config.TenantConfig
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenant = &services.Cfg.Tenants[i]
				break
			}
		}

		if tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		// Mask IAM secret key (show only first/last 4 chars)
		maskedSecretKey := ""
		if tenant.IAM.SecretKey != "" {
			if len(tenant.IAM.SecretKey) > 8 {
				maskedSecretKey = tenant.IAM.SecretKey[:4] + "****" + tenant.IAM.SecretKey[len(tenant.IAM.SecretKey)-4:]
			} else {
				maskedSecretKey = "********"
			}
		}

		response := gin.H{
			"name":                  tenant.Name,
			"description":           "Manage S3 access and resources",
			"admin_emails":          tenant.TenantAdmins,
			"iam_access_key":        tenant.IAM.AccessKey,
			"iam_secret_key_masked": maskedSecretKey,
			"sram_collaboration_id": tenant.SRAMCollaborationID,
			"has_iam_credentials":   tenant.IAM.AccessKey != "" && tenant.IAM.SecretKey != "",
		}

		c.JSON(http.StatusOK, response)
	})

	// GET /tenants/:name/sram-invitations - Get SRAM invitation status for a tenant (global admin only)
	router.GET("/tenants/:name/sram-invitations", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		if !services.Cfg.SRAM.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SRAM integration is not enabled"})
			return
		}

		// Find tenant
		var tenant *config.TenantConfig
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenant = &services.Cfg.Tenants[i]
				break
			}
		}

		if tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		if tenant.SRAMCollaborationID == "" {
			c.JSON(http.StatusOK, gin.H{
				"message":     "No SRAM collaboration associated with this tenant",
				"invitations": []interface{}{},
			})
			return
		}

		// Get invitation status from SRAM
		sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)
		invitations, err := sramClient.GetCollaborationInvitations(tenant.SRAMCollaborationID)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to get SRAM invitations")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get SRAM invitations: %v", err)})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"tenant":           tenantName,
			"collaboration_id": tenant.SRAMCollaborationID,
			"invitations":      invitations,
			"invitation_count": len(invitations),
		})
	})

	// GET /tenants/:name/sram-collaboration - Get SRAM collaboration details including members (authenticated users only)
	router.GET("/tenants/:name/sram-collaboration", middleware.OIDCAuth(services.Authenticator, services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		if !services.Cfg.SRAM.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SRAM integration is not enabled"})
			return
		}

		// Find tenant
		var tenant *config.TenantConfig
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenant = &services.Cfg.Tenants[i]
				break
			}
		}

		if tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		if tenant.SRAMCollaborationID == "" {
			c.JSON(http.StatusOK, gin.H{
				"message": "No SRAM collaboration associated with this tenant",
			})
			return
		}

		// Get collaboration details from SRAM
		sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)
		collaboration, err := sramClient.GetCollaboration(tenant.SRAMCollaborationID, services.Cfg.OIDC.ClientID)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to get SRAM collaboration details")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get SRAM collaboration: %v", err)})
			return
		}

		// Service connection is now handled automatically in GetCollaboration

		c.JSON(http.StatusOK, gin.H{
			"tenant":        tenantName,
			"collaboration": collaboration,
		})
	})

	// GET /tenants/:name/sram-groups - Get SRAM groups for a tenant (authenticated users only)
	router.GET("/tenants/:name/sram-groups", middleware.OIDCAuth(services.Authenticator, services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		if !services.Cfg.SRAM.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SRAM integration is not enabled"})
			return
		}

		// Find tenant
		var tenant *config.TenantConfig
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenant = &services.Cfg.Tenants[i]
				break
			}
		}

		if tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		if tenant.SRAMCollaborationID == "" {
			c.JSON(http.StatusOK, gin.H{
				"groups": []interface{}{},
			})
			return
		}

		// Get collaboration details from SRAM to extract groups
		sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)
		collaboration, err := sramClient.GetCollaboration(tenant.SRAMCollaborationID, services.Cfg.OIDC.ClientID)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to get SRAM collaboration details")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get SRAM groups: %v", err)})
			return
		}

		// Service connection is now handled automatically in GetCollaboration

		c.JSON(http.StatusOK, gin.H{
			"tenant": tenantName,
			"groups": collaboration.Groups,
		})
	})

	// Build tenant names for tenant middleware
	tenantNames := make([]string, 0, len(services.Cfg.Tenants))
	for _, tenant := range services.Cfg.Tenants {
		tenantNames = append(tenantNames, tenant.Name)
	}
	tenantMiddleware := middleware.TenantAuth(tenantNames, services.Logger)

	oidcConfigHandler := handler.NewOIDCConfigHandler(services.Cfg)

	// Global OIDC config endpoint for login screen
	router.GET("/oidc-config", func(c *gin.Context) {
		oidcConfigHandler.GetOIDCConfig(c)
	})

	router.GET("/tenant/:tenant/oidc-config", tenantMiddleware, oidcConfigHandler.GetOIDCConfig)

	// Metrics endpoint
	if services.Cfg.Monitoring.MetricsEnabled {
		router.GET("/metrics", handler.MetricsHandler())
	}

	// Apply authentication middleware
	authMiddleware := middleware.OIDCAuth(services.Authenticator, services.Logger)

	// Apply S3 authentication middleware (supports both OIDC and access key auth)
	s3AuthMiddleware := middleware.S3Auth(services.Authenticator, services.CredStores, services.Logger)

	// Apply user sync middleware (syncs IAM user/policies after authentication)
	syncMiddleware := middleware.Sync(services.SyncServices, services.Logger)

	// Admin middleware - requires admin role
	adminMiddleware := middleware.RequireAdmin(services.Logger)

	// Build tenant admins map for all tenants
	tenantAdmins := make(map[string][]string)
	for _, tenant := range services.Cfg.Tenants {
		tenantAdmins[tenant.Name] = tenant.TenantAdmins
	}

	// POST /tenants/:name/sync-sram-admins - Sync accepted SRAM invitations to tenant config (global admin only)
	// This must be after tenantAdmins map is created
	router.POST("/tenants/:name/sync-sram-admins", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		if !services.Cfg.SRAM.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SRAM integration is not enabled"})
			return
		}

		// Find tenant
		var tenant *config.TenantConfig
		var tenantIndex int
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenant = &services.Cfg.Tenants[i]
				tenantIndex = i
				break
			}
		}

		if tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		if tenant.SRAMCollaborationID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No SRAM collaboration associated with this tenant"})
			return
		}

		// Get invitation status from SRAM
		sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)
		invitations, err := sramClient.GetCollaborationInvitations(tenant.SRAMCollaborationID)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to get SRAM invitations")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get SRAM invitations: %v", err)})
			return
		}

		// Collect accepted SRAM usernames
		var acceptedUsernames []string
		var acceptedEmails []string
		for _, inv := range invitations {
			if inv.Status == "accepted" && inv.SRAMUsername != "" {
				acceptedUsernames = append(acceptedUsernames, inv.SRAMUsername)
				acceptedEmails = append(acceptedEmails, inv.Email)
			}
		}

		if len(acceptedUsernames) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"message": "No accepted invitations with SRAM usernames found",
				"synced":  0,
			})
			return
		}

		// Update tenant config with new SRAM usernames (avoiding duplicates)
		existingAdmins := make(map[string]bool)
		for _, admin := range tenant.TenantAdmins {
			existingAdmins[admin] = true
		}

		var newAdmins []string
		for _, username := range acceptedUsernames {
			if !existingAdmins[username] {
				tenant.TenantAdmins = append(tenant.TenantAdmins, username)
				newAdmins = append(newAdmins, username)
				existingAdmins[username] = true
			}
		}

		// Update the config in memory
		services.Cfg.Tenants[tenantIndex] = *tenant

		// Also update the in-memory tenantAdmins map used by middleware
		tenantAdmins[tenantName] = tenant.TenantAdmins

		// Save updated config to file
		if err := services.Cfg.SaveToFile("config.yaml"); err != nil {
			services.Logger.WithError(err).Error("Failed to save updated config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save config: %v", err)})
			return
		}

		services.Logger.WithField("tenant", tenantName).
			WithField("new_admins", newAdmins).
			Info("Synced SRAM admins to tenant config")

		// Ensure service connection if collaboration has active admins and OIDC service is configured
		// This ensures the service is connected whenever there are active admins, regardless of when they were accepted
		if services.Cfg.OIDC.ClientID != "" {
			sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)

			// Get collaboration details to trigger automatic service connection
			_, err := sramClient.GetCollaboration(tenant.SRAMCollaborationID, services.Cfg.OIDC.ClientID)
			if err != nil {
				services.Logger.WithError(err).Warn("Failed to get collaboration details during admin sync")
			} else {
				// Service connection is now handled automatically in GetCollaboration
				services.Logger.WithFields(logrus.Fields{
					"tenant":           tenantName,
					"collaboration_id": tenant.SRAMCollaborationID,
					"service_id":       services.Cfg.OIDC.ClientID,
				}).Debug("Service connection ensured automatically during collaboration fetch")
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"message":        "SRAM admins synced successfully",
			"synced":         len(newAdmins),
			"new_admins":     newAdmins,
			"total_admins":   len(tenant.TenantAdmins),
			"accepted_users": acceptedEmails,
		})
	})

	// POST /tenants/:name/sram-refresh - Refresh SRAM collaboration status for a tenant (global admin only)
	router.POST("/tenants/:name/sram-refresh", middleware.OIDCAuth(services.Authenticator, services.Logger), middleware.RequireAdmin(services.Logger), func(c *gin.Context) {
		tenantName := c.Param("name")

		if !services.Cfg.SRAM.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SRAM integration is not enabled"})
			return
		}

		// Find tenant
		var tenant *config.TenantConfig
		for i := range services.Cfg.Tenants {
			if services.Cfg.Tenants[i].Name == tenantName {
				tenant = &services.Cfg.Tenants[i]
				break
			}
		}

		if tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}

		if tenant.SRAMCollaborationID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No SRAM collaboration associated with this tenant"})
			return
		}

		// Get SRAM client and check admin acceptance
		sramClient := sram.NewClient(services.Cfg.SRAM.APIURL, services.Cfg.SRAM.APIKey)
		collaboration, err := sramClient.GetCollaboration(tenant.SRAMCollaborationID, services.Cfg.OIDC.ClientID)
		if err != nil {
			services.Logger.WithError(err).Error("Failed to get SRAM collaboration for refresh")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get SRAM collaboration: %v", err)})
			return
		}

		// Check if at least one admin has accepted
		adminAccepted := false
		for _, membership := range collaboration.Memberships {
			if membership.Role == "admin" && membership.Status == "active" {
				adminAccepted = true
				break
			}
		}

		services.Logger.WithFields(logrus.Fields{
			"tenant":         tenantName,
			"collaboration":  tenant.SRAMCollaborationID,
			"admin_accepted": adminAccepted,
		}).Info("Refreshed SRAM collaboration status")

		c.JSON(http.StatusOK, gin.H{
			"tenant":           tenantName,
			"collaboration_id": tenant.SRAMCollaborationID,
			"admin_accepted":   adminAccepted,
			"refreshed_at":     time.Now().Format(time.RFC3339),
		})
	})

	// Settings/Credentials management endpoints (authenticated)
	setupSettingsRoutes(router, authMiddleware, syncMiddleware, adminMiddleware,
		services.CredStores, services.GroupStore, services.UserStore, services.RoleStores, services.PolicyStores, services.IAMClients, services.AdminClients, services.GroupManagers,
		services.SyncServices, services.Cfg, services.Logger, services.UserManagers, services.AdminUsernames)

	// Also set up root-level settings routes for global admins (when tenant context is not available)
	setupRootSettingsRoutes(router, authMiddleware, syncMiddleware, adminMiddleware,
		services.CredStores, services.GroupStore, services.UserStore, services.RoleStores, services.PolicyStores, services.IAMClients, services.AdminClients, services.GroupManagers,
		services.SyncServices, services.Cfg, services.Logger, services.UserManagers, services.AdminUsernames, tenantAdmins)

	// S3 proxy endpoints - users must be authenticated and select a credential
	s3Handler := handler.NewS3Handler(services.S3Client, services.Cfg.S3, services.IAMClients, services.CredStores, services.GroupStore, services.UserStore, services.PolicyEngines, services.Logger)

	// S3 routes - support both OIDC authentication (web UI) and access key authentication (CLI)
	// Removed /s3/ prefix to handle S3 operations at root level for AWS CLI compatibility
	// s3Routes := router.Group("/s3")
	// s3Routes.Use(s3AuthMiddleware) // Supports both OIDC and access key auth
	// s3Routes.Use(syncMiddleware)   // Sync IAM user/policies after auth
	// {
	// 	// Match all S3-like paths: /s3/{bucket}/{key...}
	// 	// Web UI: Frontend must send X-S3-Credential-AccessKey header with selected credential
	// 	// CLI: AWS CLI sends Authorization header with access key
	// 	s3Routes.Any("/*proxyPath", s3Handler.ProxyRequest)
	// Root path handler - serves S3 operations (for CLI) or frontend (for web UI)
	rootHandler := func(c *gin.Context) {
		// Extract bucket and key from path
		path := strings.TrimPrefix(c.Request.URL.Path, "/")
		path = strings.TrimPrefix(path, "s3/")
		parts := strings.SplitN(path, "/", 2)
		bucket := parts[0]

		if bucket == "" {
			// Root path - check if S3 list buckets request
			authHeader := c.GetHeader("Authorization")
			credHeader := c.GetHeader("X-S3-Credential-AccessKey")
			if (authHeader != "" && strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256")) || credHeader != "" {
				// S3 list buckets request
				s3AuthMiddleware(c)
				if c.IsAborted() {
					return // Auth failed
				}
				syncMiddleware(c)
				if c.IsAborted() {
					return // Sync failed
				}
				s3Handler.ListBuckets(c)
				return
			}
			// Not S3 request - serve frontend (login screen or tenant selection for authenticated global admins)
			// The frontend JavaScript will handle authentication and determine what screen to show
			c.File("./frontend/index.html")
			return
		}

		// Bucket/key path, extract key
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}

		// This is a bucket/key path, handle as S3 request (requires auth)
		s3AuthMiddleware(c)
		if c.IsAborted() {
			return // Auth failed, response already sent
		}
		syncMiddleware(c)
		if c.IsAborted() {
			return // Sync failed, response already sent
		}

		// Get user info and credential from context
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

		credValue, exists := c.Get("selectedCredential")
		if !exists {
			c.Header("Content-Type", "application/xml")
			c.XML(http.StatusBadRequest, gin.H{
				"Error": gin.H{
					"Code":    "InvalidRequest",
					"Message": "No credential available",
				},
			})
			return
		}
		cred := credValue.(*store.Credential)

		// Create S3 client for user
		tenantName := c.GetString("tenant")
		s3Client, err := s3Handler.CreateUserS3Client(c.Request.Context(), tenantName, cred)
		if err != nil {
			c.Header("Content-Type", "application/xml")
			c.XML(http.StatusInternalServerError, gin.H{
				"Error": gin.H{
					"Code":    "InternalError",
					"Message": "Failed to create S3 client",
				},
			})
			return
		}

		s3Handler.ProxyToS3(c, s3Client, bucket, key, userInfo)
	}
	// Serve index.html for OIDC callback (frontend handles the callback in JavaScript)
	router.GET("/tenant/:tenant/callback", tenantMiddleware, func(c *gin.Context) {
		c.File("./frontend/index.html")
	})
	// Also serve callback from root path (for cases where tenant context is not set)
	router.GET("/callback", func(c *gin.Context) {
		c.File("./frontend/index.html")
	})
	// Serve specific static files
	router.GET("/tenant/:tenant/app.js", tenantMiddleware, func(c *gin.Context) {
		c.File("./frontend/app.js")
	})
	router.GET("/tenant/:tenant/styles.css", tenantMiddleware, func(c *gin.Context) {
		c.File("./frontend/styles.css")
	})
	router.GET("/tenant/:tenant/favicon.ico", tenantMiddleware, func(c *gin.Context) {
		c.File("./frontend/favicon.ico")
	})
	// Handle any other static assets
	router.GET("/tenant/:tenant/assets/*filepath", tenantMiddleware, func(c *gin.Context) {
		http.StripPrefix("/tenant/"+c.Param("tenant"), http.FileServer(http.Dir("./frontend"))).ServeHTTP(c.Writer, c.Request)
	})
	router.GET("/tenant/:tenant/css/*filepath", tenantMiddleware, func(c *gin.Context) {
		http.StripPrefix("/tenant/"+c.Param("tenant"), http.FileServer(http.Dir("./frontend"))).ServeHTTP(c.Writer, c.Request)
	})
	router.GET("/tenant/:tenant/js/*filepath", tenantMiddleware, func(c *gin.Context) {
		http.StripPrefix("/tenant/"+c.Param("tenant"), http.FileServer(http.Dir("./frontend"))).ServeHTTP(c.Writer, c.Request)
	})

	// Handle tenant root - serve frontend
	router.GET("/tenant/:tenant/", tenantMiddleware, func(c *gin.Context) {
		c.File("./frontend/index.html")
	})
	router.GET("/tenant/:tenant", tenantMiddleware, func(c *gin.Context) {
		c.File("./frontend/index.html")
	})

	// Handle unmatched routes as potential S3 operations (for AWS CLI compatibility)
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if this is a tenant-prefixed request
		if strings.HasPrefix(path, "/tenant/") {
			// Apply tenant middleware
			tenantMiddleware(c)
			if c.IsAborted() {
				return
			}

			// Remove tenant prefix and handle as frontend or S3 request
			tenantName := c.GetString(middleware.TenantContextKey)
			remainingPath := strings.TrimPrefix(path, "/tenant/"+tenantName)

			if remainingPath == "" || remainingPath == "/" {
				// Tenant root - check if S3 list buckets request
				authHeader := c.GetHeader("Authorization")
				credHeader := c.GetHeader("X-S3-Credential-AccessKey")
				if (authHeader != "" && strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256")) || credHeader != "" {
					// S3 list buckets request for tenant
					s3AuthMiddleware(c)
					if c.IsAborted() {
						return // Auth failed
					}
					syncMiddleware(c)
					if c.IsAborted() {
						return // Sync failed
					}
					s3Handler.ListBuckets(c)
					return
				}
				// Not S3 request, serve frontend
				c.File("./frontend/index.html")
				return
			}

			// Check if it's a static file request
			if strings.HasPrefix(remainingPath, "/app.js") ||
				strings.HasPrefix(remainingPath, "/styles.css") ||
				strings.HasPrefix(remainingPath, "/favicon.ico") ||
				strings.HasPrefix(remainingPath, "/assets/") ||
				strings.HasPrefix(remainingPath, "/css/") ||
				strings.HasPrefix(remainingPath, "/js/") {
				// Serve static file
				c.Request.URL.Path = remainingPath
				http.FileServer(http.Dir("./frontend")).ServeHTTP(c.Writer, c.Request)
				return
			}

			// Handle as tenant S3 operation
			// Extract bucket and key from remaining path
			s3Path := strings.TrimPrefix(remainingPath, "/")
			s3Path = strings.TrimPrefix(s3Path, "s3/")
			parts := strings.SplitN(s3Path, "/", 2)
			bucket := parts[0]

			if bucket == "" {
				// Invalid S3 path for tenant
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid S3 path"})
				return
			}

			// Bucket/key path, extract key
			key := ""
			if len(parts) > 1 {
				key = parts[1]
			}

			// Handle as tenant S3 request (requires auth)
			s3AuthMiddleware(c)
			if c.IsAborted() {
				return // Auth failed, response already sent
			}
			syncMiddleware(c)
			if c.IsAborted() {
				return // Sync failed, response already sent
			}

			// Get user info and credential from context
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

			credValue, exists := c.Get("selectedCredential")
			if !exists {
				c.Header("Content-Type", "application/xml")
				c.XML(http.StatusBadRequest, gin.H{
					"Error": gin.H{
						"Code":    "InvalidRequest",
						"Message": "No credential available",
					},
				})
				return
			}
			cred := credValue.(*store.Credential)

			// Create S3 client for user
			tenant := c.GetString("tenant")
			s3Client, err := s3Handler.CreateUserS3Client(c.Request.Context(), tenant, cred)
			if err != nil {
				c.Header("Content-Type", "application/xml")
				c.XML(http.StatusInternalServerError, gin.H{
					"Error": gin.H{
						"Code":    "InternalError",
						"Message": "Failed to create S3 client",
					},
				})
				return
			}

			s3Handler.ProxyToS3(c, s3Client, bucket, key, userInfo)
			return
		}

		// Original root handler logic for non-tenant requests
		rootHandler(c)
	})

	// Start server
	startServer(router, services.Cfg, services.Logger)
}

func startServer(router *gin.Engine, cfg *config.Config, logger *logrus.Logger) {
	// Create HTTP server with optimized settings for concurrency
	srv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:        router,
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
		// Allow more concurrent connections
	}

	// Start server in goroutine
	go func() {
		logger.WithFields(logrus.Fields{
			"host":             cfg.Server.Host,
			"port":             cfg.Server.Port,
			"read_timeout":     cfg.Server.ReadTimeout,
			"write_timeout":    cfg.Server.WriteTimeout,
			"max_header_bytes": cfg.Server.MaxHeaderBytes,
			"rate_limit":       "100 req/sec (burst: 200)",
		}).Info("Server listening with optimized concurrency settings")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	logger.Info("Server stopped")
}
