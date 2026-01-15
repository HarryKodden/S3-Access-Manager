package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/harrykodden/s3-gateway/internal/auth"
	"github.com/harrykodden/s3-gateway/internal/backend"
	awscli "github.com/harrykodden/s3-gateway/internal/backend/aws-cli"
	"github.com/harrykodden/s3-gateway/internal/config"
	"github.com/harrykodden/s3-gateway/internal/handler"
	"github.com/harrykodden/s3-gateway/internal/logging"
	"github.com/harrykodden/s3-gateway/internal/middleware"
	"github.com/harrykodden/s3-gateway/internal/policy"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/harrykodden/s3-gateway/internal/sync"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	configPath  = flag.String("config", "config.yaml", "Path to configuration file")
	showVersion = flag.Bool("version", false, "Show version information")

	// Version information (set via ldflags during build)
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

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

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := logging.NewLogger(cfg.Logging)
	logger.WithFields(logrus.Fields{
		"version":    version,
		"commit":     commit,
		"build_date": buildDate,
		"config":     *configPath,
	}).Info("Starting S3 Access Manager")

	// Initialize policy engine first (needed by authenticator)
	policyEngine, err := policy.NewEngine(cfg.Policies, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize policy engine")
	}

	// Initialize policy store (needed by authenticator)
	policyStore, err := store.NewPolicyStore("./data/policies", logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize policy store")
	}

	// Initialize role store
	roleStore, err := store.NewRoleStore(cfg.Roles.Directory, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize role store")
	}

	// Prepare admin users list
	adminUsers := []string{}
	if cfg.Admin.Username != "" {
		adminUsers = append(adminUsers, cfg.Admin.Username)
	}

	// Initialize OIDC authenticator with policy engine, policy store, and admin users
	authenticator, err := auth.NewOIDCAuthenticator(cfg.OIDC, logger, policyEngine, policyStore, adminUsers)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize OIDC authenticator")
	}

	// Start session cleanup goroutine with a context that will be cancelled on shutdown
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	authenticator.StartSessionCleanup(cleanupCtx)

	// Initialize S3 client
	s3Client, err := s3client.NewClient(cfg.S3, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize S3 client")
	}

	// Initialize IAM client with IAM-specific credentials
	// Only initialize for backends that support IAM operations
	var iamClient *s3client.IAMClient

	// Initialize backend-specific admin client based on backend type
	var adminClient backend.AdminClient

	awsCliClient, err := awscli.NewClient(cfg.S3.Endpoint, cfg.S3.IAM.AccessKey, cfg.S3.IAM.SecretKey, cfg.S3.Region, logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize AWS CLI client, using local credentials only")
		// When no backend is configured, don't initialize IAM client
		iamClient = nil
	} else {
		adminClient = awsCliClient
		logger.WithField("backend", "aws-cli").Info("AWS CLI client initialized")

		// Only initialize IAM client when backend is available
		iamClient, err = s3client.NewIAMClient(cfg.S3, logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize IAM client")
			iamClient = nil
		}
	}

	// Initialize user manager based on backend
	var userManager backend.UserManager
	var roleManager interface{}

	if adminClient != nil {
		if awsCliClient, ok := adminClient.(*awscli.Client); ok {
			userManager = awscli.NewUserManager(awsCliClient)
			roleManager = awscli.NewRoleManager(awsCliClient)
		}
	}

	syncService := sync.NewSyncService(iamClient, roleStore, "./data/policies", cfg.Admin.Username, roleManager, logger)

	// Initialize credential store
	credStore, err := store.NewCredentialStore("./data/credentials.json", logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize credential store")
	}

	// Setup Gin router
	if cfg.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()

	// Add middleware
	router.Use(middleware.RequestLogger(logger))
	router.Use(middleware.Recovery(logger))
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RateLimit(10, 20)) // 10 requests/sec, burst of 20
	router.Use(middleware.CORS(cfg.Security))
	router.Use(middleware.PrometheusMetrics()) // Record metrics for all requests

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "version": version})
	})

	// OIDC configuration endpoint (public, no auth required)
	oidcConfigHandler := handler.NewOIDCConfigHandler(cfg)
	router.GET("/oidc-config", oidcConfigHandler.GetOIDCConfig)

	// Metrics endpoint
	if cfg.Monitoring.MetricsEnabled {
		router.GET("/metrics", handler.MetricsHandler())
	}

	// Apply authentication middleware
	authMiddleware := middleware.OIDCAuth(authenticator, logger)

	// Apply user sync middleware (syncs IAM user/policies after authentication)
	syncMiddleware := middleware.Sync(syncService, logger)

	// Settings/Credentials management endpoints (authenticated)
	settingsRoutes := router.Group("/settings")
	settingsRoutes.Use(authMiddleware)
	settingsRoutes.Use(syncMiddleware) // Sync IAM user/policies after auth
	{
		credHandler := handler.NewCredentialHandler(credStore, roleStore, policyStore, iamClient, adminClient, cfg.Admin.Username, roleManager, logger)
		settingsRoutes.GET("/credentials", credHandler.ListCredentials)
		settingsRoutes.POST("/credentials", credHandler.CreateCredential)
		settingsRoutes.POST("/credentials/update-all", credHandler.UpdateCredentials)
		settingsRoutes.DELETE("/credentials/:accessKey", credHandler.DeleteCredential)
		settingsRoutes.GET("/credentials/:accessKey", credHandler.GetCredential)

		policyHandler := handler.NewPolicyHandler(policyStore, logger)
		settingsRoutes.GET("/policies", policyHandler.ListPolicies)
		settingsRoutes.GET("/policies/:name", policyHandler.GetPolicy)
		settingsRoutes.POST("/policies", policyHandler.CreatePolicy)
		settingsRoutes.PUT("/policies/:name", policyHandler.UpdatePolicy)
		settingsRoutes.DELETE("/policies/:name", policyHandler.DeletePolicy)
		settingsRoutes.POST("/policies/validate", policyHandler.ValidatePolicy)

		roleHandler := handler.NewRoleHandler(roleStore, policyStore, roleManager, "./data/policies", logger)
		settingsRoutes.GET("/roles", roleHandler.ListRoles)
		settingsRoutes.GET("/roles/:name", roleHandler.GetRole)
		settingsRoutes.POST("/roles", roleHandler.CreateRole)
		settingsRoutes.PUT("/roles/:name", roleHandler.UpdateRole)
		settingsRoutes.DELETE("/roles/:name", roleHandler.DeleteRole)

		userHandler := handler.NewUserHandler(userManager, cfg.Admin.Username, logger)
		settingsRoutes.GET("/users", userHandler.ListUsers)
		settingsRoutes.DELETE("/users/:username", userHandler.DeleteUser)

		bucketHandler := handler.NewBucketHandler(s3Client, logger)
		settingsRoutes.GET("/buckets", bucketHandler.ListBuckets)
		settingsRoutes.POST("/buckets", bucketHandler.CreateBucket)
		settingsRoutes.DELETE("/buckets/:name", bucketHandler.DeleteBucket)
	}

	// S3 proxy endpoints - users must be authenticated and select a credential
	s3Handler := handler.NewS3Handler(s3Client, cfg.S3, credStore, policyEngine, logger)

	// S3 routes - require OIDC authentication + credential selection + user/policy sync
	// Use /s3/ prefix to avoid conflicts with other routes
	s3Routes := router.Group("/s3")
	s3Routes.Use(authMiddleware) // OIDC authentication
	s3Routes.Use(syncMiddleware) // Sync IAM user/policies after auth
	{
		// Match all S3-like paths: /s3/{bucket}/{key...}
		// Frontend must send X-S3-Credential-AccessKey header with selected credential
		s3Routes.Any("/*proxyPath", s3Handler.ProxyRequest)
	}

	// Serve static frontend files
	// Serve index.html for root path
	router.GET("/", func(c *gin.Context) {
		c.File("./frontend/index.html")
	})
	// Serve index.html for OIDC callback (frontend handles the callback in JavaScript)
	router.GET("/callback", func(c *gin.Context) {
		c.File("./frontend/index.html")
	})
	// Serve specific static files
	router.StaticFile("/app.js", "./frontend/app.js")
	router.StaticFile("/styles.css", "./frontend/styles.css")
	router.StaticFile("/favicon.ico", "./frontend/favicon.ico")
	// Handle any other static assets
	router.StaticFS("/assets", http.Dir("./frontend/assets"))
	router.StaticFS("/css", http.Dir("./frontend/css"))
	router.StaticFS("/js", http.Dir("./frontend/js"))

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.WithFields(logrus.Fields{
			"host": cfg.Server.Host,
			"port": cfg.Server.Port,
		}).Info("Server listening")

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
