package main

import (
	"context"
	"flag"
	"fmt"
	"io"
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
	"github.com/harrykodden/s3-gateway/internal/logging"
	"github.com/harrykodden/s3-gateway/internal/middleware"
	"github.com/harrykodden/s3-gateway/internal/policy"
	"github.com/harrykodden/s3-gateway/internal/s3client"
	"github.com/harrykodden/s3-gateway/internal/store"
	"github.com/harrykodden/s3-gateway/internal/sync"
	"github.com/harrykodden/s3-gateway/internal/watcher"

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

	// Initialize group store (manages role-to-policy mappings from ./data/roles/)
	// Note: Called "groupStore" as it bridges SCIM groups to S3 IAM groups via roles
	groupStore, err := store.NewGroupStore(cfg.Roles.Directory, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize group store")
	}

	// Initialize user store for SCIM user data
	userStore, err := store.NewUserStore(cfg.SCIMUsers.Directory, cfg.SCIMGroups.Directory, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize user store")
	}

	// Prepare admin users list
	adminUsers := []string{}
	if cfg.Admin.Username != "" {
		adminUsers = append(adminUsers, cfg.Admin.Username)
	}

	// Initialize OIDC authenticator with policy engine, policy store, user store, and admin users
	authenticator, err := auth.NewOIDCAuthenticator(cfg.OIDC, logger, policyEngine, policyStore, userStore, adminUsers)
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
	var groupManager interface{}

	if adminClient != nil {
		if awsCliClient, ok := adminClient.(*awscli.Client); ok {
			userManager = awscli.NewUserManager(awsCliClient)
			groupManager = awscli.NewGroupManager(awsCliClient)
		}
	}

	// Initialize credential store
	credStore, err := store.NewCredentialStore("./data/credentials.json", logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize credential store")
	}

	syncService := sync.NewSyncService(iamClient, groupStore, userStore, credStore, "./data/policies", cfg.Admin.Username, groupManager, logger)

	// Perform initial SCIM-to-IAM synchronization to make SCIM authoritative
	if err := syncService.SyncAllSCIM(context.Background()); err != nil {
		logger.WithError(err).Error("Failed to perform initial SCIM-to-IAM synchronization")
		// Don't exit, continue with startup - sync can be retried later
	} else {
		logger.Info("Initial SCIM-to-IAM synchronization completed successfully")
	}

	// Start file watcher to detect SCIM data changes
	fileWatcher, err := watcher.NewFileWatcher(syncService, logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize file watcher - SCIM changes won't auto-sync")
	} else {
		// Watch SCIM Users and Groups directories
		if err := fileWatcher.AddDirectory(cfg.SCIMUsers.Directory); err != nil {
			logger.WithError(err).WithField("dir", cfg.SCIMUsers.Directory).Warn("Failed to watch users directory")
		}
		if err := fileWatcher.AddDirectory(cfg.SCIMGroups.Directory); err != nil {
			logger.WithError(err).WithField("dir", cfg.SCIMGroups.Directory).Warn("Failed to watch groups directory")
		}

		// Start watching in background
		watcherCtx, watcherCancel := context.WithCancel(context.Background())
		defer watcherCancel()
		defer fileWatcher.Close()
		fileWatcher.Start(watcherCtx)

		logger.WithFields(logrus.Fields{
			"users_dir":  cfg.SCIMUsers.Directory,
			"groups_dir": cfg.SCIMGroups.Directory,
		}).Info("File watcher started for SCIM data directories")
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
	router.Use(middleware.RateLimit(100, 200)) // Increased: 100 requests/sec, burst of 200
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

	// Apply S3 authentication middleware (supports both OIDC and access key auth)
	s3AuthMiddleware := middleware.S3Auth(authenticator, credStore, groupStore, logger)

	// Apply user sync middleware (syncs IAM user/policies after authentication)
	syncMiddleware := middleware.Sync(syncService, logger)

	// Admin middleware - requires admin role
	adminMiddleware := middleware.RequireAdmin(logger)

	// Settings/Credentials management endpoints (authenticated)
	settingsRoutes := router.Group("/settings")
	settingsRoutes.Use(authMiddleware)
	// Note: Sync middleware removed from group level - now applied only to mutation operations
	{
		credHandler := handler.NewCredentialHandler(credStore, groupStore, userStore, policyStore, iamClient, adminClient, cfg.Admin.Username, groupManager, cfg.S3, logger)
		// GET operations - no sync needed
		settingsRoutes.GET("/credentials", credHandler.ListCredentials)
		settingsRoutes.GET("/credentials/:accessKey", credHandler.GetCredential)
		// Mutation operations - sync user after changes
		settingsRoutes.POST("/credentials", syncMiddleware, credHandler.CreateCredential)
		settingsRoutes.POST("/credentials/update-all", syncMiddleware, credHandler.UpdateCredentials)
		settingsRoutes.DELETE("/credentials/:accessKey", syncMiddleware, credHandler.DeleteCredential)

		policyHandler := handler.NewPolicyHandlerWithSync(policyStore, groupStore, syncService, logger)
		// ADMIN ONLY - Policy management
		// GET operations - no sync needed
		settingsRoutes.GET("/policies", adminMiddleware, policyHandler.ListPolicies)
		settingsRoutes.GET("/policies/:name", adminMiddleware, policyHandler.GetPolicy)
		settingsRoutes.POST("/policies/validate", adminMiddleware, policyHandler.ValidatePolicy)
		// Mutation operations - no sync needed (handled in handler)
		settingsRoutes.POST("/policies", adminMiddleware, policyHandler.CreatePolicy)
		settingsRoutes.PUT("/policies/:name", adminMiddleware, policyHandler.UpdatePolicy)
		settingsRoutes.DELETE("/policies/:name", adminMiddleware, policyHandler.DeletePolicy)

		groupHandler := handler.NewGroupHandler(groupStore, userStore, policyStore, groupManager, "./data/policies", syncService, cfg.Admin.Username, logger)
		// Role management
		// GET operations - no sync needed (authenticated users can list roles, filtered by groups for non-admin)
		settingsRoutes.GET("/roles", groupHandler.ListGroups)
		settingsRoutes.GET("/roles/:name", adminMiddleware, groupHandler.GetGroup)
		settingsRoutes.GET("/scim-groups", adminMiddleware, groupHandler.ListSCIMGroups)
		// ADMIN ONLY - Mutation operations - sync handled in handler (SyncAllSCIM calls)
		settingsRoutes.POST("/roles", adminMiddleware, groupHandler.CreateGroup)
		settingsRoutes.PUT("/roles/:name", adminMiddleware, groupHandler.UpdateGroup)
		settingsRoutes.DELETE("/roles/:name", adminMiddleware, groupHandler.DeleteGroup)

		userHandler := handler.NewUserHandler(userManager, userStore, cfg.Admin.Username, logger)
		// ADMIN ONLY - User management
		// GET operations - no sync needed
		settingsRoutes.GET("/users", adminMiddleware, userHandler.ListUsers)
		settingsRoutes.GET("/users/:username/details", adminMiddleware, userHandler.GetUserDetails)
		// DELETE operation - sync handled if needed
		settingsRoutes.DELETE("/users/:username", adminMiddleware, userHandler.DeleteUser)
	}

	// SCIM proxy - forward SCIM requests to SCIM service
	scimRoutes := router.Group("/scim")
	scimRoutes.Use(authMiddleware) // SCIM requests require authentication
	scimRoutes.Use(syncMiddleware) // Sync IAM user/policies after auth
	scimRoutes.Any("/*path", func(c *gin.Context) {
		// Forward request to SCIM service
		targetURL := "http://localhost:8000" + c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			targetURL += "?" + c.Request.URL.RawQuery
		}

		// Create new request to SCIM service
		req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
		if err != nil {
			logger.WithError(err).Error("Failed to create SCIM proxy request")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to proxy request"})
			return
		}

		// Copy headers
		for key, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		// Make request to SCIM service
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logger.WithError(err).Error("Failed to proxy request to SCIM service")
			c.JSON(http.StatusBadGateway, gin.H{"error": "SCIM service unavailable"})
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}

		// Set status code and copy response body
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
	})

	// S3 proxy endpoints - users must be authenticated and select a credential
	s3Handler := handler.NewS3Handler(s3Client, cfg.S3, credStore, groupStore, userStore, policyEngine, logger)

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
	// }

	// Catch-all route for S3 operations at root level (for AWS CLI compatibility)
	// Temporarily disabled for debugging
	/*
		catchAllHandler := func(c *gin.Context) {
			// Check if this is an S3 request (has Authorization header for CLI)
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
				// This is an AWS CLI S3 request, handle with S3 middleware
				s3AuthMiddleware(c)
				if c.IsAborted() {
					return // Auth failed, response already sent
				}
				syncMiddleware(c)
				if c.IsAborted() {
					return // Sync failed, response already sent
				}

				// Extract bucket/key from path
				path := strings.TrimPrefix(c.Request.URL.Path, "/")
				if path == "" {
					// Root path - list buckets
					s3Handler.ListBuckets(c)
				} else {
					// Bucket/key operation - proxy to S3
					parts := strings.SplitN(path, "/", 2)
					bucket := parts[0]
					key := ""
					if len(parts) > 1 {
						key = parts[1]
					}

					// Create user S3 client and proxy the request
					userInfoValue, _ := c.Get("userInfo")
					userInfo := userInfoValue.(*auth.UserInfo)
					selectedCredValue, _ := c.Get("selectedCredential")
					cred := selectedCredValue.(*store.Credential)

					s3Client, err := s3Handler.CreateUserS3Client(c.Request.Context(), cred)
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
				return
			}

			// Not an S3 request, return 404
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		}
	*/

	// Root path handler - serves S3 operations (for CLI) or frontend (for web UI)
	rootHandler := func(c *gin.Context) {
		// Check if this is an S3 request (has Authorization header for CLI or X-S3-Credential-AccessKey for web UI)
		authHeader := c.GetHeader("Authorization")
		credHeader := c.GetHeader("X-S3-Credential-AccessKey")

		if (authHeader != "" && strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256")) || credHeader != "" {
			// This is an S3 request, handle with S3 middleware
			s3AuthMiddleware(c)
			if c.IsAborted() {
				return // Auth failed, response already sent
			}
			syncMiddleware(c)
			if c.IsAborted() {
				return // Sync failed, response already sent
			}

			// Extract bucket and key from path
			path := strings.TrimPrefix(c.Request.URL.Path, "/")
			path = strings.TrimPrefix(path, "s3/")
			parts := strings.SplitN(path, "/", 2)
			bucket := parts[0]
			key := ""
			if len(parts) > 1 {
				key = parts[1]
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
			s3Client, err := s3Handler.CreateUserS3Client(c.Request.Context(), cred)
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

		fmt.Fprintf(os.Stderr, "Serving frontend HTML\n")
		// Not an S3 request, serve frontend
		c.File("./frontend/index.html")
	}
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

	// Handle unmatched routes as potential S3 operations (for AWS CLI compatibility)
	router.NoRoute(rootHandler)

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
