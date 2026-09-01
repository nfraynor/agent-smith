package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/nfraynor/agent-smith/internal/audit"
	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/changes"
	"github.com/nfraynor/agent-smith/internal/compose"
	"github.com/nfraynor/agent-smith/internal/config"
	"github.com/nfraynor/agent-smith/internal/deployment"
	"github.com/nfraynor/agent-smith/internal/diagnostics"
	remotedocker "github.com/nfraynor/agent-smith/internal/docker"
	"github.com/nfraynor/agent-smith/internal/envconfig"
	"github.com/nfraynor/agent-smith/internal/filesystem"
	"github.com/nfraynor/agent-smith/internal/godmode"
	"github.com/nfraynor/agent-smith/internal/limits"
	"github.com/nfraynor/agent-smith/internal/locks"
	"github.com/nfraynor/agent-smith/internal/mcpserver"
	"github.com/nfraynor/agent-smith/internal/yamlconfig"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	configPath := os.Getenv("REMOTEOPS_CONFIG")
	if configPath == "" {
		configPath = config.DefaultPath
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	auditService, err := audit.New("/data/audit.jsonl", audit.Options{SecretValues: []string{cfg.BearerToken}, SyncWrites: true})
	if err != nil {
		logger.Error("audit initialization failed", "error", err)
		os.Exit(1)
	}
	defer auditService.Close()

	var authenticator auth.Authenticator
	var oauthHandler http.Handler
	authChallenge := ""
	if cfg.Auth.Mode == "bearer" {
		authenticator, err = auth.NewBearer(cfg.BearerToken, cfg.Auth.Actor, cfg.Permissions.DefaultRole)
		if err != nil {
			logger.Error("authentication initialization failed", "error", err)
			os.Exit(1)
		}
	} else {
		var oauth *oauthRuntime
		oauth, err = newOAuthRuntime(cfg, auditService, logger)
		if err != nil {
			logger.Error("local OAuth initialization failed", "error", err)
			os.Exit(1)
		}
		defer oauth.Close()
		authenticator = oauth.authenticator
		oauthHandler = oauth.handler
		authChallenge = oauth.challenge
	}
	authMiddleware := auth.Middleware{Authenticator: authenticator, Challenge: authChallenge, OnAttempt: func(attempt auth.Attempt) {
		_ = auditService.Record(context.Background(), audit.Event{Actor: attempt.Actor, Action: "authentication", Allowed: attempt.Success, Success: attempt.Success, Error: attempt.Reason})
	}}

	roots := make(map[string]filesystem.Root, len(cfg.Filesystem.Roots))
	rootNames := make([]string, 0, len(cfg.Filesystem.Roots))
	for _, root := range cfg.Filesystem.Roots {
		roots[root.Name] = filesystem.Root{Path: root.Path, ReadOnly: root.ReadOnly}
		rootNames = append(rootNames, root.Name)
	}
	sort.Strings(rootNames)
	files, err := filesystem.New(roots, filesystem.Options{MaxReadBytes: cfg.Limits.MaxFileReadBytes})
	if err != nil {
		logger.Error("filesystem initialization failed", "error", err)
		os.Exit(1)
	}
	yamlService := yamlconfig.New(files, cfg.Limits.MaxFileReadBytes)
	envService := envconfig.New(files, cfg.Limits.MaxFileReadBytes, nil)
	changeStore, err := changes.New("/data/changes", changes.Options{RetentionDays: cfg.Changes.RetentionDays, MaxRecords: cfg.Changes.MaxRecords, MaxTargetBytes: cfg.Limits.MaxFileReadBytes})
	if err != nil {
		logger.Error("change store initialization failed", "error", err)
		os.Exit(1)
	}

	projects := make([]compose.Project, 0, len(cfg.Compose.Projects))
	for _, project := range cfg.Compose.Projects {
		projects = append(projects, compose.Project{Name: project.Name, Path: project.Path, File: project.File})
	}
	composeService, err := compose.New(projects, compose.ExecRunner{Binary: "docker"}, cfg.Limits.MaxLogBytes)
	if err != nil {
		logger.Error("compose initialization failed", "error", err)
		os.Exit(1)
	}

	var dockerService *remotedocker.Service
	var diagnosticsService *diagnostics.Service
	var deploymentService *deployment.Service
	if cfg.Docker.Enabled {
		dockerClient, dockerErr := remotedocker.NewSDKClient(cfg.Docker.Socket)
		if dockerErr != nil {
			logger.Error("docker client initialization failed", "error", dockerErr)
			os.Exit(1)
		}
		defer dockerClient.Close()
		dockerService = remotedocker.New(dockerClient, cfg.Limits.MaxLogBytes)
		diagnosticsService = diagnostics.New(dockerService, composeService, nil, nil, version, cfg.GodMode)
		deploymentService = deployment.New(composeService, dockerService, diagnosticsService, deployment.ContextChangeRecorder{Store: changeStore, FallbackActor: cfg.Auth.Actor}, deployment.Options{VerificationTimeout: time.Duration(cfg.Limits.MaxExecutionSeconds) * time.Second})
	}

	godRunner := &godmode.Runner{Enabled: cfg.GodMode, NSenterPath: "/usr/bin/nsenter", DefaultTimeout: time.Duration(cfg.Limits.MaxExecutionSeconds) * time.Second, MaximumTimeout: time.Duration(cfg.Limits.MaxExecutionSeconds) * time.Second, MaxOutputBytes: int(cfg.Limits.MaxLogBytes)}
	remote, err := mcpserver.New(mcpserver.Options{Name: cfg.Server.Name, Version: version, Commit: commit, GodMode: cfg.GodMode, RootNames: rootNames, Docker: dockerService, Compose: composeService, Files: files, YAML: yamlService, Env: envService, Changes: changeStore, Diagnostics: diagnosticsService, Deployment: deploymentService, GodShell: godRunner, Audit: auditService, Limiter: limits.NewLimiter(cfg.Limits.RequestsPerMinute, cfg.Limits.MutationsPerMinute), Locks: locks.New()})
	if err != nil {
		logger.Error("MCP initialization failed", "error", err)
		os.Exit(1)
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote.MCP() }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, Logger: logger, MaxRequestBodyBytes: cfg.Limits.MaxRequestBytes, PropagateRequestCancellation: true})
	originProtection := http.NewCrossOriginProtection()
	mux := http.NewServeMux()
	httpLimiter := limits.NewLimiter(cfg.Limits.RequestsPerMinute, cfg.Limits.MutationsPerMinute)
	if oauthHandler != nil {
		mux.Handle("/.well-known/", oauthHandler)
		mux.Handle("/oauth/", oauthHandler)
		mux.Handle("/login", oauthHandler)
		mux.Handle("/logout", oauthHandler)
		mux.Handle("/account/", oauthHandler)
		mux.Handle("/admin/", oauthHandler)
	}
	mux.Handle("/mcp", httpRateLimit(httpLimiter, authMiddleware.Wrap(originProtection.Handler(mcpHandler))))
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"status": "healthy", "version": version, "docker": map[bool]string{true: "configured", false: "disabled"}[cfg.Docker.Enabled], "configured": true, "godMode": cfg.GodMode})
	})
	mux.Handle("GET /ready", authMiddleware.Wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if dockerService != nil {
			if _, dockerErr := dockerService.List(request.Context(), true); dockerErr != nil {
				writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "error": "Docker is unavailable"})
				return
			}
		}
		writeJSON(writer, http.StatusOK, map[string]any{"status": "ready"})
	})))

	server := &http.Server{Addr: cfg.Server.Listen, Handler: limits.MaxRequestBytes(cfg.Limits.MaxRequestBytes, mux), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		contextWithTimeout, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(contextWithTimeout)
	}()
	if cfg.GodMode {
		logger.Warn("GOD MODE ENABLED: unrestricted host administration is available")
	}
	logger.Info("RemoteOps MCP listening", "address", cfg.Server.Listen, "version", version, "authMode", cfg.Auth.Mode, "godMode", cfg.GodMode)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("HTTP server failed", "error", err)
		os.Exit(1)
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func httpRateLimit(limiter *limits.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := request.RemoteAddr
		if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
			identity = host
		}
		if !limiter.Allow("http:"+identity, false) {
			writeJSON(writer, http.StatusTooManyRequests, map[string]string{"code": "RATE_LIMITED", "message": "Request rate limit exceeded."})
			return
		}
		next.ServeHTTP(writer, request)
	})
}
