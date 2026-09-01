package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nfraynor/agent-smith/internal/audit"
	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/config"
	"github.com/nfraynor/agent-smith/internal/localoauth"
	"github.com/nfraynor/agent-smith/internal/oauthbridge"
	"github.com/nfraynor/agent-smith/internal/oauthserver"
	"github.com/nfraynor/agent-smith/internal/oauthui"
	"github.com/nfraynor/agent-smith/internal/permissions"
)

type oauthRuntime struct {
	authenticator auth.Authenticator
	handler       http.Handler
	challenge     string
	store         *localoauth.Store
	stopCleanup   chan struct{}
}

func newOAuthRuntime(cfg config.Config, auditService *audit.Service, logger *slog.Logger) (*oauthRuntime, error) {
	settings := cfg.Auth.OAuthLocal
	store, err := localoauth.Open(localoauth.Options{Path: settings.DataFile, PasswordConcurrency: 2})
	if err != nil {
		return nil, fmt.Errorf("open local OAuth store: %w", err)
	}
	fail := func(err error) (*oauthRuntime, error) { _ = store.Close(); return nil, err }
	users, err := store.ListUsers()
	if err != nil {
		return fail(fmt.Errorf("read local OAuth users: %w", err))
	}
	if len(users) == 0 {
		if strings.TrimSpace(settings.BootstrapEmail) == "" || settings.BootstrapPassword == "" {
			return fail(errors.New("OAuth store is empty; bootstrap email and password file are required"))
		}
		user, created, bootstrapErr := store.Bootstrap(settings.BootstrapEmail, settings.BootstrapPassword, permissions.RoleAdmin)
		if bootstrapErr != nil {
			return fail(fmt.Errorf("bootstrap local OAuth administrator: %w", bootstrapErr))
		}
		if created {
			logger.Info("local OAuth administrator bootstrapped", "actor", user.Email)
			_ = auditService.Record(context.Background(), audit.Event{Actor: user.Email, Action: "oauth_bootstrap", Class: permissions.SafeWrite, Allowed: true, Success: true})
		}
	}
	if err = store.CleanupExpired(); err != nil {
		return fail(fmt.Errorf("clean expired OAuth state: %w", err))
	}
	issuer := strings.TrimSuffix(settings.PublicOrigin, "/")
	resource := issuer + "/mcp"
	bridge, err := oauthbridge.New(store, issuer, resource)
	if err != nil {
		return fail(err)
	}
	ui, err := oauthui.New(oauthui.Options{
		PublicOrigin: issuer, Backend: bridge,
		SessionTTL:          time.Duration(settings.BrowserSessionHours) * time.Hour,
		MaxBodyBytes:        cfg.Limits.MaxRequestBytes,
		LoginSourceAttempts: 10000,
		Audit: func(event oauthui.AuditEvent) {
			_ = auditService.Record(context.Background(), audit.Event{Actor: event.Actor, Action: "oauth_" + event.Action, Class: permissions.SafeWrite, Target: event.Target, Allowed: event.Success, Success: event.Success, Error: event.Reason})
		},
	})
	if err != nil {
		return fail(fmt.Errorf("initialize OAuth browser UI: %w", err))
	}
	protocol, err := oauthserver.New(oauthserver.Config{
		Issuer: issuer, Resource: resource,
		AllowedRedirectURIs:  settings.AllowedRedirectURIs,
		AccessTokenTTL:       time.Duration(settings.AccessTokenMinutes) * time.Minute,
		RefreshTokenTTL:      time.Duration(settings.RefreshTokenDays) * 24 * time.Hour,
		AuthorizationCodeTTL: 5 * time.Minute,
	}, bridge, bridge)
	if err != nil {
		return fail(fmt.Errorf("initialize OAuth protocol server: %w", err))
	}
	protocolHandler := bridge.ResumeAuthorization(protocol.Handler())
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", protocolHandler)
	mux.Handle("/oauth/consent", bridge.ConsentHandler())
	mux.Handle("/oauth/", protocolHandler)
	mux.Handle("/login", ui)
	mux.Handle("/logout", ui)
	mux.Handle("/account/", ui)
	mux.Handle("/admin/", ui)

	runtime := &oauthRuntime{
		authenticator: oauthbridge.AccessAuthenticator{Bridge: bridge}, handler: auditOAuthProtocol(mux, auditService),
		challenge: `Bearer realm="remoteops", resource_metadata="` + issuer + `/.well-known/oauth-protected-resource/mcp"`,
		store:     store, stopCleanup: make(chan struct{}),
	}
	go runtime.cleanupLoop(logger)
	return runtime, nil
}

type oauthStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *oauthStatusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func auditOAuthProtocol(next http.Handler, service *audit.Service) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		action := map[string]string{
			"/oauth/register":  "oauth_client_register",
			"/oauth/authorize": "oauth_authorize",
			"/oauth/consent":   "oauth_consent",
			"/oauth/token":     "oauth_token",
			"/oauth/revoke":    "oauth_revoke",
		}[request.URL.Path]
		if action == "" {
			next.ServeHTTP(writer, request)
			return
		}
		recorder := &oauthStatusRecorder{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		success := recorder.status < http.StatusBadRequest
		_ = service.Record(request.Context(), audit.Event{
			Actor: "oauth-client", Action: action, Class: permissions.SafeWrite,
			Target: request.URL.Path, Allowed: success, Success: success,
		})
	})
}

func (r *oauthRuntime) cleanupLoop(logger *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := r.store.CleanupExpired(); err != nil {
				logger.Error("OAuth state cleanup failed", "error", err)
			}
		case <-r.stopCleanup:
			return
		}
	}
}

func (r *oauthRuntime) Close() error {
	close(r.stopCleanup)
	return r.store.Close()
}
