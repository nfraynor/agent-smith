package oauthserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxRequestBody = 64 << 10

var (
	ErrNotFound        = errors.New("not found")
	ErrInvalidGrant    = errors.New("invalid grant")
	ErrBindingMismatch = errors.New("binding mismatch")
)

// Client is a restricted public OAuth client. Confidential clients are deliberately unsupported.
type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
	Disabled     bool
}

type ClientRegistration struct {
	Name         string
	RedirectURIs []string
}

type AuthorizationGrant struct {
	UserID, ClientID, RedirectURI, Resource, CodeChallenge string
	Scopes                                                 []string
}

type CodeBinding struct {
	ClientID, RedirectURI, Resource, CodeChallenge string
}

type TokenGrant struct {
	UserID, ClientID, Resource string
	Scopes                     []string
}

type RefreshBinding struct {
	ClientID, Resource string
}

type TokenPair struct {
	AccessToken, RefreshToken         string
	AccessExpiresAt, RefreshExpiresAt time.Time
}

// Store owns all persistence and atomic one-time/rotation behavior. Implementations must
// hash raw codes and tokens before storage.
type Store interface {
	RegisterClient(ClientRegistration) (Client, error)
	GetClient(id string) (Client, error)
	CreateAuthorizationCode(AuthorizationGrant, time.Duration) (string, error)
	ConsumeAuthorizationCode(raw string, binding CodeBinding) (AuthorizationGrant, error)
	IssueTokenPair(TokenGrant, time.Duration, time.Duration) (TokenPair, error)
	RotateRefresh(raw string, binding RefreshBinding, accessTTL, refreshTTL time.Duration) (TokenPair, error)
	RevokeToken(raw, clientID string) error
}

type AuthorizationRequest struct {
	ClientID, RedirectURI, Resource, State, CodeChallenge string
	Scopes                                                []string
}

// AuthorizationDecision is produced by the local browser identity/session layer.
// LoginURL resumes this exact validated request after authentication. An empty UserID
// with no LoginURL is an explicit denial.
type AuthorizationDecision struct {
	UserID   string
	LoginURL string
}

type Authorizer interface {
	Authorize(context.Context, *http.Request, AuthorizationRequest) (AuthorizationDecision, error)
}

type Config struct {
	Issuer               string
	Resource             string
	AllowedRedirectURIs  []string
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	AuthorizationCodeTTL time.Duration
	Now                  func() time.Time
}

type Server struct {
	config     Config
	store      Store
	authorizer Authorizer
	registerMu sync.Mutex
	registerAt time.Time
	registerN  int
}

func New(config Config, store Store, authorizer Authorizer) (*Server, error) {
	if store == nil || authorizer == nil {
		return nil, errors.New("oauth store and authorizer are required")
	}
	issuer, err := canonicalHTTPSURL(config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	issuerURL, _ := url.Parse(issuer)
	if issuerURL.Path != "" && issuerURL.Path != "/" {
		return nil, errors.New("issuer must be an HTTPS origin without a path")
	}
	resource, err := canonicalHTTPSURL(config.Resource)
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	if issuer != config.Issuer || resource != config.Resource {
		return nil, errors.New("issuer and resource must be canonical HTTPS URLs")
	}
	if config.AccessTokenTTL <= 0 || config.RefreshTokenTTL <= 0 || config.AuthorizationCodeTTL <= 0 {
		return nil, errors.New("oauth token and code lifetimes must be positive")
	}
	for _, redirect := range config.AllowedRedirectURIs {
		if err := validateRedirectURI(redirect); err != nil {
			return nil, fmt.Errorf("allowed redirect URI %q: %w", redirect, err)
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.AllowedRedirectURIs = slices.Clone(config.AllowedRedirectURIs)
	return &Server{config: config, store: store, authorizer: authorizer}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.protectedResourceMetadata)
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	return s.securityHeaders(mux)
}

func (s *Server) authorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.config.Issuer,
		"authorization_endpoint":                         s.config.Issuer + "/oauth/authorize",
		"token_endpoint":                                 s.config.Issuer + "/oauth/token",
		"registration_endpoint":                          s.config.Issuer + "/oauth/register",
		"revocation_endpoint":                            s.config.Issuer + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               []string{"mcp", "offline_access"},
	})
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.config.Resource,
		"authorization_servers":    []string{s.config.Issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   s.config.Issuer + "/docs/authentication",
		"scopes_supported":         []string{"mcp", "offline_access"},
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) oauthError(w http.ResponseWriter, status int, code, description string) {
	s.writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func canonicalHTTPSURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return "", errors.New("must be an absolute HTTPS URL without userinfo, query, or fragment")
	}
	if strings.Contains(u.Host, "@") {
		return "", errors.New("invalid host")
	}
	return u.String(), nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" || u.Scheme != "https" {
		return errors.New("must be an absolute HTTPS URL without userinfo or fragment")
	}
	if strings.ContainsAny(raw, "*\r\n") {
		return errors.New("wildcards and control characters are forbidden")
	}
	return nil
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := r.ParseForm(); err != nil {
		return err
	}
	return nil
}

func pkceChallenge(verifier string) (string, bool) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return "", false
	}
	for _, c := range verifier {
		if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && !strings.ContainsRune("-._~", c) {
			return "", false
		}
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), true
}

func (s *Server) bearerChallenge() string {
	metadata := s.config.Issuer + "/.well-known/oauth-protected-resource/mcp"
	return `Bearer realm="remoteops", resource_metadata="` + metadata + `"`
}

// WriteBearerError preserves RemoteOps' resource error body while publishing OAuth discovery.
func (s *Server) WriteBearerError(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("WWW-Authenticate", s.bearerChallenge())
	s.oauthError(w, http.StatusUnauthorized, errorCode, description)
}

func expiresIn(now, expiry time.Time) int64 {
	seconds := int64(expiry.Sub(now) / time.Second)
	if seconds < 0 {
		return 0
	}
	return seconds
}

func parseScopes(raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	seen := map[string]bool{}
	var scopes []string
	for _, scope := range strings.Fields(raw) {
		if scope != "mcp" && scope != "offline_access" {
			return nil, false
		}
		if !seen[scope] {
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}
	if !seen["mcp"] {
		return nil, false
	}
	return scopes, true
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }

func unixTime(t time.Time) int64 { return t.Unix() }
