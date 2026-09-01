package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer   = "https://remoteops.example"
	testResource = "https://remoteops.example/mcp"
	testRedirect = "https://chatgpt.com/connector/callback"
)

type memoryStore struct {
	clients  map[string]Client
	codes    map[string]AuthorizationGrant
	revoked  []string
	nextCode int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{clients: map[string]Client{}, codes: map[string]AuthorizationGrant{}}
}

func (m *memoryStore) RegisterClient(registration ClientRegistration) (Client, error) {
	client := Client{ID: "client-1", Name: registration.Name, RedirectURIs: registration.RedirectURIs, CreatedAt: time.Unix(1000, 0)}
	m.clients[client.ID] = client
	return client, nil
}
func (m *memoryStore) GetClient(id string) (Client, error) {
	client, ok := m.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return client, nil
}
func (m *memoryStore) CreateAuthorizationCode(grant AuthorizationGrant, _ time.Duration) (string, error) {
	m.nextCode++
	code := "code-" + string(rune('0'+m.nextCode))
	m.codes[code] = grant
	return code, nil
}
func (m *memoryStore) ConsumeAuthorizationCode(raw string, binding CodeBinding) (AuthorizationGrant, error) {
	grant, ok := m.codes[raw]
	if !ok {
		return AuthorizationGrant{}, ErrInvalidGrant
	}
	delete(m.codes, raw)
	if grant.ClientID != binding.ClientID || grant.RedirectURI != binding.RedirectURI || grant.Resource != binding.Resource || grant.CodeChallenge != binding.CodeChallenge {
		return AuthorizationGrant{}, ErrBindingMismatch
	}
	return grant, nil
}
func (m *memoryStore) IssueTokenPair(_ TokenGrant, accessTTL, refreshTTL time.Duration) (TokenPair, error) {
	now := time.Unix(2000, 0)
	return TokenPair{AccessToken: "access-secret", RefreshToken: "refresh-secret", AccessExpiresAt: now.Add(accessTTL), RefreshExpiresAt: now.Add(refreshTTL)}, nil
}
func (m *memoryStore) RotateRefresh(raw string, binding RefreshBinding, accessTTL, refreshTTL time.Duration) (TokenPair, error) {
	if raw != "refresh-secret" || binding.ClientID != "client-1" || binding.Resource != testResource {
		return TokenPair{}, ErrInvalidGrant
	}
	now := time.Unix(2000, 0)
	return TokenPair{AccessToken: "access-rotated", RefreshToken: "refresh-rotated", AccessExpiresAt: now.Add(accessTTL), RefreshExpiresAt: now.Add(refreshTTL)}, nil
}
func (m *memoryStore) RevokeToken(raw, clientID string) error {
	m.revoked = append(m.revoked, clientID+":"+raw)
	return nil
}

type allowUser struct{ userID string }

func (a allowUser) Authorize(context.Context, *http.Request, AuthorizationRequest) (AuthorizationDecision, error) {
	return AuthorizationDecision{UserID: a.userID}, nil
}

func newTestServer(t *testing.T, store *memoryStore) *Server {
	t.Helper()
	server, err := New(Config{
		Issuer: testIssuer, Resource: testResource, AllowedRedirectURIs: []string{testRedirect},
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 30 * 24 * time.Hour, AuthorizationCodeTTL: 5 * time.Minute,
		Now: func() time.Time { return time.Unix(2000, 0) },
	}, store, allowUser{userID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestDiscoveryDocumentsUseCanonicalConfiguredURLs(t *testing.T) {
	server := newTestServer(t, newMemoryStore())
	for path, expected := range map[string]string{
		"/.well-known/oauth-authorization-server":   `"issuer":"https://remoteops.example"`,
		"/.well-known/oauth-protected-resource/mcp": `"resource":"https://remoteops.example/mcp"`,
	} {
		request := httptest.NewRequest(http.MethodGet, "https://attacker.invalid"+path, nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) || strings.Contains(response.Body.String(), "attacker") {
			t.Fatalf("%s: status=%d body=%s", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("missing no-store on %s", path)
		}
	}
}

func TestRestrictedDynamicClientRegistration(t *testing.T) {
	store := newMemoryStore()
	server := newTestServer(t, store)
	valid := `{"redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"ChatGPT"}`
	response := serve(server, http.MethodPost, "/oauth/register", valid, "application/json")
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"client_id":"client-1"`) {
		t.Fatalf("valid DCR: %d %s", response.Code, response.Body.String())
	}

	for name, body := range map[string]string{
		"confidential":      `{"redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"unlisted redirect": `{"redirect_uris":["https://evil.example/callback"]}`,
		"fragment":          `{"redirect_uris":["https://evil.example/callback#fragment"]}`,
		"unknown metadata":  `{"redirect_uris":["` + testRedirect + `"],"logo_uri":"https://internal.example/logo"}`,
	} {
		t.Run(name, func(t *testing.T) {
			result := serve(server, http.MethodPost, "/oauth/register", body, "application/json")
			if result.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
			}
		})
	}
}

func TestAuthorizationCodePKCEExchangeAndReplay(t *testing.T) {
	store := newMemoryStore()
	store.clients["client-1"] = Client{ID: "client-1", RedirectURIs: []string{testRedirect}}
	server := newTestServer(t, store)
	verifier := strings.Repeat("v", 43)
	challenge, _ := pkceChallenge(verifier)
	query := url.Values{
		"response_type": {"code"}, "client_id": {"client-1"}, "redirect_uri": {testRedirect},
		"scope": {"mcp offline_access"}, "resource": {testResource}, "state": {"opaque-state"},
		"code_challenge_method": {"S256"}, "code_challenge": {challenge},
	}
	response := serve(server, http.MethodGet, "/oauth/authorize?"+query.Encode(), "", "")
	if response.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", response.Code, response.Body.String())
	}
	location, _ := url.Parse(response.Header().Get("Location"))
	if location.Query().Get("state") != "opaque-state" || location.Query().Get("code") == "" {
		t.Fatalf("location=%s", location)
	}

	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"client-1"}, "code": {location.Query().Get("code")},
		"redirect_uri": {testRedirect}, "resource": {testResource}, "code_verifier": {verifier},
	}
	tokens := serve(server, http.MethodPost, "/oauth/token", form.Encode(), "application/x-www-form-urlencoded")
	if tokens.Code != http.StatusOK || !strings.Contains(tokens.Body.String(), `"access_token":"access-secret"`) || !strings.Contains(tokens.Body.String(), `"refresh_token":"refresh-secret"`) {
		t.Fatalf("exchange: %d %s", tokens.Code, tokens.Body.String())
	}
	replay := serve(server, http.MethodPost, "/oauth/token", form.Encode(), "application/x-www-form-urlencoded")
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("replay: %d %s", replay.Code, replay.Body.String())
	}
}

func TestAuthorizeRejectsBeforeRedirectIsTrusted(t *testing.T) {
	store := newMemoryStore()
	store.clients["client-1"] = Client{ID: "client-1", RedirectURIs: []string{testRedirect}}
	server := newTestServer(t, store)
	response := serve(server, http.MethodGet, "/oauth/authorize?client_id=client-1&redirect_uri=https://evil.example/callback", "", "")
	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("unsafe redirect: %d %s", response.Code, response.Header().Get("Location"))
	}
}

func TestRefreshAndRevocation(t *testing.T) {
	store := newMemoryStore()
	store.clients["client-1"] = Client{ID: "client-1", RedirectURIs: []string{testRedirect}}
	server := newTestServer(t, store)
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {"client-1"}, "refresh_token": {"refresh-secret"}, "resource": {testResource}}
	response := serve(server, http.MethodPost, "/oauth/token", refresh.Encode(), "application/x-www-form-urlencoded")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "access-rotated") {
		t.Fatalf("refresh: %d %s", response.Code, response.Body.String())
	}
	revoke := url.Values{"client_id": {"client-1"}, "token": {"refresh-rotated"}}
	response = serve(server, http.MethodPost, "/oauth/revoke", revoke.Encode(), "application/x-www-form-urlencoded")
	if response.Code != http.StatusOK || len(store.revoked) != 1 {
		t.Fatalf("revoke: %d %#v", response.Code, store.revoked)
	}
}

func TestBearerChallengeAdvertisesProtectedResourceMetadata(t *testing.T) {
	server := newTestServer(t, newMemoryStore())
	response := httptest.NewRecorder()
	server.WriteBearerError(response, "invalid_token", "access token is invalid")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	challenge := response.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://remoteops.example/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("challenge=%s", challenge)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "invalid_token" {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
}

func TestNewRejectsUnsafeCanonicalConfiguration(t *testing.T) {
	base := Config{Issuer: testIssuer, Resource: testResource, AllowedRedirectURIs: []string{testRedirect}, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute}
	for name, mutate := range map[string]func(*Config){
		"http issuer":       func(c *Config) { c.Issuer = "http://remoteops.example" },
		"issuer query":      func(c *Config) { c.Issuer += "?host=evil" },
		"resource fragment": func(c *Config) { c.Resource += "#fragment" },
		"wildcard redirect": func(c *Config) { c.AllowedRedirectURIs = []string{"https://*.example/callback"} },
		"zero lifetime":     func(c *Config) { c.AccessTokenTTL = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := New(config, newMemoryStore(), allowUser{"user"}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := New(base, nil, allowUser{"user"}); err == nil || !errors.Is(err, err) {
		t.Fatal("expected dependency error")
	}
}

func serve(server *Server, method, target, body, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, testIssuer+target, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
