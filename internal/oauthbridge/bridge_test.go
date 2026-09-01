package oauthbridge

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nfraynor/agent-smith/internal/localoauth"
	"github.com/nfraynor/agent-smith/internal/oauthserver"
	"github.com/nfraynor/agent-smith/internal/oauthui"
	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestAuthorizationLoginTransactionDoesNotExposeRequest(t *testing.T) {
	store, err := localoauth.Open(localoauth.Options{Path: t.TempDir() + "/oauth.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err = store.Bootstrap("admin@example.com", "correct horse battery staple", permissions.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	bridge, err := New(store, "https://remoteops.example", "https://remoteops.example/mcp")
	if err != nil {
		t.Fatal(err)
	}
	input := oauthserver.AuthorizationRequest{ClientID: "client-secret-id", RedirectURI: "https://client.example/callback", Resource: bridge.Resource, State: "state-value", CodeChallenge: strings.Repeat("a", 43), Scopes: []string{"mcp"}}
	decision, err := bridge.Authorize(t.Context(), httptest.NewRequest(http.MethodGet, bridge.Issuer+"/oauth/authorize", nil), input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(decision.LoginURL, input.ClientID) || strings.Contains(decision.LoginURL, input.State) {
		t.Fatal("login URL exposed authorization parameters")
	}
	loginURL, _ := url.Parse(decision.LoginURL)
	transaction := loginURL.Query().Get("transaction")

	var captured string
	handler := bridge.ResumeAuthorization(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { captured = request.URL.RawQuery }))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, bridge.Issuer+"/oauth/authorize?transaction="+url.QueryEscape(transaction), nil))
	values, err := url.ParseQuery(captured)
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("client_id") != input.ClientID || values.Get("state") != input.State || values.Get("resource") != input.Resource {
		t.Fatalf("request not restored: %v", values)
	}
}

func TestAuthenticatedBrowserAndAccessTokenMapToSameUser(t *testing.T) {
	now := time.Now().UTC()
	store, err := localoauth.Open(localoauth.Options{Path: t.TempDir() + "/oauth.db", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user, _, err := store.Bootstrap("admin@example.com", "correct horse battery staple", permissions.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	if _, err = store.UpdateUser(user.ID, localoauth.UserUpdate{MustChangePassword: &changed}); err != nil {
		t.Fatal(err)
	}
	client, err := store.RegisterClient(localoauth.ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.IssueTokenPair(localoauth.TokenGrant{UserID: user.ID, ClientID: client.ID, Resource: "https://remoteops.example/mcp", Scopes: []string{"mcp"}}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bridge, _ := New(store, "https://remoteops.example", "https://remoteops.example/mcp")
	identity, err := (AccessAuthenticator{Bridge: bridge}).Authenticate(t.Context(), pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Actor != user.Email || identity.Role != permissions.RoleAdmin {
		t.Fatalf("identity = %#v", identity)
	}

	credentials, err := bridge.CreateSession(user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, bridge.Issuer+"/oauth/authorize", nil)
	request.AddCookie(&http.Cookie{Name: oauthui.SessionCookieName, Value: credentials.Token})
	decision, err := bridge.Authorize(t.Context(), request, oauthserver.AuthorizationRequest{})
	if err != nil || !strings.HasPrefix(decision.LoginURL, bridge.Issuer+"/oauth/consent?transaction=") {
		t.Fatalf("decision = %#v, err = %v", decision, err)
	}
}

func TestAccessAuthenticatorRequiresMCPScope(t *testing.T) {
	store, err := localoauth.Open(localoauth.Options{Path: t.TempDir() + "/oauth.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user, _, err := store.Bootstrap("admin@example.com", "correct horse battery staple", permissions.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.RegisterClient(localoauth.ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.IssueTokenPair(localoauth.TokenGrant{UserID: user.ID, ClientID: client.ID, Resource: "https://remoteops.example/mcp", Scopes: []string{"offline_access"}}, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	bridge, _ := New(store, "https://remoteops.example", "https://remoteops.example/mcp")
	if _, err = (AccessAuthenticator{Bridge: bridge}).Authenticate(t.Context(), pair.AccessToken); err == nil {
		t.Fatal("access token without mcp scope was accepted")
	}
}

func TestCannotDisableLastEnabledAdministrator(t *testing.T) {
	store, err := localoauth.Open(localoauth.Options{Path: t.TempDir() + "/oauth.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin, _, err := store.Bootstrap("admin@example.com", "correct horse battery staple", permissions.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	bridge, _ := New(store, "https://remoteops.example", "https://remoteops.example/mcp")
	if err = bridge.UpdateUser(oauthui.UpdateUserInput{ID: admin.ID, Role: permissions.RoleAdmin, Enabled: false}); err == nil {
		t.Fatal("last enabled administrator was disabled")
	}
}
