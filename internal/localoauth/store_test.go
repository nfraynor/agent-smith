package localoauth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

const testPassword = "correct horse battery staple"

func openTestStore(t *testing.T, now *time.Time) *Store {
	t.Helper()
	params := Argon2Params{MemoryKiB: 16 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	store, err := Open(Options{Path: filepath.Join(t.TempDir(), "oauth.db"), Now: func() time.Time { return *now }, Argon2: params})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func bootstrapTestUser(t *testing.T, store *Store) User {
	t.Helper()
	user, created, err := store.Bootstrap("Admin@Example.com", testPassword, permissions.RoleAdmin)
	if err != nil || !created {
		t.Fatalf("bootstrap = %#v, %v, %v", user, created, err)
	}
	return user
}

func TestBootstrapIsIdempotentAndPersists(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "oauth.db")
	params := Argon2Params{MemoryKiB: 16 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	store, err := Open(Options{Path: path, Now: func() time.Time { return now }, Argon2: params})
	if err != nil {
		t.Fatal(err)
	}
	first, created, err := store.Bootstrap("Admin@Example.com", testPassword, permissions.RoleAdmin)
	if err != nil || !created || first.Email != "admin@example.com" || !first.MustChangePassword {
		t.Fatalf("first bootstrap = %#v, %v, %v", first, created, err)
	}
	second, created, err := store.Bootstrap("other@example.com", "a completely different password", permissions.RoleViewer)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("second bootstrap = %#v, %v, %v", second, created, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Options{Path: path, Now: func() time.Time { return now }, Argon2: params})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	authenticated, err := reopened.Authenticate("admin@example.com", testPassword)
	if err != nil || authenticated.ID != first.ID {
		t.Fatalf("authenticate after restart = %#v, %v", authenticated, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("data permissions = %o", info.Mode().Perm())
	}
}

func TestPasswordsAndSessionSecretsAreNotPersistedRaw(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	session, err := store.CreateSession(user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testPassword, session.Token, session.CSRFToken} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("raw secret persisted: %q", secret)
		}
	}
	if _, _, err = store.GetSession(session.Token); err != nil {
		t.Fatal(err)
	}
	if err = store.ValidateCSRF(session.Token, session.CSRFToken); err != nil {
		t.Fatal(err)
	}
	if err = store.ValidateCSRF(session.Token, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong CSRF error = %v", err)
	}
}

func TestSecurityVersionImmediatelyInvalidatesCredentials(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	client, err := store.RegisterClient(ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.CreateSession(user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.IssueTokenPair(TokenGrant{UserID: user.ID, ClientID: client.ID, Resource: "https://server.example/mcp", Scopes: []string{"mcp"}}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeUserSessions(user.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.GetSession(session.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("session error = %v", err)
	}
	if _, err = store.AuthenticateAccess(pair.AccessToken, "https://server.example/mcp"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("access error = %v", err)
	}
	if _, err = store.RotateRefresh(pair.RefreshToken, RefreshBinding{ClientID: client.ID, Resource: "https://server.example/mcp"}, time.Minute, time.Hour); !errors.Is(err, ErrRevoked) {
		t.Fatalf("refresh error = %v", err)
	}
}

func TestRevokingRefreshTokenRevokesAccessTokenFamily(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	client, err := store.RegisterClient(ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	binding := RefreshBinding{ClientID: client.ID, Resource: "https://server.example/mcp"}
	first, err := store.IssueTokenPair(TokenGrant{UserID: user.ID, ClientID: client.ID, Resource: binding.Resource, Scopes: []string{"mcp", "offline_access"}}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.RotateRefresh(first.RefreshToken, binding, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeToken(second.RefreshToken, client.ID); err != nil {
		t.Fatal(err)
	}
	for _, access := range []string{first.AccessToken, second.AccessToken} {
		if _, authErr := store.AuthenticateAccess(access, binding.Resource); !errors.Is(authErr, ErrRevoked) {
			t.Fatalf("family access token survived refresh revocation: %v", authErr)
		}
	}
	if _, err = store.RotateRefresh(second.RefreshToken, binding, time.Minute, time.Hour); !errors.Is(err, ErrRevoked) {
		t.Fatalf("refresh token survived family revocation: %v", err)
	}
}

func TestAuthorizationCodeIsBoundAndConsumedOnce(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	client, _ := store.RegisterClient(ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	grant := AuthorizationGrant{UserID: user.ID, ClientID: client.ID, RedirectURI: client.RedirectURIs[0], Resource: "https://server.example/mcp", CodeChallenge: "challenge", Scopes: []string{"mcp"}}
	code, err := store.CreateAuthorizationCode(grant, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ConsumeAuthorizationCode(code, CodeBinding{ClientID: client.ID, RedirectURI: client.RedirectURIs[0], Resource: grant.Resource, CodeChallenge: "wrong"}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("binding error = %v", err)
	}
	binding := CodeBinding{ClientID: client.ID, RedirectURI: client.RedirectURIs[0], Resource: grant.Resource, CodeChallenge: grant.CodeChallenge}
	const workers = 8
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, consumeErr := store.ConsumeAuthorizationCode(code, binding)
			results <- consumeErr
		}()
	}
	wg.Wait()
	close(results)
	success, consumed := 0, 0
	for result := range results {
		if result == nil {
			success++
		} else if errors.Is(result, ErrConsumed) {
			consumed++
		} else {
			t.Errorf("unexpected result: %v", result)
		}
	}
	if success != 1 || consumed != workers-1 {
		t.Fatalf("success=%d consumed=%d", success, consumed)
	}
}

func TestRefreshReplayRevokesTokenFamily(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	client, _ := store.RegisterClient(ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	binding := RefreshBinding{ClientID: client.ID, Resource: "https://server.example/mcp"}
	first, err := store.IssueTokenPair(TokenGrant{UserID: user.ID, ClientID: client.ID, Resource: binding.Resource, Scopes: []string{"mcp", "offline_access"}}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.RotateRefresh(first.RefreshToken, binding, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RotateRefresh(first.RefreshToken, binding, time.Minute, time.Hour); !errors.Is(err, ErrConsumed) {
		t.Fatalf("replay error = %v", err)
	}
	if _, err = store.RotateRefresh(second.RefreshToken, binding, time.Minute, time.Hour); !errors.Is(err, ErrRevoked) {
		t.Fatalf("family was not revoked: %v", err)
	}
}

func TestExpiryAndCleanup(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	session, _ := store.CreateSession(user.ID, time.Minute)
	now = now.Add(2 * time.Minute)
	if _, _, err := store.GetSession(session.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("session error = %v", err)
	}
	if err := store.CleanupExpired(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetSession(session.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleanup error = %v", err)
	}
}
