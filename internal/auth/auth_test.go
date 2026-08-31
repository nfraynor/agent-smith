package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestBearerMiddlewareSetsIdentity(t *testing.T) {
	authenticator, err := NewBearer("correct-token", "chatgpt", permissions.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	var attempts []Attempt
	handler := Middleware{Authenticator: authenticator, OnAttempt: func(a Attempt) { attempts = append(attempts, a) }}.Wrap(
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity, ok := IdentityFromContext(request.Context())
			if !ok || identity.Actor != "chatgpt" || identity.Role != permissions.RoleOperator {
				t.Fatalf("unexpected identity: %#v, %v", identity, ok)
			}
			writer.WriteHeader(http.StatusNoContent)
		}),
	)
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer correct-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || len(attempts) != 1 || !attempts[0].Success {
		t.Fatalf("unexpected response or attempts: %d, %#v", response.Code, attempts)
	}
}

func TestBearerMiddlewareRejectsWithoutLeakingToken(t *testing.T) {
	authenticator, _ := NewBearer("server-secret", "remote-client", permissions.RoleViewer)
	var attempts []Attempt
	handler := Middleware{Authenticator: authenticator, OnAttempt: func(a Attempt) { attempts = append(attempts, a) }}.Wrap(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler must not be invoked") }),
	)
	for _, header := range []string{"", "Basic bad", "Bearer", "bearer bad", "Bearer wrong-secret", "Bearer two words"} {
		request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		body, _ := io.ReadAll(response.Body)
		if response.Code != http.StatusUnauthorized || strings.Contains(string(body), "secret") {
			t.Errorf("header %q: code %d, body %q", header, response.Code, body)
		}
	}
	for _, attempt := range attempts {
		if strings.Contains(attempt.Reason, "secret") {
			t.Fatalf("attempt leaked credentials: %#v", attempt)
		}
	}
}

func TestBearerRejectsDuplicateHeaders(t *testing.T) {
	authenticator, _ := NewBearer("token", "actor", permissions.RoleViewer)
	handler := Middleware{Authenticator: authenticator}.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not be invoked")
	}))
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)
	request.Header.Add("Authorization", "Bearer token")
	request.Header.Add("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestIdentityContextDoesNotUsePublicStringKey(t *testing.T) {
	ctx := context.WithValue(context.Background(), "identity", Identity{Actor: "attacker"})
	if _, ok := IdentityFromContext(ctx); ok {
		t.Fatal("identity was accepted from a colliding public context key")
	}
}
