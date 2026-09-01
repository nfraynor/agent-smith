package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareUsesOAuthResourceChallenge(t *testing.T) {
	challenge := `Bearer realm="remoteops", resource_metadata="https://remoteops.example/.well-known/oauth-protected-resource/mcp"`
	handler := (Middleware{Challenge: challenge}).Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached handler")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != challenge {
		t.Fatalf("status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
}
