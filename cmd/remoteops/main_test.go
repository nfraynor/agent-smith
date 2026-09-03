package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nfraynor/agent-smith/internal/limits"
)

func TestOAuthRouterDoesNotRedirectExactAccountPath(t *testing.T) {
	protocol := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	mux := routeOAuthHandlers(protocol, protocol, ui)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/account", nil))
	if response.Code != http.StatusTeapot || response.Header().Get("Location") != "" {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestHTTPRateLimitUsesSourceAddressBeforeAuthentication(t *testing.T) {
	called := 0
	handler := httpRateLimit(limits.NewLimiter(1, 1), http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		called++
		writer.WriteHeader(http.StatusNoContent)
	}))

	for attempt, want := range []int{http.StatusNoContent, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		request.RemoteAddr = "192.0.2.10:54321"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("attempt %d: got status %d, want %d", attempt+1, response.Code, want)
		}
	}
	if called != 1 {
		t.Fatalf("downstream handler called %d times, want 1", called)
	}
}
