package oauthserver

import (
	"net/http"
	"testing"
)

func TestDynamicRegistrationRateLimit(t *testing.T) {
	server := newTestServer(t, newMemoryStore())
	body := `{"redirect_uris":["` + testRedirect + `"],"client_name":"ChatGPT"}`
	for range 30 {
		if response := serve(server, http.MethodPost, "/oauth/register", body, "application/json"); response.Code != http.StatusCreated {
			t.Fatalf("registration before limit returned %d", response.Code)
		}
	}
	response := serve(server, http.MethodPost, "/oauth/register", body, "application/json")
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" {
		t.Fatalf("rate-limited registration = %d, retry-after=%q", response.Code, response.Header().Get("Retry-After"))
	}
}
