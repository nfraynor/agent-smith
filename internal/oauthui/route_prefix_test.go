package oauthui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestBrowserAuthenticationRoutesUseOAuthPrefix(t *testing.T) {
	handler := newHandler(t, newFakeBackend(permissions.RoleAdmin), nil)

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://remote.test/oauth/login", nil))
	if login.Code != http.StatusOK {
		t.Fatalf("prefixed login returned %d", login.Code)
	}

	legacy := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/login"},
		{http.MethodPost, "/logout"},
		{http.MethodGet, "/account/password"},
		{http.MethodGet, "/admin/users"},
	}
	for _, route := range legacy {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, "https://remote.test"+route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("legacy route %s %s returned %d", route.method, route.path, response.Code)
		}
	}
}
