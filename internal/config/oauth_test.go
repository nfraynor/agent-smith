package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOAuthLocalIsDefaultAuthenticationMode(t *testing.T) {
	cfg := Defaults()
	if cfg.Auth.Mode != "oauth-local" {
		t.Fatalf("default auth mode = %q, want oauth-local", cfg.Auth.Mode)
	}
}

func TestLoadOAuthLocalConfigAndBootstrapSecret(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "bootstrap-password")
	if err := os.WriteFile(secretPath, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `
server:
  name: oauth-test
auth:
  oauth_local:
    public_origin: https://remoteops.example
    data_file: /data/oauth.db
    bootstrap_email_env: TEST_BOOTSTRAP_EMAIL
    bootstrap_password_file_env: TEST_BOOTSTRAP_PASSWORD_FILE
    allowed_redirect_uris:
      - https://chatgpt.example/callback
permissions:
  default_role: viewer
`)

	cfg, err := LoadWithEnv(path, mapLookup(map[string]string{
		"REMOTEOPS_GODMODE":            "false",
		"TEST_BOOTSTRAP_EMAIL":         "admin@example.com",
		"TEST_BOOTSTRAP_PASSWORD_FILE": secretPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.Mode != "oauth-local" {
		t.Fatalf("loaded auth mode = %q, want oauth-local", cfg.Auth.Mode)
	}
	if cfg.Auth.OAuthLocal.BootstrapEmail != "admin@example.com" || cfg.Auth.OAuthLocal.BootstrapPassword != "correct horse battery staple" {
		t.Fatalf("bootstrap values not resolved: %#v", cfg.Auth.OAuthLocal)
	}
	if cfg.BearerToken != "" {
		t.Fatal("OAuth mode unexpectedly resolved a bearer token")
	}
}

func TestOAuthLocalValidationRejectsUnsafeOriginsAndRedirects(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		redirect   string
		wantSubstr string
	}{
		{"http origin", "http://remoteops.example", "https://client.example/callback", "public_origin"},
		{"origin path", "https://remoteops.example/base", "https://client.example/callback", "public_origin"},
		{"redirect fragment", "https://remoteops.example", "https://client.example/callback#fragment", "redirect URI"},
		{"redirect http", "https://remoteops.example", "http://client.example/callback", "redirect URI"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Server.Name = "test"
			cfg.Auth.Mode = "oauth-local"
			cfg.Auth.OAuthLocal.PublicOrigin = test.origin
			cfg.Auth.OAuthLocal.AllowedRedirectURIs = []string{test.redirect}
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.wantSubstr) {
				t.Fatalf("got %v, want error containing %q", err, test.wantSubstr)
			}
		})
	}
}
