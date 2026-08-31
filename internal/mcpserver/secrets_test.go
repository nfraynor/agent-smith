package mcpserver

import (
	"testing"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestSensitiveReadClassificationAndPermission(t *testing.T) {
	for _, path := range []string{".env", "tls/private.key", "id_rsa", "app-secrets.yaml"} {
		if !sensitiveFile(path) {
			t.Errorf("%q was not classified as sensitive", path)
		}
	}
	if sensitiveFile("compose.yaml") {
		t.Fatal("ordinary Compose file classified as sensitive")
	}
	if !sensitiveKey("services.api.environment.API_TOKEN") {
		t.Fatal("secret YAML path was not classified")
	}
	authorizer := permissions.Authorizer{}
	if authorizer.Allowed(permissions.RoleViewer, permissions.SecretsRead) || authorizer.Allowed(permissions.RoleOperator, permissions.SecretsRead) {
		t.Fatal("non-admin role received secret-read access")
	}
	if !authorizer.Allowed(permissions.RoleAdmin, permissions.SecretsRead) {
		t.Fatal("admin lacks secret-read access")
	}
}
