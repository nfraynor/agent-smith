package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestLoadStrictConfigAndDefaults(t *testing.T) {
	path := writeConfig(t, `
server:
  name: dev-01
auth:
  mode: bearer
  token_env: TEST_REMOTEOPS_TOKEN
filesystem:
  roots:
    - name: apps
      path: /managed/apps
compose:
  projects:
    - name: app
      path: /managed/apps/app
      file: compose.yaml
permissions:
  default_role: operator
`)
	env := map[string]string{"TEST_REMOTEOPS_TOKEN": "top-secret", "REMOTEOPS_GODMODE": "false"}
	config, err := LoadWithEnv(path, mapLookup(env))
	if err != nil {
		t.Fatal(err)
	}
	if config.Server.Listen != ":8080" || config.Limits.MaxLogBytes != 1<<20 {
		t.Fatalf("defaults were not applied: %#v", config)
	}
	if config.BearerToken != "top-secret" || config.Permissions.DefaultRole != permissions.RoleOperator {
		t.Fatalf("secrets or role were not resolved: %#v", config)
	}
}

func TestLoadRejectsUnknownKeysAndMultipleDocuments(t *testing.T) {
	unknown := writeConfig(t, "server:\n  name: dev\n  typo: value\n")
	if _, err := LoadWithEnv(unknown, mapLookup(map[string]string{"REMOTEOPS_TOKEN": "x"})); err == nil || !strings.Contains(err.Error(), "field typo not found") {
		t.Fatalf("expected useful unknown-key error, got %v", err)
	}
	multiple := writeConfig(t, "server:\n  name: dev\n---\nserver:\n  name: other\n")
	if _, err := LoadWithEnv(multiple, mapLookup(map[string]string{"REMOTEOPS_TOKEN": "x"})); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func TestGodModeParsingIsExactAndFailClosed(t *testing.T) {
	tests := []struct {
		value   string
		present bool
		want    bool
		wantErr bool
	}{
		{"", false, false, false}, {"", true, false, false},
		{"false", true, false, false}, {"true", true, true, false},
		{"TRUE", true, false, true}, {" true", true, false, true},
		{"1", true, false, true}, {"yes", true, false, true},
	}
	for _, test := range tests {
		got, err := ParseGodMode(func(string) (string, bool) { return test.value, test.present })
		if got != test.want || (err != nil) != test.wantErr {
			t.Errorf("ParseGodMode(%q, %v) = (%v, %v)", test.value, test.present, got, err)
		}
	}
}

func TestValidationRejectsUnsafeAndAmbiguousResources(t *testing.T) {
	config := Defaults()
	config.Server.Name = "dev"
	config.Auth.Mode = "bearer"
	config.BearerToken = "x"
	config.Filesystem.Roots = []Root{{Name: "host", Path: string(filepath.Separator)}}
	if err := config.Validate(); err == nil {
		t.Fatal("expected filesystem root to be rejected")
	}
	config.Filesystem.Roots = []Root{{Name: "apps", Path: filepath.Join(string(filepath.Separator), "managed")}}
	config.Compose.Projects = []Project{{Name: "app", Path: filepath.Join(string(filepath.Separator), "managed", "app"), File: "../compose.yaml"}}
	if err := config.Validate(); err == nil {
		t.Fatal("expected unsafe compose filename to be rejected")
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "remoteops.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}
