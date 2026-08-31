package yamlconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	managedfs "github.com/nfraynor/agent-smith/internal/filesystem"
)

func yamlService(t *testing.T, content string) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := managedfs.New(map[string]managedfs.Root{"r": {Path: root}}, managedfs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return New(files, 1<<20), root
}

func TestGetPreviewSetAndPreserveCommentsOrder(t *testing.T) {
	s, root := yamlService(t, "# top\nservices:\n  api:\n    # level\n    level: INFO # inline\n    port: 8080\n")
	got, err := s.Get("r", "config.yml", "services.api.level")
	if err != nil || got != "INFO" {
		t.Fatalf("Get = %#v, %v", got, err)
	}
	preview, err := s.PreviewSet("r", "config.yml", "services.api.level", "DEBUG")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.Diff, "DEBUG") {
		t.Fatalf("diff missing value: %s", preview.Diff)
	}
	original, _ := os.ReadFile(filepath.Join(root, "config.yml"))
	if strings.Contains(string(original), "DEBUG") {
		t.Fatal("preview wrote file")
	}
	if _, err = s.Set("r", "config.yml", "services.api.level", "DEBUG"); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(filepath.Join(root, "config.yml"))
	text := string(updated)
	for _, want := range []string{"# top", "# level", "# inline", "level: DEBUG", "port: 8080"} {
		if !strings.Contains(text, want) {
			t.Errorf("updated YAML missing %q:\n%s", want, text)
		}
	}
}

func TestSequenceAndDelete(t *testing.T) {
	s, _ := yamlService(t, "items:\n  - one\n  - two\nmap:\n  a: 1\n  b: 2\n")
	got, err := s.Get("r", "config.yml", "items[1]")
	if err != nil || got != "two" {
		t.Fatalf("got %#v, %v", got, err)
	}
	if _, err = s.Delete("r", "config.yml", "map.a"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get("r", "config.yml", "map.a"); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("expected missing path, got %v", err)
	}
}

func TestMissingAndMalformedPaths(t *testing.T) {
	s, _ := yamlService(t, "a: 1\n")
	if _, err := s.Get("r", "config.yml", "missing"); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("got %v", err)
	}
	for _, path := range []string{".a", "a.", "a[x]"} {
		if _, err := s.Get("r", "config.yml", path); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("%q got %v", path, err)
		}
	}
}
