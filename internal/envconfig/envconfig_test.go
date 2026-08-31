package envconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	managedfs "github.com/nfraynor/agent-smith/internal/filesystem"
)

func envService(t *testing.T, content string) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := managedfs.New(map[string]managedfs.Root{"r": {Path: root}}, managedfs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return New(files, 1<<20, nil), root
}

func TestListAndGetRedactSecrets(t *testing.T) {
	s, _ := envService(t, "# header\nNORMAL=visible\nAPI_TOKEN=supersecret\n")
	vars, err := s.List("r", ".env", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 2 || vars[1].Value != RedactedValue || !vars[1].Secret {
		t.Fatalf("unexpected vars: %+v", vars)
	}
	revealed, err := s.Get("r", ".env", "API_TOKEN", true)
	if err != nil || revealed.Value != "supersecret" {
		t.Fatalf("revealed=%+v err=%v", revealed, err)
	}
}

func TestSetPreservesCommentsOrderingAndUnrelatedValues(t *testing.T) {
	s, root := envService(t, "# header\nA=one\nexport TOKEN = old  # keep me\nB='two words'\n")
	if err := s.Set("r", ".env", "TOKEN", "new value"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(root, ".env"))
	text := string(data)
	for _, want := range []string{"# header\nA=one\n", "export TOKEN = \"new value\"  # keep me", "\nB='two words'"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %q", want, text)
		}
	}
	if err := s.Set("r", ".env", "NEW", "x"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(root, ".env"))
	if !strings.HasSuffix(string(data), "NEW=x\n") {
		t.Fatalf("append failed: %q", data)
	}
}

func TestDeleteAndValidation(t *testing.T) {
	s, root := envService(t, "A=1\n# comment\nB=2\n")
	if err := s.Delete("r", ".env", "A"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(root, ".env"))
	if string(data) != "# comment\nB=2\n" {
		t.Fatalf("delete got %q", data)
	}
	if err := s.Delete("r", ".env", "NOPE"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := s.Set("r", ".env", "BAD-KEY", "x"); err == nil {
		t.Fatal("expected invalid key")
	}
}
