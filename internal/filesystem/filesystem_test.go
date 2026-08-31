package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newTestService(t *testing.T, opts Options) *Service {
	t.Helper()
	root := t.TempDir()
	s, err := New(map[string]Root{"apps": {Path: root}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveRejectsTraversalAndAbsolutePaths(t *testing.T) {
	s := newTestService(t, Options{})
	for _, path := range []string{"../secret", "a/../../secret", filepath.Join(string(filepath.Separator), "etc", "passwd")} {
		if _, err := s.Resolve("apps", path, false); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Resolve(%q) error = %v", path, err)
		}
	}
	if _, err := s.Resolve("missing", "x", false); !errors.Is(err, ErrUnknownRoot) {
		t.Fatalf("expected unknown root, got %v", err)
	}
}

func TestResolveRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation unavailable")
		}
		t.Fatal(err)
	}
	s, err := New(map[string]Root{"r": {Path: root}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Read("r", "escape/secret", 0, 10); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("expected symlink escape, got %v", err)
	}
}

func TestBoundedReadListAndAtomicWrite(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("abcdef"), 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := New(map[string]Root{"r": {Path: root}}, Options{MaxReadBytes: 4, MaxEntries: 1, MaxDiffBytes: 20})
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.Read("r", "a.txt", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Data) != "bcd" || !read.Truncated || read.NextOffset != 4 {
		t.Fatalf("unexpected read: %+v", read)
	}
	if _, err = s.Read("r", "a.txt", 0, 5); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected read limit, got %v", err)
	}
	if err = os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.List("r", ".", 0); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected list limit, got %v", err)
	}
	if err = s.WriteAtomic("r", "a.txt", []byte("changed"), 0); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "a.txt"))
	if err != nil || string(got) != "changed" {
		t.Fatalf("write got %q, %v", got, err)
	}
}

func TestReadOnlyAndDiff(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "a"), []byte("one\n"), 0o600)
	s, err := New(map[string]Root{"r": {Path: root, ReadOnly: true}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.WriteAtomic("r", "a", []byte("two\n"), 0); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("expected readonly, got %v", err)
	}
	diff, err := s.Diff("r", "a", []byte("two\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "-one") || !strings.Contains(diff, "+two") {
		t.Fatalf("bad diff: %s", diff)
	}
}
