package changes

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T, opts Options) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "changes"), opts)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestRecordGetListAndDiff(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	s := newStore(t, Options{Now: func() time.Time { return now }})
	change, err := s.Record(RecordInput{Actor: "chatgpt", Operation: "yaml_set", Target: "/managed/config.yml", Description: "set level", Before: []byte("level: INFO\n"), After: []byte("level: DEBUG\n")})
	if err != nil {
		t.Fatal(err)
	}
	if !idPattern.MatchString(change.ID) || change.BeforeHash == change.AfterHash || change.Status != "applied" {
		t.Fatalf("bad change: %+v", change)
	}
	got, err := s.Get(change.ID)
	if err != nil || got.ID != change.ID {
		t.Fatalf("Get=%+v, %v", got, err)
	}
	diff, err := s.Diff(change.ID)
	if err != nil || !strings.Contains(diff, "-level: INFO") || !strings.Contains(diff, "+level: DEBUG") {
		t.Fatalf("Diff=%q, %v", diff, err)
	}
	list, err := s.List(ListFilter{Since: now.Add(-time.Hour), Operation: "yaml_set", Target: "config", Limit: 1})
	if err != nil || len(list) != 1 {
		t.Fatalf("List=%+v, %v", list, err)
	}
	if _, err = s.Get("../../metadata"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid id got %v", err)
	}
}

func TestRollbackAndConflictDetection(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "config.yml")
	before := []byte("value: old\n")
	after := []byte("value: new\n")
	if err := os.WriteFile(target, after, 0o640); err != nil {
		t.Fatal(err)
	}
	s := newStore(t, Options{})
	original, err := s.Record(RecordInput{Actor: "a", Operation: "yaml_set", Target: target, Before: before, After: after})
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := s.Rollback(original.ID, "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if rollback.RollbackOf != original.ID || rollback.Operation != "change_rollback" {
		t.Fatalf("bad rollback: %+v", rollback)
	}
	data, _ := os.ReadFile(target)
	if string(data) != string(before) {
		t.Fatalf("target=%q", data)
	}
	if err = os.WriteFile(target, []byte("third party\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Rollback(original.ID, "admin", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err = s.Rollback(original.ID, "admin", true); err != nil {
		t.Fatalf("force rollback: %v", err)
	}
}

func TestRollbackRejectsTamperedBackup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "x")
	_ = os.WriteFile(target, []byte("after"), 0o600)
	s := newStore(t, Options{})
	change, err := s.Record(RecordInput{Operation: "file_write", Target: target, Before: []byte("before"), After: []byte("after")})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.dir, change.ID, "before"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Rollback(change.ID, "admin", false); err == nil || !strings.Contains(err.Error(), "backup hash") {
		t.Fatalf("expected tamper error, got %v", err)
	}
}

func TestRetentionByCountAndAgeCallsHook(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	pruned := 0
	s := newStore(t, Options{MaxRecords: 2, RetentionDays: 1, Now: func() time.Time { return now }, OnPrune: func(Change) error { pruned++; return nil }})
	for i := 0; i < 3; i++ {
		if _, err := s.Record(RecordInput{Operation: "x", Target: "/x", Before: []byte{byte(i)}, After: []byte{byte(i + 1)}}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	all, err := s.listAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || pruned != 1 {
		t.Fatalf("records=%d pruned=%d", len(all), pruned)
	}
	now = now.Add(48 * time.Hour)
	if err = s.Prune(); err != nil {
		t.Fatal(err)
	}
	all, _ = s.listAll()
	if len(all) != 0 {
		t.Fatalf("age retention left %d", len(all))
	}
}
