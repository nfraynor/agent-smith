package deployment

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nfraynor/agent-smith/internal/changes"
)

func TestChangeRecorderPersistsNonRollbackableDeployment(t *testing.T) {
	store, err := changes.New(filepath.Join(t.TempDir(), "changes"), changes.Options{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := (ChangeRecorder{Store: store, Actor: "operator"}).Record(context.Background(), Change{Operation: "deploy_service", Target: "app:api", Description: "Deploy", Status: "applied", Metadata: map[string]string{"currentImage": "sha256:new"}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if record.RollbackSupported {
		t.Fatal("deployment record incorrectly advertised rollback support")
	}
	if _, err = store.Rollback(id, "operator", false); !errors.Is(err, changes.ErrRollbackUnsupported) {
		t.Fatalf("rollback error = %v", err)
	}
}
