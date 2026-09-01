package deployment

import (
	"context"
	"testing"

	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/changes"
	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestContextChangeRecorderUsesAuthenticatedActor(t *testing.T) {
	store, err := changes.New(t.TempDir(), changes.Options{RetentionDays: 1, MaxRecords: 10, MaxTargetBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Actor: "alice@example.com", Role: permissions.RoleOperator})
	id, err := (ContextChangeRecorder{Store: store, FallbackActor: "legacy"}).Record(ctx, Change{Operation: "deploy_service", Target: "app:api", Description: "Deploy", Status: "applied"})
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if record.Actor != "alice@example.com" {
		t.Fatalf("actor = %q, want authenticated actor", record.Actor)
	}
}
