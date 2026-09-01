package deployment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/changes"
)

// ContextChangeRecorder attributes deployment records to the authenticated caller.
// FallbackActor is used only by legacy non-request callers that have no identity.
type ContextChangeRecorder struct {
	Store         *changes.Store
	FallbackActor string
}

func (r ContextChangeRecorder) Record(ctx context.Context, event Change) (string, error) {
	if r.Store == nil {
		return "", nil
	}
	actor := r.FallbackActor
	if identity, ok := auth.IdentityFromContext(ctx); ok && identity.Actor != "" {
		actor = identity.Actor
	}
	if actor == "" {
		actor = "unknown"
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("encode deployment change: %w", err)
	}
	record, err := r.Store.Record(changes.RecordInput{
		Actor: actor, Operation: event.Operation, Target: event.Target,
		Description: event.Description + " (" + event.Status + ")",
		After:       payload, External: true,
	})
	if err != nil {
		return "", err
	}
	return record.ID, nil
}
