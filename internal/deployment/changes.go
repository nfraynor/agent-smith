package deployment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nfraynor/agent-smith/internal/changes"
)

// ChangeRecorder persists deployment outcomes in the common change history. The
// record is intentionally marked non-rollbackable: restoring a file backup is not a
// safe substitute for orchestrating an image rollback.
type ChangeRecorder struct {
	Store *changes.Store
	Actor string
}

func (r ChangeRecorder) Record(_ context.Context, event Change) (string, error) {
	if r.Store == nil {
		return "", nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("encode deployment change: %w", err)
	}
	record, err := r.Store.Record(changes.RecordInput{
		Actor: r.Actor, Operation: event.Operation, Target: event.Target,
		Description: event.Description + " (" + event.Status + ")",
		After:       payload, External: true,
	})
	if err != nil {
		return "", err
	}
	return record.ID, nil
}
