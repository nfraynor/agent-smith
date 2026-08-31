package locks

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSameTargetSerializesAndDifferentTargetDoesNot(t *testing.T) {
	manager := New()
	unlock, err := manager.Lock(context.Background(), "service:app:api")
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan func(), 1)
	go func() {
		next, err := manager.Lock(context.Background(), "service:app:api")
		if err == nil {
			acquired <- next
		}
	}()
	select {
	case <-acquired:
		t.Fatal("same target lock was acquired concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	other, err := manager.Lock(context.Background(), "service:app:worker")
	if err != nil {
		t.Fatal(err)
	}
	other()
	unlock()
	unlock() // Idempotent by contract.
	select {
	case next := <-acquired:
		next()
	case <-time.After(time.Second):
		t.Fatal("waiter did not acquire after unlock")
	}
	if manager.ActiveTargets() != 0 {
		t.Fatalf("lock entries leaked: %d", manager.ActiveTargets())
	}
}

func TestCanceledWaiterDoesNotStrandLock(t *testing.T) {
	manager := New()
	unlock, _ := manager.Lock(context.Background(), "file:/config/app.yaml")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Lock(ctx, "file:/config/app.yaml"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	unlock()
	next, err := manager.Lock(context.Background(), "file:/config/app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	next()
}

func TestLockKeyHelpers(t *testing.T) {
	if FileKey("/x") != "file:/x" || ServiceKey("p", "s") != "service:p:s" || ContainerKey("abc") != "container:abc" {
		t.Fatal("unexpected lock key")
	}
}
