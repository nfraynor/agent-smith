package deployment

import (
	"context"
	"errors"
	"testing"
	"time"

	remotecompose "github.com/nfraynor/agent-smith/internal/compose"
	"github.com/nfraynor/agent-smith/internal/diagnostics"
	remotedocker "github.com/nfraynor/agent-smith/internal/docker"
)

type fakeCompose struct {
	calls       []string
	validateErr error
}

func (f *fakeCompose) Validate(context.Context, string) (remotecompose.OperationResult, error) {
	f.calls = append(f.calls, "validate")
	return remotecompose.OperationResult{}, f.validateErr
}
func (f *fakeCompose) Pull(context.Context, string, string) (remotecompose.OperationResult, error) {
	f.calls = append(f.calls, "pull")
	return remotecompose.OperationResult{}, nil
}
func (f *fakeCompose) Up(context.Context, string, string, bool) (remotecompose.OperationResult, error) {
	f.calls = append(f.calls, "up")
	return remotecompose.OperationResult{}, nil
}
func (f *fakeCompose) Status(context.Context, string) ([]remotecompose.ServiceStatus, error) {
	return []remotecompose.ServiceStatus{{Name: "app-api-1", Service: "api", State: "running", Image: "api:old"}}, nil
}
func (f *fakeCompose) Logs(context.Context, string, string, int, string) (remotecompose.LogsResult, error) {
	return remotecompose.LogsResult{Content: "failure log"}, nil
}

type fakeDocker struct{}

func (fakeDocker) Inspect(context.Context, string) (remotedocker.InspectResult, error) {
	return remotedocker.InspectResult{Container: remotedocker.Container{ImageID: "sha256:new"}}, nil
}
func (fakeDocker) Pull(context.Context, string) (remotedocker.PullResult, error) {
	return remotedocker.PullResult{CurrentDigest: "sha256:new"}, nil
}

type fakeHealth struct{}

func (fakeHealth) ServiceHealth(context.Context, string, string) (diagnostics.HealthResult, error) {
	return diagnostics.HealthResult{Container: "app-api-1", Status: "healthy"}, nil
}

type fakeRecorder struct{ changes []Change }

func (f *fakeRecorder) Record(_ context.Context, c Change) (string, error) {
	f.changes = append(f.changes, c)
	return "chg_1", nil
}

func TestDeployVerifiesAndRecords(t *testing.T) {
	c := &fakeCompose{}
	r := &fakeRecorder{}
	s := New(c, fakeDocker{}, fakeHealth{}, r, Options{VerificationTimeout: time.Second, PollInterval: time.Millisecond})
	got, err := s.Deploy(context.Background(), Request{Project: "app", Service: "api"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Success || got.Health != "healthy" || got.CurrentImage != "sha256:new" || got.ChangeID != "chg_1" {
		t.Fatalf("unexpected result: %#v", got)
	}
	if len(r.changes) != 1 || r.changes[0].Status != "applied" {
		t.Fatalf("changes=%#v", r.changes)
	}
}

func TestDeployValidationFailureReturnsBoundedDiagnostics(t *testing.T) {
	c := &fakeCompose{validateErr: errors.New("invalid")}
	r := &fakeRecorder{}
	s := New(c, fakeDocker{}, fakeHealth{}, r, Options{})
	got, err := s.Deploy(context.Background(), Request{Project: "app", Service: "api"})
	if err == nil {
		t.Fatal("expected error")
	}
	if got.Success || got.Logs != "failure log" || len(r.changes) != 1 || r.changes[0].Status != "failed" {
		t.Fatalf("unexpected result: %#v changes=%#v", got, r.changes)
	}
}
