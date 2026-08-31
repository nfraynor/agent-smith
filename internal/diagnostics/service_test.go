package diagnostics

import (
	"context"
	"testing"

	remotecompose "github.com/nfraynor/agent-smith/internal/compose"
	remotedocker "github.com/nfraynor/agent-smith/internal/docker"
)

type fakeDocker struct {
	inspected  remotedocker.InspectResult
	containers []remotedocker.Container
}

func (f fakeDocker) List(context.Context, bool) ([]remotedocker.Container, error) {
	return f.containers, nil
}
func (f fakeDocker) Inspect(context.Context, string) (remotedocker.InspectResult, error) {
	return f.inspected, nil
}
func (f fakeDocker) Logs(context.Context, string, int, string, bool) (remotedocker.LogsResult, error) {
	return remotedocker.LogsResult{Content: "bounded"}, nil
}
func (f fakeDocker) Stats(context.Context, string) (remotedocker.Stats, error) {
	return remotedocker.Stats{MemoryBytes: 42}, nil
}

type fakeCompose struct{ statuses []remotecompose.ServiceStatus }

func (f fakeCompose) Status(context.Context, string) ([]remotecompose.ServiceStatus, error) {
	return f.statuses, nil
}

func TestServiceHealthPrefersDockerHealthcheck(t *testing.T) {
	d := fakeDocker{inspected: remotedocker.InspectResult{Container: remotedocker.Container{Name: "app-api-1", State: "running", Health: "healthy"}}}
	c := fakeCompose{statuses: []remotecompose.ServiceStatus{{Name: "app-api-1", Service: "api"}}}
	s := New(d, c, nil, nil, "test", false)
	h, err := s.ServiceHealth(context.Background(), "app", "api")
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "healthy" || h.Source != "docker_healthcheck" {
		t.Fatalf("unexpected health: %#v", h)
	}
}

func TestSystemSummaryCountsStates(t *testing.T) {
	s := New(fakeDocker{containers: []remotedocker.Container{{State: "running", Health: "unhealthy"}, {State: "exited"}}}, nil, nil, nil, "test", true)
	got, err := s.SystemSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.RunningContainers != 1 || got.StoppedContainers != 1 || got.UnhealthyContainers != 1 || !got.GodMode {
		t.Fatalf("unexpected summary: %#v", got)
	}
}
