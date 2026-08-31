// Package diagnostics gathers deterministic service and system facts.
package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	remotecompose "github.com/nfraynor/agent-smith/internal/compose"
	remotedocker "github.com/nfraynor/agent-smith/internal/docker"
)

type Docker interface {
	List(context.Context, bool) ([]remotedocker.Container, error)
	Inspect(context.Context, string) (remotedocker.InspectResult, error)
	Logs(context.Context, string, int, string, bool) (remotedocker.LogsResult, error)
	Stats(context.Context, string) (remotedocker.Stats, error)
}

type Compose interface {
	Status(context.Context, string) ([]remotecompose.ServiceStatus, error)
}

type ProbeType string

const (
	ProbeHTTP ProbeType = "http"
	ProbeTCP  ProbeType = "tcp"
)

type HealthConfig struct {
	Project        string
	Service        string
	Type           ProbeType
	URL            string
	Address        string
	ExpectedStatus int
	Timeout        time.Duration
}

type FilesystemUsage struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	TotalBytes     uint64 `json:"totalBytes"`
	UsedBytes      uint64 `json:"usedBytes"`
	AvailableBytes uint64 `json:"availableBytes"`
}
type FilesystemReporter interface {
	Usage(context.Context) ([]FilesystemUsage, error)
}

type Service struct {
	docker     Docker
	compose    Compose
	files      FilesystemReporter
	health     map[string]HealthConfig
	httpClient *http.Client
	started    time.Time
	version    string
	godMode    bool
}

func New(docker Docker, compose Compose, files FilesystemReporter, health []HealthConfig, version string, godMode bool) *Service {
	m := make(map[string]HealthConfig, len(health))
	for _, h := range health {
		m[key(h.Project, h.Service)] = h
	}
	return &Service{docker: docker, compose: compose, files: files, health: m, httpClient: &http.Client{}, started: time.Now(), version: version, godMode: godMode}
}

type HealthResult struct {
	Project   string `json:"project,omitempty"`
	Service   string `json:"service"`
	Container string `json:"container,omitempty"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	Detail    string `json:"detail,omitempty"`
	LatencyMs int64  `json:"latencyMs,omitempty"`
}

func (s *Service) ServiceHealth(ctx context.Context, project, service string) (HealthResult, error) {
	container, err := s.resolveContainer(ctx, project, service)
	if err != nil {
		return HealthResult{}, err
	}
	inspected, err := s.docker.Inspect(ctx, container)
	if err != nil {
		return HealthResult{}, fmt.Errorf("inspect service %q: %w", service, err)
	}
	base := HealthResult{Project: project, Service: service, Container: inspected.Name}
	if inspected.Health != "" && inspected.Health != "none" {
		base.Status = inspected.Health
		base.Source = "docker_healthcheck"
		return base, nil
	}
	if cfg, ok := s.health[key(project, service)]; ok {
		started := time.Now()
		probeCtx := ctx
		cancel := func() {}
		if cfg.Timeout > 0 {
			probeCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		}
		defer cancel()
		base.Source = string(cfg.Type)
		switch cfg.Type {
		case ProbeHTTP:
			req, reqErr := http.NewRequestWithContext(probeCtx, http.MethodGet, cfg.URL, nil)
			if reqErr != nil {
				return HealthResult{}, fmt.Errorf("create health request: %w", reqErr)
			}
			resp, probeErr := s.httpClient.Do(req)
			base.LatencyMs = time.Since(started).Milliseconds()
			if probeErr != nil {
				base.Status = "unhealthy"
				base.Detail = probeErr.Error()
				return base, nil
			}
			defer resp.Body.Close()
			expected := cfg.ExpectedStatus
			if expected == 0 {
				expected = http.StatusOK
			}
			if resp.StatusCode == expected {
				base.Status = "healthy"
			} else {
				base.Status = "unhealthy"
				base.Detail = fmt.Sprintf("expected HTTP %d, got %d", expected, resp.StatusCode)
			}
			return base, nil
		case ProbeTCP:
			dialer := net.Dialer{}
			conn, probeErr := dialer.DialContext(probeCtx, "tcp", cfg.Address)
			base.LatencyMs = time.Since(started).Milliseconds()
			if probeErr != nil {
				base.Status = "unhealthy"
				base.Detail = probeErr.Error()
				return base, nil
			}
			_ = conn.Close()
			base.Status = "healthy"
			return base, nil
		default:
			return HealthResult{}, fmt.Errorf("unsupported health probe %q", cfg.Type)
		}
	}
	base.Source = "container_state"
	if inspected.State == "running" {
		base.Status = "running"
	} else {
		base.Status = "unhealthy"
		base.Detail = "container state is " + inspected.State
	}
	return base, nil
}

type Diagnostic struct {
	Project    string                        `json:"project,omitempty"`
	Service    string                        `json:"service"`
	Container  remotedocker.InspectResult    `json:"container"`
	Health     HealthResult                  `json:"health"`
	Stats      remotedocker.Stats            `json:"stats"`
	RecentLogs remotedocker.LogsResult       `json:"recentLogs"`
	Compose    []remotecompose.ServiceStatus `json:"compose,omitempty"`
	Warnings   []string                      `json:"warnings,omitempty"`
}

func (s *Service) DiagnoseService(ctx context.Context, project, service string) (Diagnostic, error) {
	container, err := s.resolveContainer(ctx, project, service)
	if err != nil {
		return Diagnostic{}, err
	}
	d := Diagnostic{Project: project, Service: service}
	if d.Container, err = s.docker.Inspect(ctx, container); err != nil {
		return d, fmt.Errorf("inspect service: %w", err)
	}
	if d.Health, err = s.ServiceHealth(ctx, project, service); err != nil {
		d.Warnings = append(d.Warnings, "health: "+err.Error())
	}
	if d.Stats, err = s.docker.Stats(ctx, container); err != nil {
		d.Warnings = append(d.Warnings, "stats: "+err.Error())
	}
	if d.RecentLogs, err = s.docker.Logs(ctx, container, 200, "", true); err != nil {
		d.Warnings = append(d.Warnings, "logs: "+err.Error())
	}
	if project != "" && s.compose != nil {
		if d.Compose, err = s.compose.Status(ctx, project); err != nil {
			d.Warnings = append(d.Warnings, "compose: "+err.Error())
		}
	}
	return d, nil
}

type SystemSummary struct {
	DockerConnected     bool              `json:"dockerConnected"`
	RunningContainers   int               `json:"runningContainerCount"`
	StoppedContainers   int               `json:"stoppedContainerCount"`
	UnhealthyContainers int               `json:"unhealthyContainerCount"`
	Filesystems         []FilesystemUsage `json:"filesystems,omitempty"`
	Version             string            `json:"version"`
	UptimeSeconds       int64             `json:"uptimeSeconds"`
	GodMode             bool              `json:"godMode"`
	Warnings            []string          `json:"warnings,omitempty"`
}

func (s *Service) SystemSummary(ctx context.Context) (SystemSummary, error) {
	r := SystemSummary{Version: s.version, UptimeSeconds: int64(time.Since(s.started).Seconds()), GodMode: s.godMode}
	containers, err := s.docker.List(ctx, true)
	if err != nil {
		return r, fmt.Errorf("docker connectivity: %w", err)
	}
	r.DockerConnected = true
	for _, c := range containers {
		if c.State == "running" {
			r.RunningContainers++
		} else {
			r.StoppedContainers++
		}
		if c.Health == "unhealthy" {
			r.UnhealthyContainers++
		}
	}
	if s.files != nil {
		if r.Filesystems, err = s.files.Usage(ctx); err != nil {
			r.Warnings = append(r.Warnings, "filesystem usage: "+err.Error())
		}
	}
	return r, nil
}

func (s *Service) resolveContainer(ctx context.Context, project, service string) (string, error) {
	if strings.TrimSpace(service) == "" {
		return "", fmt.Errorf("service is required")
	}
	if project == "" || s.compose == nil {
		return service, nil
	}
	statuses, err := s.compose.Status(ctx, project)
	if err != nil {
		return "", fmt.Errorf("resolve compose service: %w", err)
	}
	for _, st := range statuses {
		if st.Service == service {
			if st.Name == "" {
				return service, nil
			}
			return st.Name, nil
		}
	}
	return "", fmt.Errorf("service %q was not found in compose project %q", service, project)
}
func key(project, service string) string { return project + "\x00" + service }
