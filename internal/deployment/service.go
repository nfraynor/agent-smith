// Package deployment orchestrates verified, serialised Compose deployments.
package deployment

import (
	"context"
	"fmt"
	"sync"
	"time"

	remotecompose "github.com/nfraynor/agent-smith/internal/compose"
	"github.com/nfraynor/agent-smith/internal/diagnostics"
	remotedocker "github.com/nfraynor/agent-smith/internal/docker"
)

type Compose interface {
	Validate(context.Context, string) (remotecompose.OperationResult, error)
	Pull(context.Context, string, string) (remotecompose.OperationResult, error)
	Up(context.Context, string, string, bool) (remotecompose.OperationResult, error)
	Status(context.Context, string) ([]remotecompose.ServiceStatus, error)
	Logs(context.Context, string, string, int, string) (remotecompose.LogsResult, error)
}
type Docker interface {
	Inspect(context.Context, string) (remotedocker.InspectResult, error)
	Pull(context.Context, string) (remotedocker.PullResult, error)
}
type Health interface {
	ServiceHealth(context.Context, string, string) (diagnostics.HealthResult, error)
}

type Change struct {
	Timestamp   time.Time         `json:"timestamp"`
	Operation   string            `json:"operation"`
	Target      string            `json:"target"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
type Recorder interface {
	Record(context.Context, Change) (string, error)
}

type Options struct {
	VerificationTimeout time.Duration
	PollInterval        time.Duration
	LogLines            int
}
type Service struct {
	compose  Compose
	docker   Docker
	health   Health
	recorder Recorder
	opts     Options
	locks    sync.Map
}

func New(compose Compose, docker Docker, health Health, recorder Recorder, opts Options) *Service {
	if opts.VerificationTimeout <= 0 {
		opts.VerificationTimeout = 60 * time.Second
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}
	if opts.LogLines <= 0 {
		opts.LogLines = 100
	}
	if opts.LogLines > 1000 {
		opts.LogLines = 1000
	}
	return &Service{compose: compose, docker: docker, health: health, recorder: recorder, opts: opts}
}

type Request struct {
	Project  string `json:"project"`
	Service  string `json:"service"`
	Image    string `json:"image,omitempty"`
	Strategy string `json:"strategy,omitempty"`
}
type Result struct {
	Success       bool   `json:"success"`
	Project       string `json:"project"`
	Service       string `json:"service"`
	PreviousImage string `json:"previousImage,omitempty"`
	CurrentImage  string `json:"currentImage,omitempty"`
	Container     string `json:"container,omitempty"`
	Health        string `json:"health,omitempty"`
	Logs          string `json:"logs,omitempty"`
	LogsTruncated bool   `json:"logsTruncated,omitempty"`
	DurationMs    int64  `json:"durationMs"`
	ChangeID      string `json:"changeId,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (s *Service) Deploy(ctx context.Context, req Request) (result Result, err error) {
	started := time.Now()
	result.Project = req.Project
	result.Service = req.Service
	if req.Project == "" || req.Service == "" {
		return result, fmt.Errorf("project and service are required")
	}
	if req.Strategy != "" && req.Strategy != "recreate" {
		return result, fmt.Errorf("unsupported deployment strategy %q", req.Strategy)
	}
	lock := s.targetLock(req.Project + "\x00" + req.Service)
	lock.Lock()
	defer lock.Unlock()
	defer func() { result.DurationMs = time.Since(started).Milliseconds() }()
	status, statusErr := s.serviceStatus(ctx, req.Project, req.Service)
	if statusErr != nil {
		return s.failed(ctx, req, result, statusErr)
	}
	result.Container = status.Name
	if result.Container == "" {
		result.Container = req.Service
	}
	result.PreviousImage = status.Image
	if req.Image != "" && req.Image != status.Image {
		return s.failed(ctx, req, result, fmt.Errorf("explicit image %q does not match the configured Compose image %q", req.Image, status.Image))
	}
	if _, err = s.compose.Validate(ctx, req.Project); err != nil {
		return s.failed(ctx, req, result, fmt.Errorf("validate compose configuration: %w", err))
	}
	if req.Image != "" {
		pulled, pullErr := s.docker.Pull(ctx, req.Image)
		if pullErr != nil {
			return s.failed(ctx, req, result, fmt.Errorf("pull target image: %w", pullErr))
		}
		result.CurrentImage = pulled.CurrentDigest
		if result.CurrentImage == "" {
			result.CurrentImage = pulled.CurrentID
		}
	} else {
		if _, err = s.compose.Pull(ctx, req.Project, req.Service); err != nil {
			return s.failed(ctx, req, result, fmt.Errorf("pull compose service image: %w", err))
		}
	}
	if _, err = s.compose.Up(ctx, req.Project, req.Service, true); err != nil {
		return s.failed(ctx, req, result, fmt.Errorf("recreate compose service: %w", err))
	}
	verifyCtx, cancel := context.WithTimeout(ctx, s.opts.VerificationTimeout)
	defer cancel()
	var health diagnostics.HealthResult
	for {
		health, err = s.health.ServiceHealth(verifyCtx, req.Project, req.Service)
		if err == nil && (health.Status == "healthy" || health.Status == "running") {
			break
		}
		select {
		case <-verifyCtx.Done():
			if err == nil {
				err = fmt.Errorf("service health remained %s", health.Status)
			}
			return s.failed(ctx, req, result, fmt.Errorf("verify deployment: %w", err))
		case <-time.After(s.opts.PollInterval):
		}
	}
	result.Health = health.Status
	result.Container = health.Container
	status, statusErr = s.serviceStatus(ctx, req.Project, req.Service)
	if statusErr != nil {
		return s.failed(ctx, req, result, fmt.Errorf("verify deployed container: %w", statusErr))
	}
	if status.State != "running" {
		return s.failed(ctx, req, result, fmt.Errorf("deployed container state is %q", status.State))
	}
	if result.CurrentImage == "" {
		inspected, inspectErr := s.docker.Inspect(ctx, status.Name)
		if inspectErr != nil {
			return s.failed(ctx, req, result, fmt.Errorf("inspect deployed image: %w", inspectErr))
		}
		result.CurrentImage = inspected.ImageID
		if result.CurrentImage == "" {
			result.CurrentImage = inspected.Image
		}
	}
	result.Success = true
	if s.recorder != nil {
		result.ChangeID, err = s.recorder.Record(ctx, changeFor(req, result, "applied", ""))
		if err != nil {
			result.Success = false
			result.Error = "record deployment: " + err.Error()
			return result, fmt.Errorf("record deployment: %w", err)
		}
	}
	return result, nil
}

func (s *Service) failed(ctx context.Context, req Request, result Result, cause error) (Result, error) {
	result.Success = false
	result.Error = cause.Error()
	if logs, logErr := s.compose.Logs(ctx, req.Project, req.Service, s.opts.LogLines, ""); logErr == nil {
		result.Logs = logs.Content
		result.LogsTruncated = logs.Truncated
	}
	if s.recorder != nil {
		result.ChangeID, _ = s.recorder.Record(ctx, changeFor(req, result, "failed", cause.Error()))
	}
	return result, cause
}
func (s *Service) serviceStatus(ctx context.Context, project, service string) (remotecompose.ServiceStatus, error) {
	statuses, err := s.compose.Status(ctx, project)
	if err != nil {
		return remotecompose.ServiceStatus{}, err
	}
	for _, st := range statuses {
		if st.Service == service {
			return st, nil
		}
	}
	return remotecompose.ServiceStatus{}, fmt.Errorf("service %q not found in project %q", service, project)
}
func (s *Service) targetLock(key string) *sync.Mutex {
	v, _ := s.locks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}
func changeFor(req Request, r Result, status, detail string) Change {
	return Change{Timestamp: time.Now().UTC(), Operation: "deploy_service", Target: req.Project + ":" + req.Service, Description: "Deploy Compose service", Status: status, Metadata: map[string]string{"previousImage": r.PreviousImage, "currentImage": r.CurrentImage, "container": r.Container, "health": r.Health, "error": detail}}
}
