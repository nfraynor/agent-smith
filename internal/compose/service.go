// Package compose executes Docker Compose only for explicitly configured projects.
package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultMaxOutputBytes = 1 << 20

var (
	ErrUnknownProject = errors.New("unknown compose project")
	ErrInvalidName    = errors.New("invalid compose project or service name")
	namePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

type Project struct {
	Name string `json:"name"`
	Path string `json:"path"`
	File string `json:"file"`
}

type CommandResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

type Runner interface {
	Run(context.Context, string, []string, int64) (CommandResult, error)
}

type ExecRunner struct{ Binary string }

func (r ExecRunner) Run(ctx context.Context, dir string, args []string, maxBytes int64) (CommandResult, error) {
	binary := r.Binary
	if binary == "" {
		binary = "docker"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	stdout, stderr := &boundedBuffer{limit: maxBytes}, &boundedBuffer{limit: maxBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String(), Truncated: stdout.truncated || stderr.truncated}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
		return result, fmt.Errorf("compose command failed: %w", err)
	}
	return result, nil
}

type Service struct {
	projects       map[string]Project
	ordered        []Project
	runner         Runner
	maxOutputBytes int64
}

func New(projects []Project, runner Runner, maxOutputBytes int64) (*Service, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	if maxOutputBytes <= 0 {
		maxOutputBytes = defaultMaxOutputBytes
	}
	s := &Service{projects: make(map[string]Project, len(projects)), runner: runner, maxOutputBytes: maxOutputBytes}
	for _, p := range projects {
		if !namePattern.MatchString(p.Name) {
			return nil, fmt.Errorf("%w: project %q", ErrInvalidName, p.Name)
		}
		if !filepath.IsAbs(p.Path) {
			return nil, fmt.Errorf("project %q path must be absolute", p.Name)
		}
		p.Path = filepath.Clean(p.Path)
		if p.File == "" {
			p.File = "compose.yaml"
		}
		if filepath.IsAbs(p.File) || filepath.Clean(p.File) != p.File || strings.HasPrefix(p.File, ".."+string(filepath.Separator)) || p.File == ".." {
			return nil, fmt.Errorf("project %q has unsafe compose file", p.Name)
		}
		if _, exists := s.projects[p.Name]; exists {
			return nil, fmt.Errorf("duplicate compose project %q", p.Name)
		}
		s.projects[p.Name] = p
		s.ordered = append(s.ordered, p)
	}
	return s, nil
}

func (s *Service) Projects(context.Context) ([]Project, error) {
	return append([]Project(nil), s.ordered...), nil
}

type ServiceStatus struct {
	Name       string `json:"name"`
	Service    string `json:"service"`
	State      string `json:"state"`
	Health     string `json:"health,omitempty"`
	Image      string `json:"image,omitempty"`
	ExitCode   int    `json:"exitCode,omitempty"`
	Publishers any    `json:"publishers,omitempty"`
}

type OperationResult struct {
	Project   string `json:"project"`
	Service   string `json:"service,omitempty"`
	Success   bool   `json:"success"`
	Output    string `json:"output,omitempty"`
	Truncated bool   `json:"truncated"`
}

type LogsResult struct {
	Project   string `json:"project"`
	Service   string `json:"service,omitempty"`
	Lines     int    `json:"lines"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
}

func (s *Service) Status(ctx context.Context, project string) ([]ServiceStatus, error) {
	p, err := s.project(project)
	if err != nil {
		return nil, err
	}
	r, err := s.run(ctx, p, "ps", "--format", "json", "--all")
	if err != nil {
		return nil, operationError("status", p.Name, r, err)
	}
	return parseStatus(r.Stdout)
}

func (s *Service) Logs(ctx context.Context, project, service string, lines int, since string) (LogsResult, error) {
	p, err := s.projectService(project, service, true)
	if err != nil {
		return LogsResult{}, err
	}
	if lines <= 0 {
		lines = 200
	}
	if lines > 10000 {
		lines = 10000
	}
	if strings.ContainsAny(since, "\x00\r\n") {
		return LogsResult{}, fmt.Errorf("%w: since", ErrInvalidName)
	}
	args := []string{"logs", "--no-color", "--tail", fmt.Sprint(lines)}
	if since != "" {
		args = append(args, "--since", since)
	}
	if service != "" {
		args = append(args, service)
	}
	r, err := s.run(ctx, p, args...)
	if err != nil {
		return LogsResult{}, operationError("logs", p.Name, r, err)
	}
	return LogsResult{Project: p.Name, Service: service, Lines: lines, Content: r.Stdout + r.Stderr, Truncated: r.Truncated}, nil
}

func (s *Service) Validate(ctx context.Context, project string) (OperationResult, error) {
	return s.operation(ctx, project, "", "validate", "config", "--quiet")
}
func (s *Service) Pull(ctx context.Context, project, service string) (OperationResult, error) {
	args := []string{"pull"}
	if service != "" {
		args = append(args, service)
	}
	return s.operation(ctx, project, service, "pull", args...)
}
func (s *Service) Up(ctx context.Context, project, service string, recreate bool) (OperationResult, error) {
	args := []string{"up", "--detach"}
	if recreate {
		args = append(args, "--force-recreate")
	}
	if service != "" {
		args = append(args, service)
	}
	return s.operation(ctx, project, service, "up", args...)
}
func (s *Service) Restart(ctx context.Context, project, service string) (OperationResult, error) {
	args := []string{"restart"}
	if service != "" {
		args = append(args, service)
	}
	return s.operation(ctx, project, service, "restart", args...)
}
func (s *Service) Stop(ctx context.Context, project, service string) (OperationResult, error) {
	args := []string{"stop"}
	if service != "" {
		args = append(args, service)
	}
	return s.operation(ctx, project, service, "stop", args...)
}

func (s *Service) operation(ctx context.Context, project, service, verb string, args ...string) (OperationResult, error) {
	p, err := s.projectService(project, service, true)
	if err != nil {
		return OperationResult{}, err
	}
	r, err := s.run(ctx, p, args...)
	result := OperationResult{Project: p.Name, Service: service, Success: err == nil, Output: strings.TrimSpace(r.Stdout), Truncated: r.Truncated}
	if err != nil {
		return result, operationError(verb, p.Name, r, err)
	}
	return result, nil
}

func (s *Service) run(ctx context.Context, p Project, args ...string) (CommandResult, error) {
	fixed := []string{"compose", "--project-name", p.Name, "--file", filepath.Join(p.Path, p.File)}
	return s.runner.Run(ctx, p.Path, append(fixed, args...), s.maxOutputBytes)
}
func (s *Service) project(name string) (Project, error) {
	if !namePattern.MatchString(name) {
		return Project{}, fmt.Errorf("%w: project %q", ErrInvalidName, name)
	}
	p, ok := s.projects[name]
	if !ok {
		return Project{}, fmt.Errorf("%w: %q", ErrUnknownProject, name)
	}
	return p, nil
}
func (s *Service) projectService(project, service string, optional bool) (Project, error) {
	p, err := s.project(project)
	if err != nil {
		return Project{}, err
	}
	if service == "" && optional {
		return p, nil
	}
	if !namePattern.MatchString(service) {
		return Project{}, fmt.Errorf("%w: service %q", ErrInvalidName, service)
	}
	return p, nil
}
func operationError(op, project string, r CommandResult, err error) error {
	detail := strings.TrimSpace(r.Stderr)
	if len(detail) > 2048 {
		detail = detail[:2048] + "..."
	}
	if detail == "" {
		return fmt.Errorf("compose %s for %q: %w", op, project, err)
	}
	return fmt.Errorf("compose %s for %q: %w: %s", op, project, err, detail)
}

func parseStatus(raw string) ([]ServiceStatus, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []ServiceStatus{}, nil
	}
	var out []ServiceStatus
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, fmt.Errorf("decode compose status: %w", err)
		}
		return out, nil
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item ServiceStatus
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, fmt.Errorf("decode compose status: %w", err)
		}
		out = append(out, item)
	}
	return out, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit     int64
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		b.truncated = b.truncated || n > 0
		return n, nil
	}
	if int64(n) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
