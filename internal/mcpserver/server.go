// Package mcpserver exposes RemoteOps domain services through authenticated MCP tools.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/nfraynor/agent-smith/internal/audit"
	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/changes"
	"github.com/nfraynor/agent-smith/internal/compose"
	"github.com/nfraynor/agent-smith/internal/deployment"
	"github.com/nfraynor/agent-smith/internal/diagnostics"
	remotedocker "github.com/nfraynor/agent-smith/internal/docker"
	"github.com/nfraynor/agent-smith/internal/envconfig"
	"github.com/nfraynor/agent-smith/internal/filesystem"
	"github.com/nfraynor/agent-smith/internal/godmode"
	"github.com/nfraynor/agent-smith/internal/limits"
	"github.com/nfraynor/agent-smith/internal/locks"
	"github.com/nfraynor/agent-smith/internal/permissions"
	"github.com/nfraynor/agent-smith/internal/yamlconfig"
)

type Options struct {
	Name        string
	Version     string
	Commit      string
	GodMode     bool
	RootNames   []string
	Docker      *remotedocker.Service
	Compose     *compose.Service
	Files       *filesystem.Service
	YAML        *yamlconfig.Service
	Env         *envconfig.Service
	Changes     *changes.Store
	Diagnostics *diagnostics.Service
	Deployment  *deployment.Service
	GodShell    *godmode.Runner
	Audit       audit.Recorder
	Limiter     *limits.Limiter
	Locks       *locks.Manager
}

type Server struct {
	opts       Options
	mcp        *mcp.Server
	started    time.Time
	authorizer permissions.Authorizer
	tools      []string
}

func New(options Options) (*Server, error) {
	if options.Name == "" {
		options.Name = "remoteops"
	}
	if options.Version == "" {
		options.Version = "dev"
	}
	if options.Limiter == nil {
		options.Limiter = limits.NewLimiter(120, 20)
	}
	if options.Locks == nil {
		options.Locks = locks.New()
	}
	s := &Server{opts: options, started: time.Now()}
	s.mcp = mcp.NewServer(&mcp.Implementation{Name: options.Name, Version: options.Version}, nil)
	s.register()
	sort.Strings(s.tools)
	return s, nil
}

func (s *Server) MCP() *mcp.Server { return s.mcp }

type toolSpec[In any] struct {
	name        string
	description string
	permission  permissions.Permission
	class       permissions.ActionClass
	mutation    bool
	target      func(In) string
	run         func(context.Context, auth.Identity, In) (any, error)
}

func addTool[In any](s *Server, spec toolSpec[In]) {
	s.tools = append(s.tools, spec.name)
	mcp.AddTool(s.mcp, &mcp.Tool{Name: spec.name, Description: spec.description},
		func(ctx context.Context, _ *mcp.CallToolRequest, input In) (*mcp.CallToolResult, any, error) {
			started := time.Now()
			identity, ok := auth.IdentityFromContext(ctx)
			if !ok {
				return toolError("UNAUTHENTICATED", "an authenticated identity is required")
			}
			target := ""
			if spec.target != nil {
				target = spec.target(input)
			}
			event := audit.Event{Actor: identity.Actor, Action: spec.name, Class: spec.class, Target: target, GodMode: spec.class == permissions.GodMode}
			if spec.permission != "" {
				if err := s.authorizer.Check(identity.Role, spec.permission); err != nil {
					event.Error = err.Error()
					s.record(ctx, event, started)
					return toolError("PERMISSION_DENIED", "the authenticated role cannot perform this action")
				}
			}
			event.Allowed = true
			if !s.opts.Limiter.Allow(identity.Actor, spec.mutation) {
				event.Error = limits.ErrRateLimited.Error()
				s.record(ctx, event, started)
				return toolError("RATE_LIMITED", "the request rate limit was exceeded")
			}
			var unlock func()
			if spec.mutation && target != "" {
				var err error
				unlock, err = s.opts.Locks.Lock(ctx, spec.name+":"+target)
				if err != nil {
					event.Error = err.Error()
					s.record(ctx, event, started)
					return toolError("CANCELLED", "the target lock could not be acquired")
				}
				defer unlock()
			}
			output, err := spec.run(ctx, identity, input)
			if err != nil {
				event.Error = err.Error()
				s.record(ctx, event, started)
				return toolError(codeFor(err), safeMessage(err))
			}
			event.Success = true
			if mutation, ok := output.(mutationResult); ok {
				event.ChangeID = mutation.ChangeID
			}
			s.record(ctx, event, started)
			return nil, output, nil
		})
}

func (s *Server) record(ctx context.Context, event audit.Event, started time.Time) {
	event.DurationMS = time.Since(started).Milliseconds()
	if s.opts.Audit != nil {
		_ = s.opts.Audit.Record(ctx, event)
	}
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func toolError(code, message string) (*mcp.CallToolResult, any, error) {
	var output apiError
	output.Error.Code, output.Error.Message = code, message
	return &mcp.CallToolResult{IsError: true}, output, nil
}

func codeFor(err error) string {
	switch {
	case errors.Is(err, permissions.ErrDenied):
		return "PERMISSION_DENIED"
	case errors.Is(err, filesystem.ErrInvalidPath), errors.Is(err, filesystem.ErrSymlinkEscape):
		return "PATH_OUTSIDE_ALLOWED_ROOT"
	case errors.Is(err, filesystem.ErrLimitExceeded), errors.Is(err, changes.ErrTooLarge):
		return "LIMIT_EXCEEDED"
	case errors.Is(err, os.ErrNotExist), errors.Is(err, changes.ErrNotFound):
		return "NOT_FOUND"
	case errors.Is(err, changes.ErrConflict):
		return "ROLLBACK_CONFLICT"
	case errors.Is(err, changes.ErrRollbackUnsupported):
		return "ROLLBACK_UNSUPPORTED"
	case strings.Contains(err.Error(), "GODMODE_DISABLED"):
		return "GODMODE_DISABLED"
	case strings.Contains(err.Error(), "invalid"), strings.Contains(err.Error(), "required"):
		return "INVALID_ARGUMENT"
	default:
		return "OPERATION_FAILED"
	}
}

func safeMessage(err error) string {
	message := err.Error()
	if len(message) > 2048 {
		message = message[:2048] + "..."
	}
	return message
}

type mutationResult struct {
	Success      bool   `json:"success"`
	Changed      bool   `json:"changed"`
	ChangeID     string `json:"changeId,omitempty"`
	Verification any    `json:"verification,omitempty"`
}

func (s *Server) register() {
	s.registerInfo()
	s.registerDocker()
	s.registerCompose()
	s.registerFiles()
	s.registerConfig()
	s.registerDiagnostics()
	s.registerChanges()
	if s.opts.GodMode && s.opts.GodShell != nil {
		s.registerGodMode()
	}
}

func (s *Server) registerInfo() {
	type empty struct{}
	addTool(s, toolSpec[empty]{name: "remoteops_info", description: "Report RemoteOps version, capabilities and configured resource names.", permission: permissions.DockerRead, class: permissions.ReadOnly,
		run: func(ctx context.Context, _ auth.Identity, _ empty) (any, error) {
			dockerConnected := false
			if s.opts.Docker != nil {
				_, dockerErr := s.opts.Docker.List(ctx, true)
				dockerConnected = dockerErr == nil
			}
			projects := []compose.Project{}
			if s.opts.Compose != nil {
				projects, _ = s.opts.Compose.Projects(ctx)
			}
			return map[string]any{"version": s.opts.Version, "commit": s.opts.Commit, "serverName": s.opts.Name, "uptimeSeconds": int64(time.Since(s.started).Seconds()), "capabilities": s.tools, "dockerConnected": dockerConnected, "composeProjects": projects, "filesystemRoots": s.opts.RootNames, "godMode": s.opts.GodMode}, nil
		}})
	if s.opts.Diagnostics != nil {
		addTool(s, toolSpec[empty]{name: "system_summary", description: "Summarize Docker and managed filesystem health.", permission: permissions.DockerRead, class: permissions.ReadOnly,
			run: func(ctx context.Context, _ auth.Identity, _ empty) (any, error) {
				return s.opts.Diagnostics.SystemSummary(ctx)
			}})
	}
}

func (s *Server) registerDocker() {
	if s.opts.Docker == nil {
		return
	}
	type listInput struct {
		All bool `json:"all,omitempty"`
	}
	type containerInput struct {
		Container string `json:"container"`
	}
	type logsInput struct {
		Container  string `json:"container"`
		Lines      int    `json:"lines,omitempty"`
		Since      string `json:"since,omitempty"`
		Timestamps bool   `json:"timestamps,omitempty"`
	}
	type timeoutInput struct {
		Container      string `json:"container"`
		TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
	}
	type imageInput struct {
		Image string `json:"image"`
	}
	addTool(s, toolSpec[listInput]{name: "docker_list", description: "List Docker containers with structured state and health.", permission: permissions.DockerRead, class: permissions.ReadOnly, run: func(ctx context.Context, _ auth.Identity, in listInput) (any, error) {
		return s.opts.Docker.List(ctx, in.All)
	}})
	addTool(s, toolSpec[containerInput]{name: "docker_inspect", description: "Inspect curated Docker container details.", permission: permissions.DockerRead, class: permissions.ReadOnly, target: func(in containerInput) string { return in.Container }, run: func(ctx context.Context, _ auth.Identity, in containerInput) (any, error) {
		return s.opts.Docker.Inspect(ctx, in.Container)
	}})
	addTool(s, toolSpec[logsInput]{name: "docker_logs", description: "Read safely bounded Docker logs.", permission: permissions.DockerRead, class: permissions.ReadOnly, target: func(in logsInput) string { return in.Container }, run: func(ctx context.Context, _ auth.Identity, in logsInput) (any, error) {
		return s.opts.Docker.Logs(ctx, in.Container, in.Lines, in.Since, in.Timestamps)
	}})
	addTool(s, toolSpec[containerInput]{name: "docker_stats", description: "Read a one-shot container resource sample.", permission: permissions.DockerRead, class: permissions.ReadOnly, target: func(in containerInput) string { return in.Container }, run: func(ctx context.Context, _ auth.Identity, in containerInput) (any, error) {
		return s.opts.Docker.Stats(ctx, in.Container)
	}})
	addTool(s, toolSpec[timeoutInput]{name: "docker_restart", description: "Restart a container and return verified before/after state.", permission: permissions.DockerRestart, class: permissions.SafeWrite, mutation: true, target: func(in timeoutInput) string { return in.Container }, run: func(ctx context.Context, _ auth.Identity, in timeoutInput) (any, error) {
		return s.opts.Docker.Restart(ctx, in.Container, time.Duration(in.TimeoutSeconds)*time.Second)
	}})
	addTool(s, toolSpec[containerInput]{name: "docker_start", description: "Start a container and verify its state.", permission: permissions.DockerRestart, class: permissions.SafeWrite, mutation: true, target: func(in containerInput) string { return in.Container }, run: func(ctx context.Context, _ auth.Identity, in containerInput) (any, error) {
		return s.opts.Docker.Start(ctx, in.Container)
	}})
	addTool(s, toolSpec[timeoutInput]{name: "docker_stop", description: "Stop a container and verify its state.", permission: permissions.DockerRestart, class: permissions.Destructive, mutation: true, target: func(in timeoutInput) string { return in.Container }, run: func(ctx context.Context, _ auth.Identity, in timeoutInput) (any, error) {
		return s.opts.Docker.Stop(ctx, in.Container, time.Duration(in.TimeoutSeconds)*time.Second)
	}})
	addTool(s, toolSpec[imageInput]{name: "docker_pull", description: "Pull an image and report previous/current identifiers.", permission: permissions.DockerDeploy, class: permissions.Deployment, mutation: true, target: func(in imageInput) string { return in.Image }, run: func(ctx context.Context, _ auth.Identity, in imageInput) (any, error) {
		return s.opts.Docker.Pull(ctx, in.Image)
	}})
	addTool(s, toolSpec[imageInput]{name: "docker_image_info", description: "Inspect image tags, digests, creation time and size.", permission: permissions.DockerRead, class: permissions.ReadOnly, target: func(in imageInput) string { return in.Image }, run: func(ctx context.Context, _ auth.Identity, in imageInput) (any, error) {
		return s.opts.Docker.ImageInfo(ctx, in.Image)
	}})
}

func (s *Server) registerCompose() {
	if s.opts.Compose == nil {
		return
	}
	type empty struct{}
	type projectInput struct {
		Project string `json:"project"`
	}
	type serviceInput struct {
		Project string `json:"project"`
		Service string `json:"service,omitempty"`
	}
	type logsInput struct {
		Project string `json:"project"`
		Service string `json:"service,omitempty"`
		Lines   int    `json:"lines,omitempty"`
		Since   string `json:"since,omitempty"`
	}
	type upInput struct {
		Project  string `json:"project"`
		Service  string `json:"service,omitempty"`
		Recreate bool   `json:"recreate,omitempty"`
	}
	target := func(in serviceInput) string { return in.Project + ":" + in.Service }
	addTool(s, toolSpec[empty]{name: "compose_projects", description: "List explicitly configured Compose projects.", permission: permissions.ComposeRead, class: permissions.ReadOnly, run: func(ctx context.Context, _ auth.Identity, _ empty) (any, error) { return s.opts.Compose.Projects(ctx) }})
	addTool(s, toolSpec[projectInput]{name: "compose_status", description: "Return structured status for a configured Compose project.", permission: permissions.ComposeRead, class: permissions.ReadOnly, target: func(in projectInput) string { return in.Project }, run: func(ctx context.Context, _ auth.Identity, in projectInput) (any, error) {
		return s.opts.Compose.Status(ctx, in.Project)
	}})
	addTool(s, toolSpec[logsInput]{name: "compose_logs", description: "Read bounded logs from a configured Compose service.", permission: permissions.ComposeRead, class: permissions.ReadOnly, target: func(in logsInput) string { return in.Project + ":" + in.Service }, run: func(ctx context.Context, _ auth.Identity, in logsInput) (any, error) {
		return s.opts.Compose.Logs(ctx, in.Project, in.Service, in.Lines, in.Since)
	}})
	addTool(s, toolSpec[projectInput]{name: "compose_validate", description: "Validate a configured Compose project.", permission: permissions.ComposeRead, class: permissions.ReadOnly, target: func(in projectInput) string { return in.Project }, run: func(ctx context.Context, _ auth.Identity, in projectInput) (any, error) {
		return s.opts.Compose.Validate(ctx, in.Project)
	}})
	addTool(s, toolSpec[serviceInput]{name: "compose_pull", description: "Pull images for a configured Compose project or service.", permission: permissions.ComposeDeploy, class: permissions.Deployment, mutation: true, target: target, run: func(ctx context.Context, _ auth.Identity, in serviceInput) (any, error) {
		return s.opts.Compose.Pull(ctx, in.Project, in.Service)
	}})
	addTool(s, toolSpec[upInput]{name: "compose_up", description: "Create or update a configured Compose service.", permission: permissions.ComposeDeploy, class: permissions.Deployment, mutation: true, target: func(in upInput) string { return in.Project + ":" + in.Service }, run: func(ctx context.Context, _ auth.Identity, in upInput) (any, error) {
		return s.opts.Compose.Up(ctx, in.Project, in.Service, in.Recreate)
	}})
	addTool(s, toolSpec[serviceInput]{name: "compose_restart", description: "Restart a configured Compose project or service.", permission: permissions.ComposeDeploy, class: permissions.SafeWrite, mutation: true, target: target, run: func(ctx context.Context, _ auth.Identity, in serviceInput) (any, error) {
		return s.opts.Compose.Restart(ctx, in.Project, in.Service)
	}})
	addTool(s, toolSpec[serviceInput]{name: "compose_stop", description: "Stop a configured Compose project or service.", permission: permissions.ComposeDeploy, class: permissions.Destructive, mutation: true, target: target, run: func(ctx context.Context, _ auth.Identity, in serviceInput) (any, error) {
		return s.opts.Compose.Stop(ctx, in.Project, in.Service)
	}})
}

func (s *Server) registerFiles() {
	if s.opts.Files == nil {
		return
	}
	type pathInput struct {
		Root string `json:"root"`
		Path string `json:"path,omitempty"`
	}
	type listInput struct {
		Root  string `json:"root"`
		Path  string `json:"path,omitempty"`
		Limit int    `json:"limit,omitempty"`
	}
	type readInput struct {
		Root     string `json:"root"`
		Path     string `json:"path"`
		Offset   int64  `json:"offset,omitempty"`
		MaxBytes int64  `json:"maxBytes,omitempty"`
	}
	type diffInput struct {
		Root            string `json:"root"`
		Path            string `json:"path"`
		ProposedContent string `json:"proposedContent"`
	}
	type writeInput struct {
		Root    string `json:"root"`
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	type patchInput struct {
		Root                string `json:"root"`
		Path                string `json:"path"`
		Find                string `json:"find"`
		Replace             string `json:"replace"`
		ExpectedOccurrences int    `json:"expectedOccurrences,omitempty"`
	}
	addTool(s, toolSpec[listInput]{name: "file_list", description: "List a directory beneath a named managed root.", permission: permissions.FilesystemRead, class: permissions.ReadOnly, target: func(in listInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, _ auth.Identity, in listInput) (any, error) {
		return s.opts.Files.List(in.Root, in.Path, in.Limit)
	}})
	addTool(s, toolSpec[readInput]{name: "file_read", description: "Read a bounded byte range beneath a named managed root.", permission: permissions.FilesystemRead, class: permissions.ReadOnly, target: func(in readInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, id auth.Identity, in readInput) (any, error) {
		if sensitiveFile(in.Path) {
			if err := s.authorizer.Check(id.Role, permissions.SecretsRead); err != nil {
				return nil, err
			}
		}
		return s.opts.Files.Read(in.Root, in.Path, in.Offset, in.MaxBytes)
	}})
	addTool(s, toolSpec[pathInput]{name: "file_exists", description: "Check whether a managed path exists.", permission: permissions.FilesystemRead, class: permissions.ReadOnly, target: func(in pathInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, _ auth.Identity, in pathInput) (any, error) {
		exists, err := s.opts.Files.Exists(in.Root, in.Path)
		return map[string]any{"exists": exists}, err
	}})
	addTool(s, toolSpec[pathInput]{name: "file_stat", description: "Return metadata for a managed path.", permission: permissions.FilesystemRead, class: permissions.ReadOnly, target: func(in pathInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, _ auth.Identity, in pathInput) (any, error) {
		return s.opts.Files.Stat(in.Root, in.Path)
	}})
	addTool(s, toolSpec[diffInput]{name: "file_diff", description: "Preview a full-content replacement without writing.", permission: permissions.FilesystemRead, class: permissions.ReadOnly, target: func(in diffInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, id auth.Identity, in diffInput) (any, error) {
		if sensitiveFile(in.Path) {
			if err := s.authorizer.Check(id.Role, permissions.SecretsRead); err != nil {
				return nil, err
			}
		}
		diff, err := s.opts.Files.Diff(in.Root, in.Path, []byte(in.ProposedContent))
		return map[string]any{"diff": diff}, err
	}})
	addTool(s, toolSpec[writeInput]{name: "file_write", description: "Atomically replace a managed file with backup and change record.", permission: permissions.FilesystemWrite, class: permissions.SafeWrite, mutation: true, target: func(in writeInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, id auth.Identity, in writeInput) (any, error) {
		return s.writeFile(id, in.Root, in.Path, []byte(in.Content), "file_write", "Replace managed file")
	}})
	addTool(s, toolSpec[patchInput]{name: "file_patch", description: "Atomically replace an exact text occurrence in a managed file.", permission: permissions.FilesystemWrite, class: permissions.SafeWrite, mutation: true, target: func(in patchInput) string { return in.Root + ":" + in.Path }, run: func(_ context.Context, id auth.Identity, in patchInput) (any, error) {
		before, err := s.opts.Files.Read(in.Root, in.Path, 0, 0)
		if err != nil {
			return nil, err
		}
		expected := in.ExpectedOccurrences
		if expected <= 0 {
			expected = 1
		}
		if in.Find == "" || strings.Count(string(before.Data), in.Find) != expected {
			return nil, fmt.Errorf("invalid patch: expected %d exact occurrences", expected)
		}
		after := []byte(strings.Replace(string(before.Data), in.Find, in.Replace, expected))
		return s.writeFileWithBefore(id, in.Root, in.Path, before.Data, after, "file_patch", "Apply controlled text patch")
	}})
}

func (s *Server) writeFile(identity auth.Identity, root, path string, after []byte, operation, description string) (any, error) {
	before, err := s.opts.Files.Read(root, path, 0, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s.writeFileWithBefore(identity, root, path, before.Data, after, operation, description)
}

func (s *Server) writeFileWithBefore(identity auth.Identity, root, path string, before, after []byte, operation, description string) (any, error) {
	target, err := s.opts.Files.Resolve(root, path, true)
	if err != nil {
		return nil, err
	}
	if string(before) == string(after) {
		return mutationResult{Success: true, Changed: false, Verification: map[string]any{"hash": filesystem.Hash(after)}}, nil
	}
	if err = s.opts.Files.WriteAtomic(root, path, after, 0); err != nil {
		return nil, err
	}
	changeID := ""
	if s.opts.Changes != nil {
		change, recordErr := s.opts.Changes.Record(changes.RecordInput{Actor: identity.Actor, Operation: operation, Target: target, Description: description, Before: before, After: after})
		if recordErr != nil {
			return nil, recordErr
		}
		changeID = change.ID
	}
	verification, err := s.opts.Files.Read(root, path, 0, 0)
	if err != nil {
		return nil, err
	}
	return mutationResult{Success: true, Changed: true, ChangeID: changeID, Verification: map[string]any{"hash": filesystem.Hash(verification.Data)}}, nil
}

func (s *Server) registerConfig() {
	if s.opts.YAML != nil {
		type yamlInput struct {
			Root string `json:"root"`
			File string `json:"file"`
			Path string `json:"path"`
		}
		type yamlSetInput struct {
			Root  string `json:"root"`
			File  string `json:"file"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		}
		addTool(s, toolSpec[yamlInput]{name: "yaml_get", description: "Read a typed value from managed YAML.", permission: permissions.ConfigRead, class: permissions.ReadOnly, target: func(in yamlInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in yamlInput) (any, error) {
			if sensitiveKey(in.Path) && !s.authorizer.Allowed(id.Role, permissions.SecretsRead) {
				return "[REDACTED]", nil
			}
			return s.opts.YAML.Get(in.Root, in.File, in.Path)
		}})
		addTool(s, toolSpec[yamlSetInput]{name: "yaml_preview_change", description: "Preview a node-aware YAML change without writing.", permission: permissions.ConfigRead, class: permissions.ReadOnly, target: func(in yamlSetInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, _ auth.Identity, in yamlSetInput) (any, error) {
			return s.opts.YAML.PreviewSet(in.Root, in.File, in.Path, in.Value)
		}})
		addTool(s, toolSpec[yamlSetInput]{name: "yaml_set", description: "Set a managed YAML node atomically and record the change.", permission: permissions.ConfigWrite, class: permissions.SafeWrite, mutation: true, target: func(in yamlSetInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in yamlSetInput) (any, error) {
			before, err := s.opts.Files.Read(in.Root, in.File, 0, 0)
			if err != nil {
				return nil, err
			}
			preview, err := s.opts.YAML.Set(in.Root, in.File, in.Path, in.Value)
			if err != nil {
				return nil, err
			}
			return s.recordExistingFile(id, in.Root, in.File, before.Data, preview.Content, "yaml_set", "Set YAML node")
		}})
		addTool(s, toolSpec[yamlInput]{name: "yaml_delete", description: "Delete a managed YAML node atomically and record the change.", permission: permissions.ConfigWrite, class: permissions.SafeWrite, mutation: true, target: func(in yamlInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in yamlInput) (any, error) {
			before, err := s.opts.Files.Read(in.Root, in.File, 0, 0)
			if err != nil {
				return nil, err
			}
			preview, err := s.opts.YAML.Delete(in.Root, in.File, in.Path)
			if err != nil {
				return nil, err
			}
			return s.recordExistingFile(id, in.Root, in.File, before.Data, preview.Content, "yaml_delete", "Delete YAML node")
		}})
	}
	if s.opts.Env != nil {
		type envInput struct {
			Root          string `json:"root"`
			File          string `json:"file"`
			Key           string `json:"key"`
			RevealSecrets bool   `json:"revealSecrets,omitempty"`
		}
		type envListInput struct {
			Root          string `json:"root"`
			File          string `json:"file"`
			RevealSecrets bool   `json:"revealSecrets,omitempty"`
		}
		type envSetInput struct {
			Root  string `json:"root"`
			File  string `json:"file"`
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		addTool(s, toolSpec[envInput]{name: "env_get", description: "Read a dotenv key with secret redaction by default.", permission: permissions.ConfigRead, class: permissions.ReadOnly, target: func(in envInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in envInput) (any, error) {
			if in.RevealSecrets {
				if err := s.authorizer.Check(id.Role, permissions.SecretsRead); err != nil {
					return nil, err
				}
			}
			return s.opts.Env.Get(in.Root, in.File, in.Key, in.RevealSecrets)
		}})
		addTool(s, toolSpec[envListInput]{name: "env_list", description: "List dotenv keys with secret redaction by default.", permission: permissions.ConfigRead, class: permissions.ReadOnly, target: func(in envListInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in envListInput) (any, error) {
			if in.RevealSecrets {
				if err := s.authorizer.Check(id.Role, permissions.SecretsRead); err != nil {
					return nil, err
				}
			}
			return s.opts.Env.List(in.Root, in.File, in.RevealSecrets)
		}})
		addTool(s, toolSpec[envSetInput]{name: "env_set", description: "Blindly replace a dotenv value and record the change.", permission: permissions.ConfigWrite, class: permissions.SafeWrite, mutation: true, target: func(in envSetInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in envSetInput) (any, error) {
			before, err := s.opts.Files.Read(in.Root, in.File, 0, 0)
			if err != nil {
				return nil, err
			}
			if err = s.opts.Env.Set(in.Root, in.File, in.Key, in.Value); err != nil {
				return nil, err
			}
			after, err := s.opts.Files.Read(in.Root, in.File, 0, 0)
			if err != nil {
				return nil, err
			}
			return s.recordExistingFile(id, in.Root, in.File, before.Data, after.Data, "env_set", "Set dotenv key")
		}})
		addTool(s, toolSpec[envInput]{name: "env_delete", description: "Delete a dotenv key and record the change.", permission: permissions.ConfigWrite, class: permissions.SafeWrite, mutation: true, target: func(in envInput) string { return in.Root + ":" + in.File }, run: func(_ context.Context, id auth.Identity, in envInput) (any, error) {
			before, err := s.opts.Files.Read(in.Root, in.File, 0, 0)
			if err != nil {
				return nil, err
			}
			if err = s.opts.Env.Delete(in.Root, in.File, in.Key); err != nil {
				return nil, err
			}
			after, err := s.opts.Files.Read(in.Root, in.File, 0, 0)
			if err != nil {
				return nil, err
			}
			return s.recordExistingFile(id, in.Root, in.File, before.Data, after.Data, "env_delete", "Delete dotenv key")
		}})
	}
}

func (s *Server) recordExistingFile(identity auth.Identity, root, path string, before, after []byte, operation, description string) (any, error) {
	target, err := s.opts.Files.Resolve(root, path, true)
	if err != nil {
		return nil, err
	}
	changeID := ""
	if s.opts.Changes != nil {
		change, recordErr := s.opts.Changes.Record(changes.RecordInput{Actor: identity.Actor, Operation: operation, Target: target, Description: description, Before: before, After: after})
		if recordErr != nil {
			return nil, recordErr
		}
		changeID = change.ID
	}
	return mutationResult{Success: true, Changed: string(before) != string(after), ChangeID: changeID, Verification: map[string]any{"hash": filesystem.Hash(after)}}, nil
}

func (s *Server) registerDiagnostics() {
	if s.opts.Diagnostics == nil {
		return
	}
	type serviceInput struct {
		Project string `json:"project,omitempty"`
		Service string `json:"service"`
	}
	addTool(s, toolSpec[serviceInput]{name: "service_health", description: "Verify service health using Docker, configured HTTP/TCP, or running state.", permission: permissions.DockerRead, class: permissions.ReadOnly, target: func(in serviceInput) string { return in.Project + ":" + in.Service }, run: func(ctx context.Context, _ auth.Identity, in serviceInput) (any, error) {
		return s.opts.Diagnostics.ServiceHealth(ctx, in.Project, in.Service)
	}})
	addTool(s, toolSpec[serviceInput]{name: "diagnose_service", description: "Gather structured service state, health, stats, logs and Compose facts.", permission: permissions.DockerRead, class: permissions.ReadOnly, target: func(in serviceInput) string { return in.Project + ":" + in.Service }, run: func(ctx context.Context, _ auth.Identity, in serviceInput) (any, error) {
		return s.opts.Diagnostics.DiagnoseService(ctx, in.Project, in.Service)
	}})
	if s.opts.Deployment != nil {
		addTool(s, toolSpec[deployment.Request]{name: "deploy_service", description: "Validate, pull, recreate and verify a configured Compose service.", permission: permissions.DockerDeploy, class: permissions.Deployment, mutation: true, target: func(in deployment.Request) string { return in.Project + ":" + in.Service }, run: func(ctx context.Context, _ auth.Identity, in deployment.Request) (any, error) {
			return s.opts.Deployment.Deploy(ctx, in)
		}})
	}
}

func (s *Server) registerChanges() {
	if s.opts.Changes == nil {
		return
	}
	type listInput struct {
		Since     string `json:"since,omitempty"`
		Operation string `json:"operation,omitempty"`
		Target    string `json:"target,omitempty"`
		Limit     int    `json:"limit,omitempty"`
	}
	type idInput struct {
		ChangeID string `json:"changeId"`
	}
	type rollbackInput struct {
		ChangeID string `json:"changeId"`
		Force    bool   `json:"force,omitempty"`
	}
	addTool(s, toolSpec[listInput]{name: "changes_list", description: "List persistent change records.", permission: permissions.ChangesRead, class: permissions.ReadOnly, run: func(_ context.Context, _ auth.Identity, in listInput) (any, error) {
		var since time.Time
		var err error
		if in.Since != "" {
			since, err = time.Parse(time.RFC3339, in.Since)
			if err != nil {
				return nil, fmt.Errorf("invalid since timestamp")
			}
		}
		return s.opts.Changes.List(changes.ListFilter{Since: since, Operation: in.Operation, Target: in.Target, Limit: in.Limit})
	}})
	addTool(s, toolSpec[idInput]{name: "change_get", description: "Get one persistent change record.", permission: permissions.ChangesRead, class: permissions.ReadOnly, target: func(in idInput) string { return in.ChangeID }, run: func(_ context.Context, _ auth.Identity, in idInput) (any, error) {
		return s.opts.Changes.Get(in.ChangeID)
	}})
	addTool(s, toolSpec[idInput]{name: "change_diff", description: "Read the bounded diff for one change.", permission: permissions.ChangesRead, class: permissions.ReadOnly, target: func(in idInput) string { return in.ChangeID }, run: func(_ context.Context, _ auth.Identity, in idInput) (any, error) {
		diff, err := s.opts.Changes.Diff(in.ChangeID)
		return map[string]any{"changeId": in.ChangeID, "diff": diff}, err
	}})
	addTool(s, toolSpec[rollbackInput]{name: "change_rollback", description: "Conflict-check and restore the previous file state.", permission: permissions.ChangesRollback, class: permissions.SafeWrite, mutation: true, target: func(in rollbackInput) string { return in.ChangeID }, run: func(_ context.Context, id auth.Identity, in rollbackInput) (any, error) {
		if in.Force && id.Role != permissions.RoleAdmin {
			return nil, &permissions.DeniedError{Role: id.Role, Permission: permissions.ChangesRollback}
		}
		return s.opts.Changes.Rollback(in.ChangeID, id.Actor, in.Force)
	}})
}

func (s *Server) registerGodMode() {
	addTool(s, toolSpec[godmode.Request]{name: "godmode_shell", description: "DANGER: execute an unrestricted command in the host namespaces.", class: permissions.GodMode, mutation: true, target: func(_ godmode.Request) string { return "host" }, run: func(ctx context.Context, _ auth.Identity, in godmode.Request) (any, error) {
		return s.opts.GodShell.Execute(ctx, in)
	}})
}

func sensitiveKey(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "API_KEY")
}

func sensitiveFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == ".env" || name == "id_rsa" || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || strings.Contains(name, "secret")
}
