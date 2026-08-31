// Package godmode implements the explicitly enabled, unrestricted host shell.
// It is deliberately separate from every constrained RemoteOps capability.
package godmode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CommandRunner is the small seam used by tests and alternate nsenter locations.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, env []string) (stdout, stderr []byte, exitCode int, err error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args, env []string) ([]byte, []byte, int, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, err
}

type Runner struct {
	Enabled        bool
	NSenterPath    string
	DefaultTimeout time.Duration
	MaximumTimeout time.Duration
	MaxOutputBytes int
	CommandRunner  CommandRunner
}

type Request struct {
	Command          string            `json:"command" jsonschema:"the unrestricted command to run on the host"`
	WorkingDirectory string            `json:"workingDirectory,omitempty" jsonschema:"host working directory"`
	TimeoutSeconds   int               `json:"timeoutSeconds,omitempty" jsonschema:"execution timeout in seconds"`
	Environment      map[string]string `json:"environment,omitempty" jsonschema:"additional environment variables"`
}

type Result struct {
	Success    bool   `json:"success"`
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated"`
	DurationMS int64  `json:"durationMs"`
}

func (r Runner) Execute(ctx context.Context, req Request) (Result, error) {
	if !r.Enabled {
		return Result{}, errors.New("GODMODE_DISABLED: godmode_shell is not enabled")
	}
	if strings.TrimSpace(req.Command) == "" {
		return Result{}, errors.New("INVALID_ARGUMENT: command is required")
	}
	if r.NSenterPath == "" {
		r.NSenterPath = "/usr/bin/nsenter"
	}
	if r.DefaultTimeout <= 0 {
		r.DefaultTimeout = 60 * time.Second
	}
	if r.MaximumTimeout <= 0 {
		r.MaximumTimeout = r.DefaultTimeout
	}
	if r.MaxOutputBytes <= 0 {
		r.MaxOutputBytes = 1 << 20
	}
	timeout := r.DefaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	if timeout > r.MaximumTimeout {
		return Result{}, fmt.Errorf("LIMIT_EXCEEDED: timeout exceeds %s", r.MaximumTimeout)
	}
	for key := range req.Environment {
		if !environmentName.MatchString(key) {
			return Result{}, fmt.Errorf("INVALID_ARGUMENT: invalid environment name %q", key)
		}
	}

	workingDirectory := req.WorkingDirectory
	if workingDirectory == "" {
		workingDirectory = "/"
	}
	args := []string{
		"--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--",
		"/bin/sh", "-c", `cd -- "$1" && shift && exec /bin/sh -lc "$1"`,
		"remoteops-godmode", workingDirectory, req.Command,
	}
	env := make([]string, 0, len(req.Environment))
	keys := make([]string, 0, len(req.Environment))
	for key := range req.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+req.Environment[key])
	}

	runner := r.CommandRunner
	if runner == nil {
		runner = execRunner{}
	}
	started := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout, stderr, exitCode, err := runner.Run(runCtx, r.NSenterPath, args, env)
	duration := time.Since(started).Milliseconds()
	stdout, stderr, truncated := boundCombined(stdout, stderr, r.MaxOutputBytes)
	result := Result{
		Success:    err == nil,
		ExitCode:   exitCode,
		Stdout:     string(stdout),
		Stderr:     string(stderr),
		Truncated:  truncated,
		DurationMS: duration,
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		result.Success = false
		result.ExitCode = -1
		return result, errors.New("EXECUTION_TIMEOUT: host command exceeded its timeout")
	}
	// Non-zero exit is an operational result, not an MCP transport failure.
	return result, nil
}

func boundCombined(stdout, stderr []byte, limit int) ([]byte, []byte, bool) {
	if len(stdout)+len(stderr) <= limit {
		return stdout, stderr, false
	}
	stdoutLimit := min(len(stdout), limit)
	stdout = stdout[:stdoutLimit]
	remaining := limit - stdoutLimit
	stderr = stderr[:min(len(stderr), remaining)]
	return stdout, stderr, true
}
