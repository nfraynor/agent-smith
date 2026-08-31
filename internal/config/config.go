// Package config loads and strictly validates RemoteOps startup configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nfraynor/agent-smith/internal/permissions"
	"gopkg.in/yaml.v3"
)

const DefaultPath = "/config/remoteops.yaml"

type Config struct {
	Server      Server      `yaml:"server"`
	Auth        Auth        `yaml:"auth"`
	Docker      Docker      `yaml:"docker"`
	Filesystem  Filesystem  `yaml:"filesystem"`
	Compose     Compose     `yaml:"compose"`
	Permissions Permissions `yaml:"permissions"`
	Shell       Shell       `yaml:"shell"`
	Changes     Changes     `yaml:"changes"`
	Limits      Limits      `yaml:"limits"`
	GodMode     bool        `yaml:"-"`
	BearerToken string      `yaml:"-"`
}

type Server struct {
	Name   string `yaml:"name"`
	Listen string `yaml:"listen"`
}

type Auth struct {
	Mode     string `yaml:"mode"`
	TokenEnv string `yaml:"token_env"`
	Actor    string `yaml:"actor"`
}

type Docker struct {
	Enabled bool   `yaml:"enabled"`
	Socket  string `yaml:"socket"`
}

type Filesystem struct {
	Roots []Root `yaml:"roots"`
}

type Root struct {
	Name     string `yaml:"name"`
	Path     string `yaml:"path"`
	ReadOnly bool   `yaml:"read_only"`
}

type Compose struct {
	Projects []Project `yaml:"projects"`
}

type Project struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
	File string `yaml:"file"`
}

type Permissions struct {
	DefaultRole permissions.Role `yaml:"default_role"`
}

type Shell struct {
	Enabled bool `yaml:"enabled"`
}

type Changes struct {
	RetentionDays int `yaml:"retention_days"`
	MaxRecords    int `yaml:"max_records"`
}

type Limits struct {
	MaxLogBytes         int64 `yaml:"max_log_bytes"`
	MaxFileReadBytes    int64 `yaml:"max_file_read_bytes"`
	MaxExecutionSeconds int   `yaml:"max_execution_seconds"`
	MaxRequestBytes     int64 `yaml:"max_request_bytes"`
	RequestsPerMinute   int   `yaml:"requests_per_minute"`
	MutationsPerMinute  int   `yaml:"mutations_per_minute"`
}

func Defaults() Config {
	return Config{
		Server:      Server{Listen: ":8080"},
		Auth:        Auth{Mode: "bearer", TokenEnv: "REMOTEOPS_TOKEN", Actor: "remote-client"},
		Docker:      Docker{Enabled: true, Socket: "unix:///var/run/docker.sock"},
		Permissions: Permissions{DefaultRole: permissions.RoleViewer},
		Changes:     Changes{RetentionDays: 30, MaxRecords: 10000},
		Limits: Limits{
			MaxLogBytes: 1 << 20, MaxFileReadBytes: 1 << 20,
			MaxExecutionSeconds: 60, MaxRequestBytes: 1 << 20,
			RequestsPerMinute: 120, MutationsPerMinute: 20,
		},
	}
}

// Load reads a YAML file, rejects unknown fields, resolves the configured bearer
// token from the environment, and parses God Mode independently.
func Load(path string) (Config, error) {
	return LoadWithEnv(path, os.LookupEnv)
}

func LoadWithEnv(path string, lookup func(string) (string, bool)) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	config := Defaults()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode configuration: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}

	godMode, err := ParseGodMode(lookup)
	if err != nil {
		return Config{}, err
	}
	config.GodMode = godMode
	if err := config.resolveSecrets(lookup); err != nil {
		return Config{}, err
	}
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate configuration: %w", err)
	}
	return config, nil
}

// ParseGodMode deliberately accepts only the literal values "true" and
// "false". It does not trim whitespace or accept case variants.
func ParseGodMode(lookup func(string) (string, bool)) (bool, error) {
	value, present := lookup("REMOTEOPS_GODMODE")
	if !present || value == "" || value == "false" {
		return false, nil
	}
	if value == "true" {
		return true, nil
	}
	return false, fmt.Errorf("REMOTEOPS_GODMODE must be exactly %q or %q; got %q", "true", "false", value)
}

func (c *Config) resolveSecrets(lookup func(string) (string, bool)) error {
	if c.Auth.TokenEnv == "" {
		return errors.New("auth.token_env is required")
	}
	token, ok := lookup(c.Auth.TokenEnv)
	if !ok || token == "" {
		return fmt.Errorf("required bearer token environment variable %q is not set", c.Auth.TokenEnv)
	}
	c.BearerToken = token
	return nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Name) == "" {
		return errors.New("server.name is required")
	}
	if strings.TrimSpace(c.Server.Listen) == "" {
		return errors.New("server.listen is required")
	}
	if c.Auth.Mode != "bearer" {
		return fmt.Errorf("auth.mode must be %q", "bearer")
	}
	if _, err := permissions.ParseRole(string(c.Permissions.DefaultRole)); err != nil {
		return fmt.Errorf("permissions.default_role: %w", err)
	}
	if c.Docker.Enabled && strings.TrimSpace(c.Docker.Socket) == "" {
		return errors.New("docker.socket is required when Docker is enabled")
	}
	if err := validateRoots(c.Filesystem.Roots); err != nil {
		return err
	}
	if err := validateProjects(c.Compose.Projects); err != nil {
		return err
	}
	if c.Changes.RetentionDays <= 0 || c.Changes.MaxRecords <= 0 {
		return errors.New("change retention_days and max_records must be positive")
	}
	if c.Limits.MaxLogBytes <= 0 || c.Limits.MaxFileReadBytes <= 0 ||
		c.Limits.MaxExecutionSeconds <= 0 || c.Limits.MaxRequestBytes <= 0 ||
		c.Limits.RequestsPerMinute <= 0 || c.Limits.MutationsPerMinute <= 0 {
		return errors.New("all limits must be positive")
	}
	return nil
}

func validateRoots(roots []Root) error {
	seen := make(map[string]struct{}, len(roots))
	for i, root := range roots {
		if strings.TrimSpace(root.Name) == "" {
			return fmt.Errorf("filesystem.roots[%d].name is required", i)
		}
		if _, exists := seen[root.Name]; exists {
			return fmt.Errorf("filesystem root name %q is duplicated", root.Name)
		}
		seen[root.Name] = struct{}{}
		if !filepath.IsAbs(root.Path) || filepath.Clean(root.Path) == string(filepath.Separator) {
			return fmt.Errorf("filesystem root %q must be an absolute path other than the filesystem root", root.Name)
		}
	}
	return nil
}

func validateProjects(projects []Project) error {
	seen := make(map[string]struct{}, len(projects))
	for i, project := range projects {
		if strings.TrimSpace(project.Name) == "" {
			return fmt.Errorf("compose.projects[%d].name is required", i)
		}
		if _, exists := seen[project.Name]; exists {
			return fmt.Errorf("compose project name %q is duplicated", project.Name)
		}
		seen[project.Name] = struct{}{}
		if !filepath.IsAbs(project.Path) {
			return fmt.Errorf("compose project %q path must be absolute", project.Name)
		}
		if project.File == "" || filepath.IsAbs(project.File) || filepath.Base(project.File) != project.File {
			return fmt.Errorf("compose project %q file must be a plain relative filename", project.Name)
		}
	}
	return nil
}
