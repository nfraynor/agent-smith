// Package permissions defines RemoteOps' server-side authorization policy.
package permissions

import (
	"errors"
	"fmt"
	"strings"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

func ParseRole(value string) (Role, error) {
	role := Role(strings.ToLower(strings.TrimSpace(value)))
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
		return role, nil
	default:
		return "", fmt.Errorf("unknown role %q", value)
	}
}

type Permission string

const (
	DockerRead      Permission = "docker.read"
	DockerRestart   Permission = "docker.restart"
	DockerDeploy    Permission = "docker.deploy"
	ComposeRead     Permission = "compose.read"
	ComposeDeploy   Permission = "compose.deploy"
	FilesystemRead  Permission = "filesystem.read"
	FilesystemWrite Permission = "filesystem.write"
	ConfigRead      Permission = "config.read"
	ConfigWrite     Permission = "config.write"
	ChangesRead     Permission = "changes.read"
	ChangesRollback Permission = "changes.rollback"
	ShellExecute    Permission = "shell.execute"
	SecretsRead     Permission = "secrets.read"
)

type ActionClass string

const (
	ReadOnly    ActionClass = "READ_ONLY"
	SafeWrite   ActionClass = "SAFE_WRITE"
	Deployment  ActionClass = "DEPLOYMENT"
	Destructive ActionClass = "DESTRUCTIVE"
	Privileged  ActionClass = "PRIVILEGED"
	GodMode     ActionClass = "GODMODE"
)

var ErrDenied = errors.New("permission denied")

type DeniedError struct {
	Role       Role
	Permission Permission
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("PERMISSION_DENIED: role %q does not have %q", e.Role, e.Permission)
}

func (e *DeniedError) Unwrap() error { return ErrDenied }

// Authorizer is intentionally independent of tool visibility. Every handler must
// call Check before performing its operation.
type Authorizer struct{}

func (Authorizer) Allowed(role Role, permission Permission) bool {
	allowed, ok := rolePermissions[role]
	if !ok {
		return false
	}
	_, ok = allowed[permission]
	return ok
}

func (a Authorizer) Check(role Role, permission Permission) error {
	if !a.Allowed(role, permission) {
		return &DeniedError{Role: role, Permission: permission}
	}
	return nil
}

var rolePermissions = map[Role]map[Permission]struct{}{
	RoleViewer: permissionSet(
		DockerRead, ComposeRead, FilesystemRead, ConfigRead, ChangesRead,
	),
	RoleOperator: permissionSet(
		DockerRead, DockerRestart, DockerDeploy,
		ComposeRead, ComposeDeploy,
		FilesystemRead, FilesystemWrite,
		ConfigRead, ConfigWrite,
		ChangesRead, ChangesRollback,
	),
	RoleAdmin: permissionSet(
		DockerRead, DockerRestart, DockerDeploy,
		ComposeRead, ComposeDeploy,
		FilesystemRead, FilesystemWrite,
		ConfigRead, ConfigWrite,
		ChangesRead, ChangesRollback, ShellExecute, SecretsRead,
	),
}

func permissionSet(values ...Permission) map[Permission]struct{} {
	result := make(map[Permission]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
