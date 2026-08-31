package permissions

import (
	"errors"
	"testing"
)

func TestBuiltInRoles(t *testing.T) {
	tests := []struct {
		role       Role
		permission Permission
		allowed    bool
	}{
		{RoleViewer, DockerRead, true},
		{RoleViewer, DockerRestart, false},
		{RoleOperator, ConfigWrite, true},
		{RoleOperator, ShellExecute, false},
		{RoleAdmin, ShellExecute, true},
		{Role("invented"), DockerRead, false},
	}
	authorizer := Authorizer{}
	for _, test := range tests {
		if got := authorizer.Allowed(test.role, test.permission); got != test.allowed {
			t.Errorf("Allowed(%q, %q) = %v, want %v", test.role, test.permission, got, test.allowed)
		}
	}
}

func TestCheckReturnsTypedDenial(t *testing.T) {
	err := (Authorizer{}).Check(RoleViewer, DockerDeploy)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
}

func TestGodModeIsNotRolePermission(t *testing.T) {
	if (Authorizer{}).Allowed(RoleAdmin, Permission("godmode.execute")) {
		t.Fatal("God Mode must not be granted through the normal role system")
	}
}
