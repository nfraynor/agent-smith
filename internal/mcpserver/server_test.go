package mcpserver

import (
	"context"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/godmode"
	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestGodModeToolRegistrationIsDynamic(t *testing.T) {
	disabled, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	disabledTools := toolNames(t, disabled, auth.Identity{Actor: "viewer", Role: permissions.RoleViewer})
	if slices.Contains(disabledTools, "godmode_shell") {
		t.Fatal("godmode_shell was visible while disabled")
	}

	enabled, err := New(Options{GodMode: true, GodShell: &godmode.Runner{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	enabledTools := toolNames(t, enabled, auth.Identity{Actor: "viewer", Role: permissions.RoleViewer})
	if !slices.Contains(enabledTools, "godmode_shell") {
		t.Fatal("godmode_shell was not visible while enabled")
	}
}

func TestPermissionCheckRunsInsideHandler(t *testing.T) {
	server, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	executed := false
	addTool(server, toolSpec[struct{}]{name: "test_mutation", permission: permissions.DockerDeploy, class: permissions.Deployment, mutation: true, run: func(context.Context, auth.Identity, struct{}) (any, error) {
		executed = true
		return map[string]bool{"ok": true}, nil
	}})
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Actor: "viewer", Role: permissions.RoleViewer})
	session := connect(t, server, ctx)
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "test_mutation", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("unauthorized mutation did not return a tool error")
	}
	if executed {
		t.Fatal("unauthorized mutation reached the domain handler")
	}
}

func toolNames(t *testing.T, server *Server, identity auth.Identity) []string {
	t.Helper()
	ctx := auth.WithIdentity(context.Background(), identity)
	session := connect(t, server, ctx)
	defer session.Close()
	var names []string
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	return names
}

func connect(t *testing.T, server *Server, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.MCP().Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
