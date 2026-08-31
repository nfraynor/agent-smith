# 0001: RemoteOps V1 architecture

- Status: accepted
- Date: 2026-08-31

## Context

RemoteOps is a security-sensitive, remotely accessible MCP server that must manage a
single Linux Docker host without installing an application runtime on that host. It
needs deterministic operational services, persistent audit/change data, and a clear
boundary between constrained tools and unrestricted administration.

## Decision

- Implement a single Go binary using the official MCP Go SDK and stateless Streamable
  HTTP at `/mcp`.
- Use the Docker Go SDK for container/image operations. Use the Docker Compose CLI only
  for explicitly configured projects, with arguments constructed by the server.
- Model authentication behind an interface. V1 maps one environment-sourced bearer
  token to a configured actor and role; role checks remain server-side.
- Keep `/health` as unauthenticated liveness. `/ready`, `/mcp`, and operational data are
  authenticated.
- Persist append-only JSON audit records and per-change metadata/backups under `/data`.
- Resolve all normal filesystem operations beneath named roots and reject traversal,
  absolute-path, and symlink escapes.
- Register `godmode_shell` only when the exact startup value
  `REMOTEOPS_GODMODE=true` is present. Execute it through `nsenter` into host PID 1;
  normal tools keep their constraints in that mode.

## Consequences

The server remains small, container-native, testable through service interfaces, and
compatible with future identity providers. Compose availability is a runtime image
requirement. File-backed history is deliberately simple for a single-host V1 and does
not provide distributed transactions. The Docker socket and God Mode deployment remain
root-equivalent capabilities and require strong network isolation and TLS termination.
