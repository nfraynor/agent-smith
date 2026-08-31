# RemoteOps MCP V1

## Outcome

A production-oriented Go MCP server that runs in Docker and provides authenticated,
permission-controlled, bounded, audited Docker/Compose/file/config/deployment tools,
conflict-safe rollback, and an explicitly enabled host-level God Mode.

## Constraints

- Normal Mode remains structured and constrained to configured resources.
- `REMOTEOPS_GODMODE=true` is the only way to expose unrestricted host execution.
- The safe deployment is the default and never mounts the host root or uses privileged mode.
- Secrets, credentials, and unbounded command/file/log output must not enter responses or logs.
- V1 targets Linux Docker hosts; no host application runtime is required.

## Steps

- [x] Establish the Go module, strict configuration, authentication, permissions, limits,
      audit model, and architecture decision record.
- [x] Implement Docker, configured Compose, managed-filesystem, YAML, env, diagnostics,
      and health services behind testable interfaces.
- [x] Implement atomic backups, change records, hashes, diffs, conflict-safe rollback,
      target locking, and deployment verification.
- [x] Expose the services through authenticated Streamable HTTP MCP with bounded,
      structured errors and dynamic God Mode tool registration.
- [x] Add minimal container image plus separate safe and God Mode Compose examples.
- [x] Add unit/security tests, endpoint smoke verification, CI, operator docs, and
      security documentation.
- [x] Build and run the documented safe-mode check suite in Docker; review the final diff.
- [ ] Exercise host namespace execution on a disposable Linux host after explicit approval.

## Verification

- `docker build --target test .`
- `docker build -t remoteops-mcp:local .`
- `docker compose -f docker-compose.safe.yml config`
- `docker compose -f docker-compose.godmode.yml config`
- Unit and security tests run by the Docker test target.
- Smoke-tested `/health`, `/ready`, bearer rejection, MCP initialization, and safe-mode
  tool listing against a running container.
- God Mode registration and namespace arguments are unit-tested; a live privileged
  host-namespace test remains approval-gated on disposable Linux infrastructure.
