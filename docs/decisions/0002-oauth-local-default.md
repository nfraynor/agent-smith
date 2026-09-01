# OAuth-local is the default authentication mode

Status: Accepted (2026-09-01)

## Context

Remote MCP clients such as ChatGPT and Claude require an interactive OAuth flow for
individual users. RemoteOps must provide that flow, account allowlisting, and roles
without depending on an external identity provider.

## Decision

- `oauth-local` is the configuration default and the normal safe and God Mode
  deployment mode.
- Normal Compose files do not inject `REMOTEOPS_TOKEN`.
- Static bearer authentication remains available only through an explicit
  `auth.mode: bearer` configuration or the bearer rollback Compose file.
- An explicitly configured bearer deployment is honored during upgrades; RemoteOps
  does not silently migrate operator configuration.
- OAuth account and token state remains in the single-replica transactional store
  under `/data`. The standards-required discovery endpoints remain at
  `/.well-known/*`; interactive authorization routes live under `/oauth/*`.

## Consequences

Fresh deployments must configure the exact public HTTPS origin and bootstrap the
first administrator. Existing bearer deployments must deliberately change their
configuration before `/oauth/*` is exposed. Bearer rollback stays available for
non-browser automation and incident recovery.
