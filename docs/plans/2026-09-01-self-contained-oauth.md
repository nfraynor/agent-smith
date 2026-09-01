# Self-contained OAuth for RemoteOps

## Outcome

A fresh RemoteOps deployment can be started as one container, bootstrap its first
local administrator from a Docker secret, and authenticate individual ChatGPT and
Claude remote-MCP users through OAuth 2.1 without an external identity service.

## Status

Implemented and locally verified on 2026-09-01. This supersedes the shorter
`2026-08-31-self-contained-oauth.md` draft. Live ChatGPT and Claude connection tests
through the production HAProxy route remain rollout gates; static `bearer` mode is
retained as an explicit rollback deployment.

## Compatibility baseline

Implement the narrow MCP authorization profile used by ChatGPT and Claude, not a
general-purpose identity provider:

- Authorization Code grant with PKCE S256 for public clients.
- RFC 8414 authorization-server metadata and RFC 9728 protected-resource metadata,
  including path-aware discovery for `/mcp`.
- Dynamic Client Registration (DCR) for paste-the-URL setup, plus optional
  operator-defined registrations if a client requires fixed credentials.
- RFC 8707 `resource` handling, with tokens bound to the exact MCP resource URL.
- RFC 6750 bearer challenges with the MCP `resource_metadata` location.
- Refresh-token grant and RFC 7009 revocation.
- Opaque tokens. Because RemoteOps is issuer and resource server, JWT, JWKS,
  introspection, and OIDC are unnecessary.

Before implementation, pin the MCP authorization specification revision and re-check
the official ChatGPT and Claude connector documentation. Put client-specific behavior
in compatibility fixtures rather than weakening the core protocol.

## Deployment contract

- Require a canonical HTTPS `public_origin`; development uses
  `https://this.dev.privacyperfect.com`. Never derive issuer URLs from request headers.
- The exact MCP resource identifier is `<public-origin>/mcp`.
- HAProxy forwards `/mcp`, `/mcp/*`, `/oauth/*`, `/.well-known/*`, and `/health` without path rewriting. HAProxy continues to terminate TLS.
- Store OAuth/account state in one transactional file below `/data`, opened by one
  RemoteOps process. Multiple replicas require a future shared database.
- Consume the first administrator email/password only when the account store is
  empty. Read the password from a Docker secret/file, never YAML, arguments, logs,
  image layers, or source control.
- Keep `auth.mode: bearer` for rollback and non-browser automation. Make
  `auth.mode: oauth-local` the documented normal deployment after acceptance.
- `/health` stays public and contains no identity/store details. `/mcp/ready` and `/mcp`
  require an audience-bound access token.

## Scope

Included:

- Local email/password users with `viewer`, `operator`, or `admin` roles.
- Minimal login/approval pages and an admin page for creating, disabling,
  role-changing, password-resetting, and session-revoking users.
- Browser sessions only for OAuth/admin pages; MCP always uses bearer access tokens.
- DCR, authorization codes, access tokens, rotating refresh tokens, revocation,
  logout, auditing, and expired-record cleanup.
- OAuth scopes such as `mcp` and optional `offline_access`; scopes never confer roles.

Initial non-goals:

- Google/social login, mail, self-service recovery, SCIM, LDAP, SAML, OIDC identity
  tokens, organizations, or multiple tenants.
- Arbitrary third-party OAuth clients. Registrations are limited to configured
  ChatGPT/Claude redirect URIs and operator-created clients.
- Multiple replicas or a second authorization-service container.
- MFA. Keep the model extensible for TOTP/WebAuthn and document network allowlisting
  as a compensating control for this host-administration service.
- Any path from OAuth scopes or account management to the startup-only God Mode flag.

## Configuration contract

Settle exact names in configuration tests before service code. Proposed shape:

```yaml
auth:
  mode: oauth-local
  oauth_local:
    public_origin: https://this.dev.privacyperfect.com
    data_file: /data/oauth.db
    bootstrap_email_env: REMOTEOPS_BOOTSTRAP_EMAIL
    bootstrap_password_file_env: REMOTEOPS_BOOTSTRAP_PASSWORD_FILE
    allowed_redirect_uris:
      - <verified ChatGPT callback URI>
      - <verified Claude callback URI>
    access_token_minutes: 15
    refresh_token_days: 30
    browser_session_hours: 8
```

Rules:

- `public_origin` is an origin-only HTTPS URL without userinfo, query, fragment, or
  non-root path. Permit loopback HTTP only in explicit test mode.
- Redirect URIs are exact-matched after strict parsing. Reject wildcards, fragments,
  userinfo, open redirects, arbitrary schemes, and non-test HTTP.
- Ship the redirect allowlist empty; examples use callback values verified at release
  time rather than silently trusting changing vendor domains.
- Bound all lifetimes. Reject bearer-only fields in OAuth mode and OAuth-only fields
  in bearer mode so startup fails closed.
- Prefer `*_FILE` secrets. An environment password may exist only as a documented
  development fallback.

## HTTP surface

| Route | Purpose | Authentication |
| --- | --- | --- |
| `GET /.well-known/oauth-protected-resource/mcp` | MCP resource metadata | Public |
| `GET /.well-known/oauth-protected-resource` | Compatibility alias, only if testing requires it | Public |
| `GET /.well-known/oauth-authorization-server` | Authorization-server metadata | Public |
| `POST /oauth/register` | Restricted DCR for public PKCE clients | Public, rate-limited |
| `GET /oauth/authorize` | Validate/resume browser authorization | Browser session |
| `GET, POST /oauth/login` | Local sign-in | Public, CSRF-protected/rate-limited |
| `POST /oauth/logout` | End browser session | Browser session plus CSRF |
| `POST /oauth/token` | Code exchange and refresh grant | Public-client rules/rate limit |
| `POST /oauth/revoke` | Revoke token or token family | Client-bound request |
| `GET, POST /oauth/admin/*` | Local user/session administration | Admin session plus CSRF |
| `POST /mcp` | Streamable HTTP MCP | Audience-bound access token |
| `GET /mcp/ready` | Docker-backed readiness | Audience-bound access token |

OAuth endpoints return OAuth-shaped errors. A resource 401 keeps RemoteOps' stable
JSON error and adds the compliant `WWW-Authenticate` discovery challenge. Never
redirect an MCP request to browser login.

## Persistent model

Select a mature CGO-free transactional embedded store compatible with the static
Docker build and hide it behind interfaces. Persist:

- Users: immutable ID, normalized email, Argon2id hash/parameters, role, enabled and
  password-change flags, timestamps, and security version.
- Clients: generated ID, normalized metadata, exact redirects, registration source,
  timestamps, and disabled flag.
- Browser sessions: random identifier hash, user, CSRF material, expiry, security
  version, and last-seen time.
- Authorization codes: random code hash, user/client/resource/redirect/PKCE binding,
  expiry, and consumed time.
- Access tokens: random token hash, user/client/resource/scope binding, expiry,
  revocation, and security version.
- Refresh tokens: random token hash, family ID, bindings/scope, expiry,
  consumed/revoked state, and security version.

Store only hashes of credentials, codes, and sessions. Generate at least 256 bits of
entropy. Enforce uniqueness, one-time use, and rotation transactionally. Disabling a
user, resetting a password, changing a role, or revoking sessions increments the
security version and immediately invalidates earlier sessions and tokens.

## Security requirements

- Prefer a vetted OAuth library where it fits; document/test local protocol code.
- Use Argon2id with reviewed bounded parameters and rehash-on-login.
- Bind short-lived, single-use authorization codes to client, exact redirect,
  resource, and PKCE. Reject replay atomically.
- Require PKCE `S256`; reject `plain`, missing/malformed verifiers, implicit flow,
  password flow, and unsupported grants.
- Use short-lived, exact-audience access tokens. Rotate refresh tokens every use;
  replay of a consumed refresh token revokes its whole family.
- DCR accepts public clients only (`token_endpoint_auth_method: none`), bounds
  metadata/counts, exact-matches allowed redirects, escapes display metadata, never
  fetches client-supplied URLs, and has an independent rate limit.
- Use generic login errors, account/source throttling, progressive backoff, and
  bounded password-verification concurrency.
- Make cookies Secure, HttpOnly, host-only, and SameSite=Lax; rotate on login. Protect
  state-changing browser routes with CSRF tokens and Origin checks. Set restrictive
  CSP, `frame-ancestors 'none'`, nosniff, no-referrer, and no-store headers.
- Bind server-side authorization transactions to client, redirect, resource, scopes,
  and PKCE. OAuth `state` is not login CSRF protection.
- Never log passwords, cookies, codes, tokens, PKCE verifiers, or full query strings.
- Do not trust forwarded IP headers without explicit trusted-proxy configuration.
  Apply account/client limits in RemoteOps and outer source-IP limits in HAProxy.
- Audit bootstrap, logins, approvals/denials, registrations, token issue/refresh/
  replay/revocation, logout, and admin actions without credential material.
- Enforce restrictive data file/directory permissions, durable commits, schema
  versions, and documented backup/restore.

## Implementation sequence

### 1. Freeze decisions and fixtures

- [ ] Add an ADR for embedded OAuth, opaque tokens, the chosen CGO-free store,
      one-replica operation, restricted DCR, and bearer rollback.
- [ ] Verify current ChatGPT/Claude callbacks and connector behavior from official
      documentation and live test accounts.
- [ ] Create fixtures for discovery, DCR, authorization, token/refresh/revocation,
      scopes/resources, and bearer challenges.

### 2. Configuration, storage, and bootstrap

- [ ] Add mutually exclusive `bearer`/`oauth-local` configuration and secret files.
- [ ] Construct canonical issuer/resource URLs without proxy headers.
- [ ] Add the versioned transactional store, permissions, durable writes, cleanup,
      and actionable corrupt/migration startup errors.
- [ ] Bootstrap one admin only when empty; make retries idempotent, force first-login
      password change, and ignore bootstrap values after initialization.

### 3. Local identity and browser security

- [ ] Implement accounts, Argon2id, constant-work failures, browser sessions, CSRF,
      throttling, and security-version invalidation.
- [ ] Add dependency-light templates for login, approval, first password change, and
      safe generic errors.
- [ ] Add admin user/session operations and recent-password confirmation for
      high-impact changes.

### 4. OAuth server

- [ ] Serve discovery from canonical configured URLs.
- [ ] Implement bounded DCR/operator clients and exact redirect validation.
- [ ] Implement authorization with login resumption, approval/denial, state/resource/
      scope validation, PKCE S256, and one-time codes.
- [ ] Implement code exchange, access tokens, refresh rotation/family replay
      detection, and revocation transactionally.
- [ ] Apply body/rate limits, security/cache headers, and standards-shaped errors per
      endpoint group rather than one global OAuth middleware.

### 5. RemoteOps integration

- [ ] Extend `auth.Identity` with immutable subject ID while retaining display/login
      name and current server-side role.
- [ ] Add an opaque-token `Authenticator` and OAuth discovery challenge without
      weakening strict bearer parsing or stable JSON errors.
- [ ] Move application assembly out of the growing `cmd/remoteops/main.go` path so
      bearer and OAuth modes can be integration-tested.
- [ ] Replace static `cfg.Auth.Actor` in deployment/change/audit paths with the
      authenticated request identity, including explicitly captured async work.
- [ ] Prove roles use existing permission checks and OAuth cannot enable God Mode.

### 6. Packaging and operator experience

- [ ] Update both Compose files for OAuth data and bootstrap Docker secrets while
      retaining an explicit static-bearer rollback profile.
- [ ] Update example YAML, README, and SECURITY docs with copy/paste first run,
      HAProxy routes, user lifecycle, backup/restore, revocation, and lost-admin
      recovery.
- [ ] Document ChatGPT and Claude connection using the same MCP URL.
- [ ] Log active auth mode/bootstrap outcome without logging credentials or tokens.

### 7. Rollout

- [ ] Deploy a disposable OAuth store to `this.dev.privacyperfect.com`.
- [ ] Test both live clients: authorization, reconnect, expiry/refresh, revocation,
      role change, and disabled user.
- [ ] Back up existing configuration/token, switch development to OAuth, retain the
      bearer rollback procedure, and observe audit/rate-limit behavior.

## Verification matrix

Automated tests cover:

- Strict modes/secrets, canonical URLs, and hostile Host/forwarded headers.
- Bootstrap/restart idempotence, permissions, migration/corruption, concurrent token
  exchanges, durable transactions, and restart persistence.
- Password rehashing, generic failures, throttling, session fixation, disabled users,
  role/password changes, and immediate invalidation.
- Exact discovery documents/challenges and ChatGPT/Claude protocol fixtures.
- DCR allowlists, exact redirects, malicious metadata, caps, and public-client rules.
- All PKCE/code expiry, replay, client/redirect/resource/scope binding, denial, and
  state cases.
- Access expiry/audience/revocation and refresh rotation/concurrency/family replay.
- CSRF/Origin, cookies, CSP/clickjacking, escaping, body limits, no-store, and secret
  absence from errors/logs/audit.
- Existing bearer behavior and the full MCP permission suite.

Canonical checks:

```sh
docker build --target test .
docker build -t remoteops-mcp:local .
docker compose -f docker-compose.safe.yml config
docker compose -f docker-compose.godmode.yml config
```

Add a Docker end-to-end test driving a browser-style Authorization Code + PKCE flow
through `/mcp`. Live ChatGPT and Claude tests remain release gates.

## Acceptance criteria

- An operator configures the public origin and bootstrap secret values, runs one
  Compose command, and reaches local login with no other service.
- Pasting the same `/mcp` URL into current ChatGPT and Claude leads to RemoteOps login
  and authorization without copying tokens or entering client secrets.
- Two users have independent identities/roles in audits and permissions. Disabling
  one immediately invalidates only that user's sessions/tokens without restart.
- Recreating the container with the same `/data` preserves accounts, clients, grants,
  and revocations and never recreates/resets the administrator.
- No credential appears in config, logs, audit, HTTP errors, or repository history.
- Bearer mode still behaves exactly as before as a tested rollback path.
- Automated checks and both live-client matrices pass, and shipped documentation
  matches Compose behavior.

## Delivery checkpoints

1. ADR, fixtures, configuration, store, and bootstrap.
2. Accounts, sessions, browser security, and admin UI.
3. OAuth discovery, registration, authorization, token, and revocation.
4. MCP identity propagation, documentation, and Compose packaging.
5. Live ChatGPT/Claude compatibility and deployment hardening.

Do not default examples to OAuth before checkpoint 4 passes. Do not call it
production-ready before checkpoint 5 passes both live clients.
