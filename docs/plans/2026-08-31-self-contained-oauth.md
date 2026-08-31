# Self-contained OAuth

## Goal

Make RemoteOps independently authenticate ChatGPT MCP users without Auth0,
Google, or another identity provider. The same Go service is both the OAuth 2.1
authorization server and the MCP resource server.

## Deployment contract

- Public origin: explicitly configured HTTPS URL (development deployment:
  `https://this.dev.privacyperfect.com`).
- MCP resource: `<origin>/mcp`.
- The load balancer forwards `/mcp`, `/oauth/*`, and `/.well-known/*` to the
  container and preserves the public host and scheme.
- OAuth and account state is persisted below `/data`; the initial administrator
  password is injected from the environment or a Docker secret and is never
  stored in YAML or logs.
- A local state directory supports one active RemoteOps replica. Multiple
  replicas require a shared transactional store and are outside this change.

## Security requirements

- Authorization Code flow with PKCE S256; no implicit flow or password grant.
- ChatGPT client metadata is validated, redirects are exact-match HTTPS URLs,
  and authorization codes are short-lived and single-use.
- Passwords are stored using an adaptive password hash.
- Access tokens are short-lived and audience-bound to the MCP resource.
- Refresh tokens are opaque, stored hashed, rotated on use, and revocable.
- Login, authorization, token, and MCP authentication attempts are rate-limited
  and auditable without recording credentials or tokens.
- Roles are assigned by RemoteOps configuration/account state, never by a
  client-requested scope. OAuth cannot enable God Mode.

## Work items

- [ ] Extend strict configuration with `oauth-local` mode and secret resolution.
- [ ] Add persistent local accounts, authorization transactions, codes, and tokens.
- [ ] Add OAuth discovery, authorization, login, token, refresh, and revocation endpoints.
- [ ] Add an OAuth bearer authenticator and standards-compliant challenges for `/mcp`.
- [ ] Wire the OAuth routes into the single service and update Compose examples.
- [ ] Add unit/integration tests for PKCE, redirect checks, one-time codes,
      password verification, refresh rotation, allow/role enforcement, and restart persistence.
- [ ] Document first-run bootstrap, load-balancer routing, deployment, and ChatGPT setup.
- [ ] Run `docker build --target test .`, both Compose config validations, and a production image build.

## Compatibility

Static bearer mode remains available for non-ChatGPT automation and rollback.
The documented Compose deployment switches to self-contained OAuth.
