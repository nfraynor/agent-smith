# Self-contained OAuth deployment

RemoteOps contains its own OAuth 2.1 authorization server and local user database.
No Auth0, Google Workspace, Keycloak, or other identity service is required.

## First deployment

1. Confirm `auth.oauth_local.public_origin` in `remoteops.yaml` is the exact public
   HTTPS origin. For the development host it is:

   ```yaml
   public_origin: https://this.dev.privacyperfect.com
   ```

2. Create the bootstrap password secret on the Docker host:

   ```sh
   cd /opt/agent-smith
   mkdir -p secrets
   openssl rand -base64 32 > secrets/remoteops_bootstrap_password
   chmod 600 secrets/remoteops_bootstrap_password
   export REMOTEOPS_BOOTSTRAP_EMAIL='your.name@privacyperfect.com'
   ```

3. Start the safe deployment:

   ```sh
   docker compose -f docker-compose.safe.yml up -d --build
   docker compose -f docker-compose.safe.yml logs --tail 100 remoteops
   ```

4. Open `https://this.dev.privacyperfect.com/admin/users`, sign in with the bootstrap
   email and the contents of the secret file, and change the temporary password.
   Create one account per allowed user and assign the smallest appropriate role.

The bootstrap values are ignored after the first account exists. Recreating the
container with the same `remoteops-data` volume preserves users, clients, tokens, and
revocations. Do not delete that volume during normal upgrades.

## HAProxy routes

The public origin must forward all of these paths to RemoteOps on port 8080 without
rewriting them:

```text
/mcp
/.well-known/*
/oauth/*
/login
/logout
/account/*
/admin/*
```

Both containers must share a Docker network, or HAProxy must be able to reach the
loopback-published RemoteOps port. A path ACL can look like:

```haproxy
acl is_remoteops_path path /mcp /login /logout
acl is_remoteops_path path_beg /.well-known/ /oauth/ /account/ /admin/
use_backend remoteops_mcp if { hdr(host) -i this.dev.privacyperfect.com } is_remoteops_path

backend remoteops_mcp
    server remoteops agent-smith-remoteops-1:8080 check
```

Apply outer source-IP rate limits in HAProxy. RemoteOps deliberately does not trust
client-supplied forwarding headers.

## Verify discovery

```sh
curl -sS https://this.dev.privacyperfect.com/.well-known/oauth-protected-resource/mcp
curl -sS https://this.dev.privacyperfect.com/.well-known/oauth-authorization-server
curl -i https://this.dev.privacyperfect.com/mcp
```

The last request should return `401` with a `WWW-Authenticate` header containing the
protected-resource metadata URL. The first two requests should return JSON containing
only URLs under the configured public origin.

## Connect ChatGPT and Claude

Add this remote MCP URL in either client's connector/integration settings:

```text
https://this.dev.privacyperfect.com/mcp
```

The client discovers OAuth, registers its allowlisted callback, and opens the
RemoteOps login page. Sign in using a local RemoteOps account. No client secret or
manually copied bearer token is required.

The default redirect allowlist contains the currently documented ChatGPT application
callbacks and Claude MCP callback. Re-check official client documentation during an
upgrade; callbacks are exact-matched and never wildcarded.

## User and incident operations

- Manage users at `/admin/users`.
- Disabling a user, changing a role/password, or revoking sessions invalidates that
  user's existing browser sessions and OAuth tokens immediately.
- Back up the complete `/data` volume consistently. It contains `oauth.db`, audit
  records, and change history.
- Retain the bootstrap password file with root-only permissions. It is only used
  while the user database is empty, but Docker Compose still mounts it on restarts.
- Run one RemoteOps replica per embedded database.
- After suspected compromise, disable the account or reset its password, review
  `/data/audit.jsonl`, and reconnect the affected MCP clients.

## Bearer rollback

Static bearer mode remains available if an OAuth deployment must be rolled back:

```yaml
auth:
  mode: bearer
  token_env: REMOTEOPS_TOKEN
  actor: emergency-operator
```

Set a new random `REMOTEOPS_TOKEN`, then start the dedicated rollback deployment:

```bash
export REMOTEOPS_TOKEN="$(openssl rand -base64 48)"
docker compose -f docker-compose.bearer.yml up -d --build
```

Send that token only from a client that supports arbitrary bearer credentials.
ChatGPT remote MCP should normally remain on OAuth mode.
