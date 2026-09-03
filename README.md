# RemoteOps MCP

RemoteOps is a containerized Model Context Protocol server for inspecting,
diagnosing, configuring, deploying, and recovering Docker-based applications on one
Linux host. It exposes structured operations instead of making an arbitrary shell the
normal interface.

> Observe → reason → bounded action → verify → audit → rollback where practical.

Normal Mode constrains files to named roots and Compose commands to configured
projects. A separate, startup-only God Mode can intentionally grant unrestricted host
administration. Read [SECURITY.md](SECURITY.md) before deploying either mode.

## Quick start

Requirements: Docker Engine with Docker Compose. No Go runtime or host agent is
required.

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/remoteops_bootstrap_password
chmod 600 secrets/remoteops_bootstrap_password
export REMOTEOPS_BOOTSTRAP_EMAIL="admin@example.com"
docker compose -f docker-compose.safe.yml up -d --build
curl http://127.0.0.1:8080/health
```

`oauth-local` is the runtime default and the normal safe/God Mode Compose
authentication mode. An existing configuration that explicitly sets
`auth.mode: bearer` remains in bearer mode until the operator changes it.

The safe example binds to loopback, mounts the Docker socket, exposes `./managed` as
the single managed root, persists audit/change/OAuth data in a named volume, and uses
`remoteops.example.yaml`. Copy that file and set `REMOTEOPS_CONFIG_FILE` when adding
real Compose projects, changing permissions, or changing the public HTTPS origin:

```sh
cp remoteops.example.yaml remoteops.yaml
export REMOTEOPS_CONFIG_FILE=./remoteops.yaml
docker compose -f docker-compose.safe.yml up -d
```

Put a TLS reverse proxy such as HAProxy, Caddy, nginx, or Traefik in front of the
service. Forward `/mcp`, `/mcp/*`, `/.well-known/*`, `/oauth/*`, and `/health` without rewriting paths. Do not publish RemoteOps as
plaintext HTTP on the public internet.

## Endpoints and authentication

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `POST /mcp` | OAuth access token | Stateless Streamable HTTP MCP |
| `GET /health` | None | Process liveness; contains no secrets |
| `GET /mcp/ready` | OAuth access token | Docker-backed readiness |
| `GET /.well-known/*` | None | MCP/OAuth discovery metadata |
| `/oauth/*` | OAuth flow | Registration, authorization, token and revocation |
| `/oauth/login`, `/oauth/account`, `/oauth/account/*` | Local browser session | Sign-in and account management |
| `/oauth/admin/*` | Local admin session | User, role, password and session administration |

Clients connect to `https://remoteops.example/mcp`. RemoteOps advertises its embedded
OAuth server, dynamically registers an allowlisted public client, and shows the local
login page. Access tokens are short-lived and audience-bound; refresh tokens rotate
and are revoked as a family on replay. Credentials are stored only as hashes.

First startup creates one administrator from `REMOTEOPS_BOOTSTRAP_EMAIL` and the
Docker secret. After changing the temporary password, that administrator manages
individual accounts at `/oauth/admin/users`. Disabling a user, changing a role/password,
or revoking sessions immediately invalidates that user's sessions and OAuth tokens.

Static bearer authentication is an explicit opt-in for automation and emergency
rollback through `remoteops.bearer.example.yaml` and `docker-compose.bearer.yml`; it
is not recommended for interactive ChatGPT/Claude users.

## Configuration

RemoteOps strictly parses `/config/remoteops.yaml`; unknown keys and invalid values
stop startup. Secrets come from environment variables. `REMOTEOPS_CONFIG` can select a
different in-container path.

Key sections in [remoteops.example.yaml](remoteops.example.yaml):

- `server`: name and listen address.
- `auth.oauth_local`: public origin, data file, bootstrap secret sources, exact
  redirect allowlist, and token/session lifetimes.
- `docker`: enablement and Docker API URI.
- `filesystem.roots`: named absolute roots; `/` is rejected.
- `compose.projects`: named absolute project directories and Compose files.
- `permissions.default_role`: `viewer`, `operator`, or `admin`.
- `changes`: retention days and maximum records.
- `limits`: request, file, log, execution, and rate bounds.

Normal file operations reject absolute paths, `..` traversal, and symlinks escaping a
configured root. Compose tools accept only configured project and service names;
callers cannot append arbitrary Compose arguments.

## Roles

- `viewer`: Docker/Compose/file/configuration inspection and change history.
- `operator`: viewer access plus lifecycle actions, deployments, managed changes, and
  conflict-safe rollback.
- `admin`: all configured Normal Mode permissions, including secret reveal and forced rollback.

Every handler checks permissions server-side. Tool visibility is not the security
boundary. Requests are rate-limited per actor and mutations serialize per target.

## MCP tools

| Area | Tools |
| --- | --- |
| Server | `remoteops_info`, `system_summary` |
| Docker | `docker_list`, `docker_inspect`, `docker_logs`, `docker_stats`, `docker_restart`, `docker_start`, `docker_stop`, `docker_pull`, `docker_image_info` |
| Compose | `compose_projects`, `compose_status`, `compose_logs`, `compose_validate`, `compose_pull`, `compose_up`, `compose_restart`, `compose_stop` |
| Files | `file_list`, `file_read`, `file_exists`, `file_stat`, `file_diff`, `file_patch`, `file_write` |
| YAML | `yaml_get`, `yaml_preview_change`, `yaml_set`, `yaml_delete` |
| dotenv | `env_get`, `env_list`, `env_set`, `env_delete` |
| Operations | `service_health`, `diagnose_service`, `deploy_service` |
| Changes | `changes_list`, `change_get`, `change_diff`, `change_rollback` |
| God Mode | `godmode_shell` only when enabled at startup |

Responses are structured and bounded. Errors use stable codes such as
`PERMISSION_DENIED`, `PATH_OUTSIDE_ALLOWED_ROOT`, `LIMIT_EXCEEDED`,
`ROLLBACK_CONFLICT`, and `GODMODE_DISABLED` instead of exposing stack traces.

## Changes, backups, and rollback

Managed file, YAML, and dotenv writes use temporary files plus atomic rename. They
record SHA-256 before/after hashes and backups under:

```text
/data/changes/<change-id>/
  metadata.json
  before
  after
  diff.patch
```

Rollback succeeds only when the current target still matches the recorded after hash.
If another modification produced state C after RemoteOps changed A to B, rollback
returns `ROLLBACK_CONFLICT`. Only an admin can explicitly force it. Audit events are
append-only JSON lines in `/data/audit.jsonl` and include denied and failed actions.

## Deployments and health

`deploy_service` serializes work per project/service, validates Compose, records the
previous image in its result, pulls, recreates, waits for the expected service,
verifies health, and returns recent bounded logs on failure. Health checks prefer
Docker HEALTHCHECK, followed by configured HTTP/TCP probes, then running state.
If an image is supplied, it must exactly match the image configured for that Compose
service; RemoteOps does not rewrite Compose files implicitly.

## God Mode

God Mode is disabled by default and enabled only by the exact startup value
`REMOTEOPS_GODMODE=true`. It cannot be changed through MCP or YAML. When false,
`godmode_shell` is absent from the advertised tools. When true, the separate tool uses
`nsenter` to execute in host PID 1 namespaces with time and output bounds. It
intentionally has no command denylist and can destroy or reboot the host.

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/remoteops_bootstrap_password
chmod 600 secrets/remoteops_bootstrap_password
export REMOTEOPS_BOOTSTRAP_EMAIL="admin@example.com"
docker compose -f docker-compose.godmode.yml up -d --build
```

The God Mode file uses privileged mode, the host PID namespace, Docker socket, and a
host-root mount. Normal structured tools remain constrained in this deployment.

## Development

Canonical checks use Docker so the host needs no Go installation:

| Task | Command |
| --- | --- |
| Dependencies | `docker run --rm -v "$PWD:/src" -w /src golang:1.25-alpine go mod tidy` |
| Format | `docker run --rm -v "$PWD:/src" -w /src golang:1.25-alpine gofmt -w .` |
| Test and vet | `docker build --target test .` |
| Build | `docker build -t remoteops-mcp:local .` |
| Run | `docker compose -f docker-compose.safe.yml up -d --build` |

CI runs formatting verification, vet, race-enabled unit tests, a binary build,
container build, and both Compose validations. Docker integration and isolated host
namespace tests must run only on disposable Linux infrastructure.

## Troubleshooting

- `401 UNAUTHENTICATED`: confirm the client completed OAuth and inspect the
  `WWW-Authenticate` resource-metadata URL.
- `OAuth store is empty`: set the bootstrap email and create the Docker secret.
- OAuth callback rejected: add the exact current HTTPS callback URI to
  `allowed_redirect_uris`; wildcards and fragments are rejected.
- `/oauth/login` returns 404: the loaded configuration explicitly uses
  `auth.mode: bearer`; change it to `oauth-local` (or start from
  `remoteops.example.yaml`) and recreate the container.
- OAuth fails through HAProxy: forward every discovery, OAuth, login, account, and
  admin path listed above, not only `/mcp`.
- `Docker is unavailable`: confirm the socket mount, URI, and permissions.
- `PATH_OUTSIDE_ALLOWED_ROOT`: use a configured root and safe relative path.
- Compose project not found: configure and mount it at the same absolute container path.
- `ROLLBACK_CONFLICT`: inspect `change_diff` and current state before an admin forces it.

For production, pin `REMOTEOPS_IMAGE` to an immutable digest, back up `/data`, pull the
reviewed image, and recreate the service.
