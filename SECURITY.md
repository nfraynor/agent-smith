# Security policy

## Security model

RemoteOps is a highly sensitive administrative endpoint. Never publish its plain HTTP
port directly to the internet. Bind it to a private interface and place an
authenticated, rate-limited TLS reverse proxy in front of it.

The Docker socket is effectively root-equivalent access to the host. Normal Mode
reduces accidental and agent-driven risk through structured tools, configured Compose
projects, managed filesystem roots, permissions, bounds, locks, audit records, and
rollback. It does not turn the Docker socket into a security sandbox.

`docker-compose.godmode.yml` is intentionally unrestricted. It uses privileged mode,
the host PID namespace, the Docker socket, and a host-root mount. When and only when
`REMOTEOPS_GODMODE=true` at startup, RemoteOps registers `godmode_shell`, which can
alter or destroy the host, install software, change networking, stop services, or
reboot the machine. The flag cannot be changed through MCP. Treat any credential able
to reach that deployment as a host-root credential.

## Operational requirements

- Use a long, randomly generated bearer token and store it outside version control.
- Terminate TLS at a trusted reverse proxy and restrict source networks.
- Keep the default Viewer role unless mutation access is deliberately required.
- Mount only the directories and Compose projects RemoteOps must manage.
- Protect `/data`; it contains configuration backups and operational history.
- Review JSON audit records and rotate credentials after suspected exposure.
- Pin production images to an immutable digest and update deliberately.

## Reporting vulnerabilities

Do not open a public issue containing exploit details or credentials. Contact the
repository owner privately with the affected version, reproduction, and impact.
