# Runtime secrets

Create the bootstrap password file before the first OAuth startup:

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/remoteops_bootstrap_password
chmod 600 secrets/remoteops_bootstrap_password
export REMOTEOPS_BOOTSTRAP_EMAIL=admin@example.com
```

The password file is mounted as a Docker secret and is ignored by Git. It is used
only when `/data/oauth.db` has no users. After the administrator changes the
bootstrap password at first login, retaining this file does not reset the account.
Keep it root-readable only and retain it in your normal secret backup system because
the Compose deployment mounts it on every container start.
