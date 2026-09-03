# OAuth consent UI

## Outcome

The OAuth authorization screen matches the polished RemoteOps account experience and
clearly explains the client, signed-in identity, role boundary, and requested access.

## Constraints

- Preserve the existing authorization, denial, CSRF, and transaction behavior.
- Keep account and client values escaped.
- Keep styles protected by a fresh CSP nonce.

## Steps

- [x] Share the existing OAuth visual foundation with the consent page.
- [x] Redesign the consent content and actions.
- [x] Test escaping, CSP nonce binding, and OAuth form fields.
- [x] Run the full suite and deploy the verified revision.

## Verification

- `docker build --target test .`
- Live container health and public OAuth flow checks.
