# OAuth administration UI

## Outcome

Make repeated user creation clear and reliable while preserving the administrator
password confirmation required for account changes.

## Constraints

- Keep all account authorization and CSRF checks server-side.
- Keep the UI dependency-free and compatible with the restrictive CSP.
- Do not weaken the current-password requirement for high-impact mutations.

## Steps

- [x] Add a cohesive responsive visual treatment for the OAuth pages.
- [x] Separate new-user credentials from administrator confirmation in the form.
- [x] Return actionable mutation failures in the administration page.
- [x] Cover repeated user creation and the rendered error state with tests.
- [x] Update operator documentation and run the documented checks.

## Verification

- `docker build --target test .`
- `docker build -t remoteops-mcp:local .`
