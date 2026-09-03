# New-user landing page

## Outcome

After changing a first-login password, non-admin users land on their own account page
instead of being redirected to the admin-only user list.

## Constraints

- Preserve OAuth transaction continuations.
- Keep the administration page restricted to administrators.
- Reuse the nonce-protected OAuth UI styling.

## Steps

- [x] Add an authenticated account landing page.
- [x] Route non-admin logins and password changes to that page when no OAuth transaction exists.
- [x] Add regression tests and deploy the verified revision.

## Verification

- `docker build --target test .`
- Live container health and public OAuth response checks.
