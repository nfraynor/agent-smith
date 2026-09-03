# Account capability summary

## Outcome

Signed-in Viewer and Operator accounts see a concise summary of the operations their
role permits on the account page.

## Constraints

- Derive visibility from the server authorization policy instead of duplicating role
  checks in the template.
- Preserve the current Agent Smith branding and existing account actions.
- Describe capability groups rather than presenting an unfiltered MCP tool catalogue.

## Steps

- [x] Add permission-backed account capability definitions.
- [x] Render the permitted capability groups on the account page.
- [x] Test Viewer and Operator output and update account documentation.
- [x] Run the relevant and full documented checks where practical.

## Verification

- `docker run --rm -v "${PWD}:/src" -w /src golang:1.25-alpine go test ./internal/oauthui`
- `docker build --target test .`
