# Account connection details

## Outcome

Signed-in users can retrieve the MCP URL and connection settings from their account
page.

## Constraints

- Derive the URL from the configured public origin, never request headers.
- Show only non-secret settings and preserve the existing authenticated boundary.
- Keep connection details discoverable for administrators.

## Steps

- [x] Render MCP connection details on the account page.
- [x] Link administrators to their account page.
- [x] Add regression coverage and update user documentation.
- [x] Run the relevant and documented checks where practical.

## Verification

- `docker run --rm -v ${PWD}:/src -w /src golang:1.25-alpine go test ./internal/oauthui`
- `docker build --target test .`
