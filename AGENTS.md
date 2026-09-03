# Agent working agreement

This file defines the default operating rules for every agent working in this
repository. More specific `AGENTS.md` files may be added inside subdirectories
later; the closest file to the code being changed takes precedence.

## Start here

1. Read `README.md` and any relevant files under `docs/`.
2. Inspect the working tree before editing. Existing changes belong to the user.
3. For work spanning multiple files or involving design choices, create or update
   a short plan in `docs/plans/` before implementation.
4. Prefer the smallest complete change that satisfies the request.

## Repository state

Agent Smith is a Go 1.25 service built and verified through Docker. Do not require a
host Go installation.

## Canonical commands

- Format: `docker run --rm -v "$PWD:/src" -w /src golang:1.25-alpine gofmt -w .`
- Test and vet: `docker build --target test .`
- Build: `docker build -t remoteops-mcp:local .`
- Validate safe deployment: `docker compose -f docker-compose.safe.yml config`
- Validate God Mode deployment: `docker compose -f docker-compose.godmode.yml config`

## Working rules

- Keep changes scoped to the requested outcome; do not clean up unrelated code.
- Search before adding new concepts, dependencies, or duplicate utilities.
- Match existing structure and style once conventions exist.
- Add or update tests for behavior changes when a test framework is available.
- Treat warnings and failing checks introduced by your change as defects.
- Never commit credentials, tokens, private keys, `.env` files, or production data.
- Record durable architectural decisions in `docs/decisions/`.
- Update documentation when behavior, setup, commands, or architecture changes.
- Avoid generated files unless they are intentionally version-controlled.

## Verification

Before handing work back:

1. Review the diff for accidental or unrelated edits.
2. Run the narrowest relevant checks, then the full documented check suite when
   practical.
3. Report what changed, which checks ran, and any remaining risks or blockers.

## Definition of done

A change is complete when the requested behavior is implemented, relevant checks
pass, documentation reflects the result, and no known regression is left hidden.
