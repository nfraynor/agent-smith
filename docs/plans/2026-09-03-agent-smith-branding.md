# Agent Smith branding

## Outcome

The product presents itself as Agent Smith in its browser UI, MCP metadata,
runtime messages, examples, and current operator documentation.

## Constraints

- Preserve established `REMOTEOPS_*` environment variables, configuration
  filenames, container resources, cookie names, and the `remoteops_info` tool name
  so existing deployments and clients continue to work.
- Treat those identifiers as legacy compatibility surfaces, not product copy.
- Leave historical implementation plans and architecture decision filenames intact.

## Steps

- [x] Replace browser-facing branding and update UI assertions.
- [x] Update MCP defaults, descriptions, example server names, and runtime copy.
- [x] Update current documentation while clearly identifying legacy identifiers.
- [x] Run focused tests, the documented full test target, and review the diff.

## Verification

- `rg -n "RemoteOps"` contains only compatibility explanations or historical records.
- `docker build --target test .`
- `docker compose -f docker-compose.safe.yml config`
- `docker compose -f docker-compose.godmode.yml config`
