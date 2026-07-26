# theredspoon/ironclaw CI Automation Branch

**⚠️ This is NOT a product source branch.**

This branch contains automation workflows only. It is the default branch for `theredspoon/ironclaw` to enable scheduled workflow execution.

## What This Branch Contains

Two GitHub Actions workflows:

| Workflow | Event | Purpose |
|----------|-------|---------|
| `sync-upstream.yml` | Hourly | Fast-forwards the exact `nearai/ironclaw:main` mirror |
| `mirror-to-deployment-target.yml` | Manual dispatch | Mirrors reviewed pilot source to the deployment target |

## Product Branches

For product work, use these branches:

| Branch | Purpose |
|--------|---------|
| `upstream-main` | Mirror of `nearai/ironclaw:main` |
| `reborn-matrix-pilot` | Reborn Matrix pilot source |
| `matrix-channel-clean` | Upstream contribution queue |

## Maintenance

**Do not merge upstream `nearai/ironclaw:main` into this branch.** The workflows here are fork-specific and do not exist upstream.

Do not commit product code to this branch. Use `reborn-matrix-pilot` or
`matrix-channel-clean` instead.

## References

- [nearai/ironclaw upstream repository](https://github.com/nearai/ironclaw)
