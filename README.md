# theredspoon/ironclaw CI Automation Branch

**⚠️ This is NOT a product source branch.**

This branch contains automation workflows only. It is the default branch for `theredspoon/ironclaw` to enable scheduled workflow execution.

## What This Branch Contains

Three GitHub Actions workflows:

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| `sync-upstream.yml` | Hourly | Syncs `nearai/ironclaw:main` → creates PRs to `native-matrix-channel-pilot` |
| `mirror-to-deployment-target.yml` | On push to `native-matrix-channel-pilot` | Mirrors reviewed source → deployment target |
| `auto-ff-matrix-pilot-sync.yml` | After PR CI passes | Auto-merges sync PRs when tests pass |

## Product Branches

For product work, use these branches:

| Branch | Purpose |
|--------|---------|
| `upstream-main` | Mirror of `nearai/ironclaw:main` |
| `native-matrix-channel-pilot` | Matrix pilot source |
| `matrix-channel-clean` | Upstream contribution queue |

## Maintenance

**Do not merge upstream `nearai/ironclaw:main` into this branch.** The workflows here are fork-specific and do not exist upstream.

Do not commit product code to this branch. Use `native-matrix-channel-pilot` or `matrix-channel-clean` instead.

## References

- [nearai/ironclaw upstream repository](https://github.com/nearai/ironclaw)
