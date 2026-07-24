# theredspoon/ironclaw CI Automation Branch

**⚠️ This is NOT a product source branch.**

This branch contains automation workflows only. It is the default branch for `theredspoon/ironclaw` to enable scheduled workflow execution.

## What This Branch Contains

Three GitHub Actions workflows:

| Workflow | Event | Purpose |
|----------|-------|---------|
| `sync-upstream.yml` | Hourly | Fast-forwards the exact `nearai/ironclaw:main` mirror |
| `mirror-to-deployment-target.yml` | Manual dispatch | Mirrors reviewed pilot source to the deployment target |
| `review-authority.yml` | Pull requests targeting `reborn-matrix-pilot` | Protects the rules that decide whether a pilot pull request may merge |

## Review Authority

`Review Authority` is the stable required-check name for pull requests targeting
`reborn-matrix-pilot`. GitHub runs it with `pull_request_target` so the workflow
definition comes from this default branch, not from the pull request under
review.

The job checks out one exact, reviewed Lighthouse commit and runs its
deterministic review-authority guard. It passes the repository, pull request
number, and exact head commit as quoted data. The guard reads changed paths and
the candidate required-check policy through the GitHub API. The job never
checks out or executes pull request code.

The guard rejects changes to GitHub workflow and review-authority paths, and
this repository additionally protects `deny.toml`. An added or modified
`.github/review/required-check-policy.json` is read as inert content and must
pass Lighthouse's canonical schema and bounded runtime validation. It is not
used as the authority for the pull request that proposes it.

The workflow and its Lighthouse commit pin live on this automation-only default
branch. Product pull requests cannot weaken either one.

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
