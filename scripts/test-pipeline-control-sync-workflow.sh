#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

workflow=".github/workflows/sync-pipeline-control.yml"

if [[ ! -f "${workflow}" ]]; then
    echo "missing ${workflow}"
    exit 1
fi

require() {
    local pattern="$1"
    local description="$2"
    if ! grep -Eq -- "${pattern}" "${workflow}"; then
        echo "missing ${description}: ${pattern}"
        exit 1
    fi
}

reject() {
    local pattern="$1"
    local description="$2"
    if grep -Eq -- "${pattern}" "${workflow}"; then
        echo "forbidden ${description}: ${pattern}"
        exit 1
    fi
}

require 'name:[[:space:]]*Sync pipeline-control with upstream' "workflow name"
require 'workflow_dispatch:' "manual dispatch trigger"
require 'schedule:' "scheduled trigger"
require 'github.repository == '"'"'theredspoon/ironclaw'"'"'' "repo guard"
require 'actions/create-github-app-token@' "GitHub App token generation"
require 'permission-contents:[[:space:]]*write' "App token contents write permission"
require 'permission-pull-requests:[[:space:]]*write' "App token pull requests write permission"
require 'permission-issues:[[:space:]]*write' "App token issues write permission"
require 'SYNC_BRANCH:[[:space:]]*sync/pipeline-control-upstream' "sync branch"
require 'BASE_BRANCH:[[:space:]]*pipeline-control' "base branch"
require 'git remote add upstream https://github.com/nearai/ironclaw.git' "nearai upstream remote"
require 'git fetch --no-tags upstream.*refs/heads/main' "upstream main fetch"
require 'git checkout -B.*\$[{(]?SYNC_BRANCH' "sync branch checkout"
require 'git merge --no-edit --allow-unrelated-histories -X theirs upstream/main' "upstream-wins unrelated-history import"
require 'import policy: upstream source wins on unrelated-history conflicts' "import policy diagnostic"
require 'git push --force-with-lease origin.*\$[{(]?SYNC_BRANCH' "lease-protected sync branch push"
require 'gh pr create.*--base "\$\{BASE_BRANCH\}".*--head "\$\{SYNC_BRANCH\}"' "PR creation into pipeline-control"
require 'gh pr edit' "existing PR update"
require 'Unable to import upstream/main into pipeline-control' "conflict diagnostic"
require 'gh issue create' "conflict issue creation"
require 'gh issue list' "conflict issue lookup"
require '--search "\$\{title\} in:title"' "conflict issue title search"
require 'gh issue comment' "existing conflict issue update"

reject 'refs/heads/pipeline-control' "direct pipeline-control ref update"
reject 'git push[^\\n]*(HEAD|upstream/main)[^\\n]*pipeline-control' "direct push to pipeline-control"

echo "pipeline-control sync workflow contract OK"
