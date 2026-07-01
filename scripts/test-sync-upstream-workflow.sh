#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

workflow=".github/workflows/sync-upstream.yml"

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

require 'name:[[:space:]]*Sync upstream' "workflow name"
require 'workflow_dispatch:' "manual dispatch trigger"
require 'schedule:' "scheduled trigger"
require 'github.repository == '"'"'theredspoon/ironclaw'"'"'' "repo guard"
require 'actions/create-github-app-token@' "GitHub App token generation"
require 'PIPELINE_CONTROL_SYNC_CLIENT_ID' "sync app client ID"
require 'PIPELINE_CONTROL_SYNC_PRIVATE_KEY' "sync app private key"
require 'permission-contents:[[:space:]]*write' "App token contents write permission"
require 'permission-pull-requests:[[:space:]]*write' "App token pull requests write permission"
require 'permission-workflows:[[:space:]]*write' "App token workflows write permission"
require 'persist-credentials:[[:space:]]*false' "checkout credential isolation"
require 'git remote set-url origin "https://x-access-token:\$\{APP_TOKEN\}@github.com/\$\{GITHUB_REPOSITORY\}\.git"' "authenticated origin rewrite"
require 'UPSTREAM_MIRROR_BRANCH:[[:space:]]*upstream-main' "upstream mirror branch"
require 'INTEGRATION_BRANCH:[[:space:]]*native-matrix-channel-pilot' "Matrix pilot branch"
require 'SYNC_BRANCH:[[:space:]]*sync/native-matrix-pilot' "sync branch"
require 'git fetch --no-tags upstream.*refs/heads/main' "upstream main fetch"
require 'git push origin "upstream/main:refs/heads/\$\{UPSTREAM_MIRROR_BRANCH\}"' "workflow-capable mirror push"
require 'git merge --no-edit --allow-unrelated-histories -X theirs "origin/\$\{UPSTREAM_MIRROR_BRANCH\}"' "upstream-wins unrelated-history import"
require 'crates/ironclaw_reborn/src/local_trigger_access\.rs' "stale local trigger module prune"
require 'crates/ironclaw_turns/src/memory\.rs' "stale memory module prune"
require 'crates/ironclaw_memory/tests/repo_in_memory_contract\.rs' "stale memory contract test prune"
require 'crates/ironclaw_memory/tests/memory_filesystem_contract\.rs' "stale memory filesystem contract test prune"
require 'git rm -f --ignore-unmatch "\$\{stale_module\}"' "stale module removal"
require "grep -Fq 'Downstream sync exception: nearai/main currently tracks these' .gitignore" "idempotent ignore exception guard"
require '!\.claude/\*\*' "tracked Claude asset ignore exception"
require '!crates/ironclaw_webui_v2_static/static/dist/\*\*' "tracked WebUI bundle ignore exception"
require 'git commit -m "ci: normalize upstream import"' "normalization commit"
require 'git push origin "HEAD:refs/heads/\$\{SYNC_BRANCH\}" --force-with-lease' "lease-protected sync branch push"
require 'GH_TOKEN:[[:space:]]*\$\{\{ steps\.app_token\.outputs\.token \}\}' "PR operations use app token"
require 'gh api --method POST "repos/\$\{GITHUB_REPOSITORY\}/pulls"' "REST pull request creation"
require '-f head="\$\{GITHUB_REPOSITORY_OWNER\}:\$\{SYNC_BRANCH\}"' "owned sync branch PR head"
require 'imports it into \\\`\$\{INTEGRATION_BRANCH\}\\\` for CI with upstream source winning unrelated-history conflicts' "import policy PR body"

reject 'GH_TOKEN:[[:space:]]*\$\{\{ secrets\.GITHUB_TOKEN \}\}' "default token for PR operations"
reject 'permissions:[[:space:]]*$[^#]*contents:[[:space:]]*write' "workflow-level contents write"
reject 'gh pr create' "GraphQL pull request creation"

echo "sync-upstream workflow contract OK"
