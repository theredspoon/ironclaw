#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

workflow=".github/workflows/auto-ff-matrix-pilot-sync.yml"
mirror_workflow=".github/workflows/mirror-to-deployment-target.yml"

if [[ ! -f "${workflow}" ]]; then
    echo "missing ${workflow}"
    exit 1
fi

if [[ ! -f "${mirror_workflow}" ]]; then
    echo "missing ${mirror_workflow}"
    exit 1
fi

require_in() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    if ! grep -Eq -- "${pattern}" "${file}"; then
        echo "missing ${description}: ${pattern}"
        exit 1
    fi
}

require_in "${workflow}" 'name:[[:space:]]*Auto fast-forward Matrix pilot sync' "workflow name"
require_in "${workflow}" 'workflow_run:' "workflow-run trigger"
require_in "${workflow}" 'actions:[[:space:]]*write' "Actions write permission for workflow dispatch"
require_in "${workflow}" 'BASE_BRANCH:[[:space:]]*native-matrix-channel-pilot' "Matrix pilot branch"
require_in "${workflow}" 'git push origin "\$\{actual_head\}:refs/heads/\$\{BASE_BRANCH\}"' "pilot branch fast-forward"
require_in "${workflow}" 'name:[[:space:]]*Dispatch deployment mirror' "post-fast-forward mirror dispatch step"
require_in "${workflow}" 'GH_TOKEN:[[:space:]]*\$\{\{ github\.token \}\}' "dispatch token"
require_in "${workflow}" 'gh workflow run mirror-to-deployment-target\.yml' "explicit deployment mirror dispatch"
require_in "${workflow}" '--ref "\$\{GITHUB_REF_NAME\}"' "control-plane workflow dispatch ref"
require_in "${workflow}" '-f "source_ref=\$\{BASE_BRANCH\}"' "mirror source ref dispatch input"
require_in "${mirror_workflow}" 'workflow_dispatch:' "manual mirror dispatch trigger"
require_in "${mirror_workflow}" 'source_ref:' "manual mirror source ref input"
require_in "${mirror_workflow}" 'SOURCE_REF:[[:space:]]*\$\{\{ github\.event\.inputs\.source_ref \|\| github\.ref_name \}\}' "source ref selection"
require_in "${mirror_workflow}" 'ref:[[:space:]]*\$\{\{ github\.event\.inputs\.source_ref \|\| github\.ref_name \}\}' "source checkout ref"
require_in "${mirror_workflow}" 'MIRRORED_SOURCE_SHA=\$\(git rev-parse HEAD\)' "source sha captured before mirror mutation"
require_in "${mirror_workflow}" 'name:[[:space:]]*Preserve deployment target-owned workflows' "deployment target workflow overlay step"
require_in "${mirror_workflow}" 'target_owned_workflows=\(' "target-owned workflow allowlist"
require_in "${mirror_workflow}" '\.github/workflows/pilot-linux-artifact\.yml' "pilot artifact workflow restored"
require_in "${mirror_workflow}" '\.github/workflows/regression-test-check\.yml' "regression check workflow restored"
require_in "${mirror_workflow}" 'git checkout "refs/remotes/deployment_mirror/\$\{TARGET_BRANCH\}" -- "\$\{target_owned_workflows\[@\]\}"' "deployment target-owned workflows restored"
require_in "${mirror_workflow}" 'Deploy Matrix pilot source \$\{MIRRORED_SOURCE_SHA:0:12\}' "deployment commit uses mirrored source sha"
require_in "${mirror_workflow}" '\[skip-regression-check\]' "deployment mirror regression-check skip marker"
require_in "${mirror_workflow}" 'branches:' "push trigger branch restriction"
require_in "${mirror_workflow}" 'native-matrix-channel-pilot' "Matrix pilot push trigger"

echo "auto-ff Matrix pilot workflow contract OK"
