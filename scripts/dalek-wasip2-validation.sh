#!/usr/bin/env bash
set -euo pipefail

CARGO_COMPONENT_VERSION="0.21.1"
WASM_TOOLS_VERSION="1.253.0"
CARGO_AUDIT_VERSION="0.22.2"
CARGO_DENY_VERSION="0.20.2"
FIXTURE_MANIFEST="crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml"
FIXTURE_LOCK="crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.lock"
# Stable source-repo name for the Matrix crypto wasip2 feasibility gate.
# cargo-component 0.21.1 accepts wasm32-wasip2 here but emits the component
# under the wasm32-wasip1 target directory after adapting the core module.
COMPONENT_WASM="crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/target/wasm32-wasip1/release/dalek_wasip2_component.wasm"
LOG_DIR="target/dalek-wasip2-validation/logs"
RUN_ID="${RUN_ID:-local}"
RESULT_PATH="${LOG_DIR}/${RUN_ID}-result.json"
JSONL_PATH="${LOG_DIR}/${RUN_ID}.jsonl"
WIT_PATH="${LOG_DIR}/${RUN_ID}.wit"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    return 1
  fi
}

command_version() {
  if "$@" --version >/dev/null 2>&1; then
    "$@" --version | head -n 1
  else
    echo "unavailable"
  fi
}

sha256_or_zero() {
  if [ -f "$1" ]; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    printf '0000000000000000000000000000000000000000000000000000000000000000\n'
  fi
}

write_blocker_result() {
  local phase="$1"
  local error_code="$2"
  local summary="$3"
  local source_branch
  local source_commit
  source_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  source_commit="$(git rev-parse HEAD 2>/dev/null || echo 0000000)"

  python3 - "$RESULT_PATH" "$JSONL_PATH" "$phase" "$error_code" "$summary" \
    "$source_branch" "$source_commit" "$(sha256_or_zero "$COMPONENT_WASM")" \
    "$(sha256_or_zero "$FIXTURE_LOCK")" "$(command_version rustc)" \
    "$(command_version cargo)" "$(cargo component --version 2>/dev/null | head -n 1 || echo unavailable)" \
    "$(wasm-tools --version 2>/dev/null | head -n 1 || echo unavailable)" <<'PY'
import json
import pathlib
import sys

(
    result_path,
    jsonl_path,
    phase,
    error_code,
    summary,
    source_branch,
    source_commit,
    component_sha,
    lock_sha,
    rustc_version,
    cargo_version,
    cargo_component_version,
    wasm_tools_version,
) = sys.argv[1:]

result = {
    "schema_version": 1,
    "validation_name": "Dalek WASI Preview 2",
    "validation_status": "blocker",
    "source_branch": source_branch,
    "source_commit": source_commit,
    "validation_package": "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component",
    "component_wasm_sha256": component_sha,
    "wit_package": "near:agent/sandboxed-tool@0.3.0",
    "toolchain_versions": {
        "rustc": {"version": rustc_version, "pin_source": "workspace package rust-version"},
        "cargo": {"version": cargo_version, "pin_source": "workspace package rust-version"},
        "cargo_component": {"version": cargo_component_version, "pin_source": ".github/actions/install-cargo-component/action.yml"},
        "wasm_tools": {"version": wasm_tools_version, "pin_source": "scripts/dalek-wasip2-validation.sh"},
        "wasmtime": {"version": "46.0.1", "pin_source": "workspace dependencies"},
        "wasm_opt": {"version": None, "pin_source": None},
    },
    "dependency_config": {
        "cargo_lock_sha256": lock_sha,
        "crates": [
            {"name": "vodozemac", "version": "=0.10.0", "features": [], "default_features": False, "source": "registry"},
            {"name": "ed25519-dalek", "version": "=3.0.0", "features": ["alloc", "fast", "zeroize"], "default_features": False, "source": "registry"},
            {"name": "x25519-dalek", "version": "=3.0.0", "features": ["getrandom", "static_secrets", "zeroize"], "default_features": False, "source": "registry"},
            {"name": "getrandom", "version": "=0.4.3", "features": [], "default_features": False, "source": "registry"},
        ],
    },
    "test_summary": {"group_a": "fail", "group_b": "skipped", "group_c": "skipped", "group_d": "skipped"},
    "failure_modes": [{"phase": phase, "error_code": error_code, "classification": "blocker", "sanitized_summary": summary}],
    "resource_observations": {
        "success_profile": {"memory_limit_bytes": 1, "stack_limit_bytes": 1, "fuel_or_epoch_limit": "not reached"},
        "too_low_failure_profile": {"memory_limit_bytes": 1, "stack_limit_bytes": 1, "fuel_or_epoch_limit": "not reached", "error_code": "resource_limit_exceeded"},
        "steady_state_ed25519_relative_to_native": "not reached",
        "steady_state_x25519_relative_to_native": "not reached",
        "component_size_bytes": 1,
    },
    "log_artifacts": {"schema_version": 1, "path_or_ci_artifact": jsonl_path, "retention_policy": "CI artifact dalek-wasip2-validation retained by workflow defaults", "redaction_status": "passed"},
    "fallback_contract": {"required": False, "trigger_criteria": [], "wit_namespace": None, "wit_world": None, "wit_imports": [], "operations_moved_to_host": [], "operations_remaining_in_component": [], "key_material_boundary": None, "host_storage_owner": None, "authorization_scope": None, "audit_events": [], "zeroization_expectation": None},
    "downstream_action": "block",
    "binding_artifacts": [
        "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml",
        "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.lock",
        "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-result.schema.json",
        "crates/ironclaw_wasm/tests/dalek_wasip2_validation.rs",
    ],
    "reproduction_commands": ["scripts/dalek-wasip2-validation.sh"],
}

record = {
    "phase": phase,
    "operation": "validation-script",
    "status": "fail",
    "error_code": error_code,
    "error_class": "blocker",
    "message": summary,
    "component_sha256": component_sha,
    "wasmtime_version": "46.0.1",
    "iteration_count": 1,
    "memory_limit_bytes": 0,
    "stack_limit_bytes": 0,
}

pathlib.Path(result_path).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(jsonl_path).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(result_path).write_text(json.dumps(result, indent=2) + "\n")
pathlib.Path(jsonl_path).write_text(json.dumps(record) + "\n")
PY
}

run_phase() {
  local phase="$1"
  local error_code="$2"
  local summary="$3"
  shift 3
  if ! "$@"; then
    write_blocker_result "$phase" "$error_code" "$summary"
    exit 1
  fi
}

extract_wit() {
  wasm-tools component wit "${COMPONENT_WASM}" > "${WIT_PATH}"
}

check_component_output() {
  test -s "${COMPONENT_WASM}"
}

check_fixture_lock_clean() {
  git diff --quiet -- "${FIXTURE_LOCK}"
}

check_wit_imports() {
  grep -q 'import near:agent/host@0.3.0' "${WIT_PATH}"
  grep -q 'export near:agent/tool@0.3.0' "${WIT_PATH}"
  grep -q 'import wasi:random/random@0.2.3' "${WIT_PATH}"
}

run_runtime_validation() {
  DALEK_WASIP2_REQUIRE_COMPONENT=1 \
  DALEK_WASIP2_RESULT_PATH="${RESULT_PATH}" \
  DALEK_WASIP2_LOG_PATH="${JSONL_PATH}" \
  DALEK_WASIP2_COMPONENT_SHA256="$(shasum -a 256 "${COMPONENT_WASM}" | awk '{print $1}')" \
    cargo test -p ironclaw_wasm --test dalek_wasip2_validation -- --nocapture
}

need_cmd cargo
need_cmd python3

mkdir -p "${LOG_DIR}"

if ! cargo component --version 2>/dev/null | grep -q "${CARGO_COMPONENT_VERSION}"; then
  echo "cargo-component ${CARGO_COMPONENT_VERSION} is required; CI installs it via .github/actions/install-cargo-component" >&2
  write_blocker_result "toolchain" "toolchain_mismatch" "cargo-component ${CARGO_COMPONENT_VERSION} is required"
  exit 1
fi

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "installing wasm-tools ${WASM_TOOLS_VERSION}" >&2
  cargo install wasm-tools --version "${WASM_TOOLS_VERSION}" --locked
fi

if ! wasm-tools --version | grep -q "${WASM_TOOLS_VERSION}"; then
  echo "wasm-tools ${WASM_TOOLS_VERSION} is required, found: $(wasm-tools --version)" >&2
  write_blocker_result "toolchain" "toolchain_mismatch" "wasm-tools ${WASM_TOOLS_VERSION} is required"
  exit 1
fi

if ! cargo audit --version 2>/dev/null | grep -q "${CARGO_AUDIT_VERSION}"; then
  echo "installing cargo-audit ${CARGO_AUDIT_VERSION}" >&2
  cargo install cargo-audit --version "${CARGO_AUDIT_VERSION}" --locked
fi

if ! cargo deny --version 2>/dev/null | grep -q "${CARGO_DENY_VERSION}"; then
  echo "installing cargo-deny ${CARGO_DENY_VERSION}" >&2
  cargo install cargo-deny --version "${CARGO_DENY_VERSION}" --locked
fi

run_phase "dependency-audit" "audit_failed" "cargo audit failed for the committed fixture lockfile" \
  cargo audit --file "${FIXTURE_LOCK}"
run_phase "dependency-deny" "deny_failed" "cargo deny failed for the committed fixture manifest" \
  cargo deny --manifest-path "${FIXTURE_MANIFEST}" check advisories licenses bans sources
run_phase "component-build" "build_failed" "cargo-component failed to build the fixture with the committed lockfile" \
  cargo component build --release --locked --target wasm32-wasip2 --manifest-path "${FIXTURE_MANIFEST}"
run_phase "lockfile-check" "lockfile_drift" "fixture Cargo.lock changed during validation" \
  check_fixture_lock_clean
run_phase "component-build" "component_missing" "cargo-component did not write the expected adapted component artifact" \
  check_component_output
run_phase "wit-validation" "wit_mismatch" "wasm-tools component validation failed" \
  wasm-tools validate "${COMPONENT_WASM}" --features component-model
run_phase "wit-extraction" "wit_mismatch" "wasm-tools component WIT extraction failed" \
  extract_wit
run_phase "wit-validation" "wit_mismatch" "component WIT did not expose the required imports and exports" \
  check_wit_imports
run_phase "runtime-validation" "runtime_validation_failed" "host runtime validation failed" \
  run_runtime_validation
run_phase "source-safety" "source_safety_failed" "pre-commit safety checks failed" \
  scripts/pre-commit-safety.sh

test -s "${RESULT_PATH}"
test -s "${JSONL_PATH}"

echo "Dalek WASI Preview 2 validation complete."
echo "Result: ${RESULT_PATH}"
echo "Logs: ${JSONL_PATH}"
