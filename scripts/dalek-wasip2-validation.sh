#!/usr/bin/env bash
set -euo pipefail

CARGO_COMPONENT_VERSION="0.21.1"
WASM_TOOLS_VERSION="1.253.0"
CARGO_AUDIT_VERSION="0.22.2"
CARGO_DENY_VERSION="0.20.2"
FIXTURE_MANIFEST="crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml"
FIXTURE_LOCK="crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.lock"
# cargo-component 0.21.1 accepts wasm32-wasip2 here but emits the component
# under the wasm32-wasip1 target directory after adapting the core module.
COMPONENT_WASM="crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/target/wasm32-wasip1/release/dalek_wasip2_component.wasm"
LOG_DIR="target/dalek-wasip2-validation/logs"
RUN_ID="${RUN_ID:-local}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    return 1
  fi
}

need_cmd cargo

if ! cargo component --version 2>/dev/null | grep -q "${CARGO_COMPONENT_VERSION}"; then
  echo "cargo-component ${CARGO_COMPONENT_VERSION} is required; CI installs it via .github/actions/install-cargo-component" >&2
  exit 1
fi

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "installing wasm-tools ${WASM_TOOLS_VERSION}" >&2
  cargo install wasm-tools --version "${WASM_TOOLS_VERSION}" --locked
fi

if ! wasm-tools --version | grep -q "${WASM_TOOLS_VERSION}"; then
  echo "wasm-tools ${WASM_TOOLS_VERSION} is required, found: $(wasm-tools --version)" >&2
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

mkdir -p "${LOG_DIR}"

cargo generate-lockfile --manifest-path "${FIXTURE_MANIFEST}"
cargo audit --file "${FIXTURE_LOCK}"
cargo deny --manifest-path "${FIXTURE_MANIFEST}" check advisories licenses bans sources
cargo component build --release --target wasm32-wasip2 --manifest-path "${FIXTURE_MANIFEST}"
wasm-tools validate "${COMPONENT_WASM}" --features component-model
wasm-tools component wit "${COMPONENT_WASM}" > "${LOG_DIR}/${RUN_ID}.wit"
grep -q 'import near:agent/host@0.3.0' "${LOG_DIR}/${RUN_ID}.wit"
grep -q 'export near:agent/tool@0.3.0' "${LOG_DIR}/${RUN_ID}.wit"
grep -q 'import wasi:random/random@0.2.3' "${LOG_DIR}/${RUN_ID}.wit"
cargo test -p ironclaw_wasm --test dalek_wasip2_validation -- --nocapture
scripts/pre-commit-safety.sh

cat > "${LOG_DIR}/${RUN_ID}.jsonl" <<JSONL
{"phase":"dalek-wasip2","operation":"validation-script","status":"pass","error_code":null,"error_class":null,"message":"Dalek WASI Preview 2 validation script completed","component_sha256":"$(shasum -a 256 "${COMPONENT_WASM}" | awk '{print $1}')","wasmtime_version":"46.0.1","iteration_count":1,"memory_limit_bytes":1048576,"stack_limit_bytes":1048576}
JSONL

echo "Dalek WASI Preview 2 validation complete. Logs: ${LOG_DIR}/${RUN_ID}.jsonl"
