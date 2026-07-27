#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

components=(
  "ironclaw_matrix_product_adapter_component:target/wasm32-wasip2/release/ironclaw_matrix_product_adapter_component.wasm"
)

wasm_build_env=(
  -u CARGO_ENCODED_RUSTFLAGS
  -u RUSTFLAGS
)

# cargo-llvm-cov replaces RUSTC_WRAPPER and records any wrapper it displaced.
# Nested wasm builds must bypass the coverage wrapper but retain that original
# wrapper (for example, sccache).
wasm_rustc_wrapper=
if [[ -n "${__CARGO_LLVM_COV_RUSTC_WRAPPER+x}" ]]; then
  if [[ -n "${__CARGO_LLVM_COV_RUSTC_WRAPPER_PRE_EXISTING:-}" ]]; then
    wasm_rustc_wrapper="$__CARGO_LLVM_COV_RUSTC_WRAPPER_PRE_EXISTING"
  else
    wasm_build_env+=(-u RUSTC_WRAPPER)
  fi
fi

while IFS= read -r variable; do
  if [[ "$variable" == __CARGO_LLVM_COV_RUSTC_WRAPPER* ]]; then
    wasm_build_env+=(-u "$variable")
  fi
done < <(compgen -e)

if [[ -n "$wasm_rustc_wrapper" ]]; then
  wasm_build_env+=(RUSTC_WRAPPER="$wasm_rustc_wrapper")
fi

for entry in "${components[@]}"; do
  package="${entry%%:*}"
  artifact="${entry#*:}"

  echo "Building ProductAdapter component: ${package}"
  # This wrapper owns the wasm32-wasip2 rustc flags, so it deliberately does
  # not inherit generic host Rust flags such as coverage instrumentation.
  env "${wasm_build_env[@]}" cargo rustc \
    -p "$package" \
    --release \
    --target wasm32-wasip2 \
    --crate-type cdylib \
    -- \
    -C opt-level=z \
    -C strip=symbols

  wasm-tools validate "$artifact"
  if command -v shasum >/dev/null 2>&1; then
    LC_ALL=C shasum -a 256 "$artifact"
  else
    sha256sum "$artifact"
  fi
done
