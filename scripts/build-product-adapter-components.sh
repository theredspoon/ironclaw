#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

components=(
  "ironclaw_matrix_product_adapter_component:target/wasm32-wasip2/release/ironclaw_matrix_product_adapter_component.wasm"
)

for entry in "${components[@]}"; do
  package="${entry%%:*}"
  artifact="${entry#*:}"

  echo "Building ProductAdapter component: ${package}"
  # This wrapper owns the wasm32-wasip2 rustc flags, so it deliberately does
  # not inherit generic host Rust flags such as coverage instrumentation.
  env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS cargo rustc \
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
