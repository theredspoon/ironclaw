# ICWM-R002A Group 0 Source Verification

Date: 2026-07-15
Branch: `agent/icwm-r002a-matrix-product-adapter-component`
Base: `reborn-matrix-pilot`
Spec: `SPEC_icwm-r002a-matrix-product-adapter-component-packaging.md`

## Result

Group 0 is clean after commit `6940c943d` (`fix(matrix-wasm): remove guest-visible installation config`).

The implementation branch no longer contains the forbidden universal
installation config import or Matrix-specific runtime config fields. R002A
continues with the JSON-string ProductAdapter WIT shim; typed WIT records remain
R002B follow-on work.

## Source Contracts

- WIT world: `crates/ironclaw_wasm_product_adapters/wit/product_adapter.wit`
  - Package: `near:product-adapter@0.1.0`
  - World: `product-adapter-component`
  - Imports: `product-adapter-host` with `log`, `now-millis`, and reserved/fail-closed `http-egress`
  - Exports: `product-adapter` with `manifest`, `parse-inbound`, and `render-outbound`
  - JSON shim fields: `parsed-json`, `evidence-json`, `outbound-json`, `egress-request-json`, and `capabilities-json`
- Manifest record: `crates/ironclaw_wasm_product_adapters/wit/product_adapter.wit`
  - `adapter-id`
  - `installation-id`
  - `capabilities-json`
  - `declared-egress-targets`
  - `declared-auth-requirements`
- Host runtime: `crates/ironclaw_wasm_product_adapters/src/component_runtime.rs`
  - `ProductAdapterComponentRuntime::prepare` compiles component bytes, extracts manifest, and creates `EgressPolicy`.
  - `parse_inbound` validates host-side auth evidence against the prepared manifest before calling guest code.
  - `render_outbound` validates guest egress JSON into canonical `EgressRequest` before returning it.
  - `StoreData::new` receives only sandbox memory and timeout; no installation config is passed into the guest store.
- Runtime config: `crates/ironclaw_wasm_product_adapters/src/config.rs`
  - `ProductAdapterComponentRuntimeConfig` has only `default_limits` and `max_component_bytes`.
- Canonical DTOs:
  - `crates/ironclaw_product_adapters/src/inbound.rs`
  - `crates/ironclaw_product_adapters/src/outbound.rs`
  - `crates/ironclaw_product_adapters/src/egress.rs`
  - `crates/ironclaw_product_adapters/src/capabilities.rs`
- Matrix parse/render APIs:
  - `crates/ironclaw_matrix_adapter/src/lib.rs`
  - `parse_matrix_event(MatrixParseInput)`
  - `render_matrix_outbound(MatrixRenderInput)`
  - `MatrixParsePolicy` documents empty allowlists as pre-transport parsing; production admission policy remains host-owned.
- R002 fixtures:
  - `crates/ironclaw_matrix_adapter/tests/matrix_parse_render_contract.rs`

## Implementation Boundary

- Forbidden config imports are absent from the WIT and component source:
  - `installation-config-json`
  - `matrix-config-json`
  - `installation_config_json`
- Forbidden Matrix-specific shared runtime config types are absent:
  - `ProductAdapterInstallationConfig`
  - `MatrixProductAdapterInstallationConfig`
  - `ProductAdapterAuthConfig`
  - `ProductAdapterEgressTargetConfig`
- Matrix component source does not call `product_adapter_host::http_egress`.
- Matrix component manifest embeds static sentinel `installation-id = "matrix-default"`.
- Matrix guest builds ProductAdapter JSON with `serde_json::json!` / `serde_json::Value` and does not define product DTO shadow structs.

## Handoff Conflict

The Lighthouse Matrix epic handoff for ICWM-R002A records an earlier
host-provided manifest `installation-id` assumption. The later Lighthouse spec
supersedes that line: R002A must not add a guest-visible config channel, so this
component uses the static sentinel and leaves actual installation binding to
host-owned composition/installation state.

## Verification Commands

```bash
rg -n "installation-config-json|matrix-config-json|installation_config_json|ProductAdapterInstallationConfig|MatrixProductAdapterInstallationConfig|ProductAdapterAuthConfig|ProductAdapterEgressTargetConfig|product_adapter_host::installation_config_json|allowed_rooms|allowed_senders" crates/ironclaw_wasm_product_adapters/src crates/ironclaw_wasm_product_adapters/wit crates/ironclaw_matrix_product_adapter_component/src
# no matches

rg -n "product_adapter_host::http_egress|http_egress\\(" crates/ironclaw_matrix_product_adapter_component/src
# no matches

cargo check -p ironclaw_matrix_product_adapter_component --target wasm32-wasip2
# pass

cargo test -p ironclaw_wasm_product_adapters --test component_runtime_contract
# 14 passed

cargo test -p ironclaw_matrix_product_adapter_component --test component_runtime_contract -- --nocapture
# 13 passed

cargo test -p ironclaw_matrix_product_adapter_component
# package tests, component runtime tests, and doctests passed

cargo clippy -p ironclaw_wasm_product_adapters -p ironclaw_matrix_product_adapter_component --all-targets -- -D warnings
# pass

./scripts/build-product-adapter-components.sh
# pass; sha256 01bdff8458e7e47ed1b073ee7d95a5ccfeed668dae7ad1dd91978bc2417ac9d3

cargo fmt --all -- --check
# pass

git diff --check
# pass
```
