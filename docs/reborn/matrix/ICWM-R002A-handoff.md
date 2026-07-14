# ICWM-R002A Matrix ProductAdapter Component Handoff

R002 provides the pure Matrix parse/render core and native ProductAdapter
boundary proof. R002A owns packaging that core as the first installable Matrix
ProductAdapter WASM component.

## Source Entry Points

- Parser: `crates/ironclaw_matrix_adapter/src/lib.rs`
  - `parse_matrix_event(MatrixParseInput) -> Result<ParsedMatrixInbound, MatrixAdapterDiagnostic>`
  - `MatrixParseInput`
  - `MatrixParsePolicy`
  - `ParsedMatrixInbound`
  - `MatrixInboundEvent`
  - `MatrixMessageMetadata`
  - `MatrixRelation`
  - `EncryptionState`
- Renderer: `crates/ironclaw_matrix_adapter/src/lib.rs`
  - `render_matrix_outbound(MatrixRenderInput) -> Result<MatrixOutboundCommand, MatrixAdapterDiagnostic>`
  - `MatrixRenderInput`
  - `MatrixRenderContext`
  - `MatrixRouteMetadata`
  - `MatrixOutboundCommand`
- Native host proof only:
  - `MatrixProductAdapter`
  - `MatrixProductAdapterConfig`

The native `MatrixProductAdapter` wrapper is not the production artifact. R002A
must export `crates/ironclaw_wasm_product_adapters/wit/product_adapter.wit`.

## ProductAdapter WIT Exports

R002A must implement these WIT exports:

- `manifest`
- `parse-inbound`
- `render-outbound`

The current WIT uses JSON-string DTO shims:

- `parsed-inbound.parsed-json`: JSON for
  `ironclaw_product_adapters::ParsedProductInbound`
- `outbound-envelope.outbound-json`: JSON for
  `ironclaw_product_adapters::ProductOutboundEnvelope`
- `outbound-render.egress-request-json`: JSON for
  `ironclaw_product_adapters::EgressRequest`
- `adapter-manifest.capabilities-json`: JSON for
  `ironclaw_product_adapters::ProductAdapterCapabilities`

The Matrix guest must not define wasm-only Rust mirrors of product DTOs.
Host-side serde validation remains authoritative until the WIT replaces these
string shims with typed records.

## Manifest Fields

The R002A component manifest must declare:

- `adapter-id`: stable Matrix adapter id, expected to be `matrix` unless the
  packaging spec chooses a more specific id.
- `installation-id`: provided by host configuration, not hard-coded as a global
  singleton.
- `capabilities-json`: serialized `ProductAdapterCapabilities`.
- `declared-auth-requirements`: the host-verified Matrix ingress auth
  requirement. Components cannot fabricate verified auth evidence.
- `declared-egress-targets`: Matrix homeserver host plus optional credential
  handle pair. The host validates the pair before any HTTP send.

## Parse Contract

`parse-inbound` receives host-verified auth evidence and raw Matrix event JSON.
It must call the R002 parser and return canonical `ParsedProductInbound` JSON in
`parsed-inbound.parsed-json`.

Matrix-only facts remain Matrix-owned:

- `MatrixMessageMetadata`
- `MatrixInboundEvent`
- `MatrixRelation`
- `EncryptionState`
- `MatrixAdapterDiagnostic`
- `MatrixReasonCode`

They must not be added to shared product DTOs without a separate
product-contract decision.

## Render Contract

`render-outbound` receives `ProductOutboundEnvelope` JSON in
`outbound-envelope.outbound-json`. It may use the R002 renderer to create an
internal `MatrixOutboundCommand`, but the WIT return value must be a validated
`EgressRequest` JSON in `outbound-render.egress-request-json`.

The required Matrix send request is host-mediated HTTP egress, not a direct
Matrix SDK call or guest-owned network effect.

## Fixtures and Tests

Current R002 contract tests live in:

- `crates/ironclaw_matrix_adapter/tests/matrix_parse_render_contract.rs`

Important tests for R002A:

- `matrix_dto_shapes_match_product_adapter_wit_json_shim`
- `matrix_product_adapter_parses_authenticated_inbound_payload`
- `matrix_product_adapter_rejects_unverified_inbound_payload`
- `matrix_product_adapter_renders_outbound_at_product_boundary`
- `test_parse_render_round_trip_preserves_semantics`
- `wasm_path_does_not_define_shadow_product_contracts`

R002A must add host-runtime component tests using
`ProductAdapterComponentRuntime` from `crates/ironclaw_wasm_product_adapters`.
Those tests must load the built Matrix component and call `manifest`,
`parse-inbound`, and `render-outbound`.

## Diagnostics

Matrix diagnostic reason codes are defined by `MatrixReasonCode` in
`crates/ironclaw_matrix_adapter/src/lib.rs`. R002A must preserve these codes in
Matrix-owned diagnostics and keep diagnostic/log output sanitized.

Safe logging requirement:

- use `MatrixMessageMetadata`'s redacted `Debug` implementation for debug logs;
- do not log raw serialized metadata in production logs;
- never log raw `mxc://` URLs, ciphertext, credential-like tokens, or raw
  formatted HTML.

## Verification Baseline

R002 verification commands:

```bash
cargo test -p ironclaw_matrix_adapter
cargo clippy -p ironclaw_matrix_adapter --all-targets -- -D warnings
cargo check -p ironclaw_matrix_adapter --target wasm32-wasip2
```

The R002A spec must replace this source-level proof with a component build and
runtime load proof. Native wrapper tests from R002 are not enough to claim an
installable Matrix ProductAdapter component.
