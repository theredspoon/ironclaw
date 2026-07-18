# ICWM-R002D Matrix ProductWorkflow Composition Handoff

Source-local handoff for the R002D Matrix ProductWorkflow composition slice.
Lighthouse planning authority:
`SPEC_icwm-r002d-matrix-productworkflow-composition.md`.

## Source Owners

| Boundary | Source owner used by this slice |
| --- | --- |
| ProductAdapter boundary | `crates/ironclaw_matrix_adapter/src/lib.rs` implements `ironclaw_product_adapters::ProductAdapter` |
| Matrix installation lifecycle and policy | `crates/ironclaw_matrix_adapter/src/installation_policy.rs` |
| Inbound idempotency and ProductWorkflow submission | `crates/ironclaw_product_workflow` via `DefaultProductWorkflow`, `DefaultInboundTurnService`, and `InMemoryIdempotencyLedger` |
| Conversation binding | `ironclaw_product_workflow::ConversationBindingService` |
| Turn submission | `ironclaw_turns::TurnCoordinator` |
| Outbound target resolution | `ironclaw_product_workflow::ProductOutboundTargetResolver` |
| Outbound attempt and status state | `crates/ironclaw_outbound` |
| Matrix pending send handoff | R003A-owned Matrix outbound bridge; R002D leaves render output as `ProductRenderOutcome::Deferred` |

## Allowed Edit Paths

- `crates/ironclaw_matrix_adapter/src/lib.rs`
- `crates/ironclaw_matrix_adapter/src/installation_policy.rs`
- `crates/ironclaw_matrix_adapter/tests/matrix_product_workflow_composition_contract.rs`
- `crates/ironclaw_matrix_adapter/Cargo.toml`
- `Cargo.lock`
- `docs/reborn/matrix/ICWM-R002D-handoff.md`

## Forbidden Imports And Boundaries

- Production Matrix adapter code must not import test-only fakes.
- Guest parse/render boundaries must not receive credential material, credential
  handles, raw HTTP headers, or host secret leases.
- R002D must not add Matrix transport sockets, live homeserver dependencies,
  Matrix E2EE persistence, schema migrations, background workers, or terminal
  Matrix delivery status ownership.
- Matrix composition must use ProductWorkflow and ProductOutbound owners for
  idempotency, binding, target resolution, attempt state, and status state.

## Verification Commands

Commands used for this PR:

```bash
cargo test -p ironclaw_matrix_adapter \
  --test matrix_product_workflow_composition_contract -- --nocapture
cargo check -p ironclaw_matrix_adapter
cargo clippy -p ironclaw_matrix_adapter \
  --test matrix_product_workflow_composition_contract -- -D warnings
cargo test -p ironclaw_matrix_adapter --tests
cargo fmt --check
git diff --check
```

Required CI checks before merge are the repository GitHub Actions checks
reported on the PR, including formatting/static checks, clippy, and regression
test enforcement.

## Reviewed Deviations

- R002D uses a small native composition shim,
  `MatrixProductAdapter::submit_verified_inbound`, because the current source
  tree exposes ProductWorkflow submission as a trait boundary rather than a
  single Matrix-specific runtime entry point. The shim extracts host routing
  facts, invokes R002C policy admission, delegates guest parse to the existing
  adapter parser, and submits the resulting envelope to ProductWorkflow. It does
  not own persistence, background work, binding, idempotency, turn submission,
  or delivery status.
- Matrix outbound lifecycle authorization before render is not changed by this
  inbound-focused PR. The active follow-on must either wire the lifecycle-aware
  outbound policy seam before Matrix render or update the R002D/R003A plan with
  the reviewed owner and slice boundary.
