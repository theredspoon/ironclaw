# Dalek WASI Preview 2 Validation

Last validated: 2026-07-13

Source branch: `reborn-matrix-pilot`

Source commit: `14068fedc0173945d66898b99dd8ac7405f42cd5`

Validation command:

```bash
RUN_ID=2026-07-13-local-r000 scripts/dalek-wasip2-validation.sh
```

Outcome: `success`

Downstream action: `proceed`

This document is the durable handoff for the Matrix crypto feasibility gate.
The validation proves that the pinned `vodozemac` and dalek-family dependencies
compile as a `wasm32-wasip2` component and execute under the Reborn Wasmtime
component runtime through the canonical `near:agent/sandboxed-tool@0.3.0` WIT
surface.

The generated result artifact was written locally to
`target/dalek-wasip2-validation/logs/2026-07-13-local-r000-result.json`; CI
runs upload the same result shape through the `dalek-wasip2-validation`
artifact path.

```json
{
  "binding_artifacts": [
    "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml",
    "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.lock",
    "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-result.schema.json",
    "crates/ironclaw_wasm/tests/dalek_wasip2_validation.rs"
  ],
  "component_wasm_sha256": "2cae06f8734060cf75c227f2e2339eca0e15846295d2daab194bcecf9f0c1013",
  "dependency_config": {
    "cargo_lock_sha256": "c618e2c0297f5b465fe9fe5144e043eb79767d3e12678e120a99ec89d4f86c43",
    "crates": [
      {
        "default_features": false,
        "features": [],
        "name": "vodozemac",
        "source": "registry",
        "version": "=0.10.0"
      },
      {
        "default_features": false,
        "features": [
          "alloc",
          "fast",
          "zeroize"
        ],
        "name": "ed25519-dalek",
        "source": "registry",
        "version": "=3.0.0"
      },
      {
        "default_features": false,
        "features": [
          "getrandom",
          "static_secrets",
          "zeroize"
        ],
        "name": "x25519-dalek",
        "source": "registry",
        "version": "=3.0.0"
      },
      {
        "default_features": false,
        "features": [],
        "name": "getrandom",
        "source": "registry",
        "version": "=0.4.3"
      }
    ]
  },
  "downstream_action": "proceed",
  "failure_modes": [],
  "fallback_contract": {
    "audit_events": [],
    "authorization_scope": null,
    "host_storage_owner": null,
    "key_material_boundary": null,
    "operations_moved_to_host": [],
    "operations_remaining_in_component": [
      "dalek Ed25519/X25519",
      "vodozemac Olm account/session/encrypt/decrypt"
    ],
    "required": false,
    "trigger_criteria": [],
    "wit_imports": [],
    "wit_namespace": null,
    "wit_world": null,
    "zeroization_expectation": null
  },
  "log_artifacts": {
    "path_or_ci_artifact": "target/dalek-wasip2-validation/logs/2026-07-13-local-r000.jsonl",
    "redaction_status": "passed",
    "retention_policy": "CI artifact dalek-wasip2-validation retained by workflow defaults",
    "schema_version": 1
  },
  "reproduction_commands": [
    "scripts/dalek-wasip2-validation.sh"
  ],
  "resource_observations": {
    "component_size_bytes": 356299,
    "steady_state_ed25519_relative_to_native": "benchmark case completed 32 Ed25519 sign/verify iterations in the component; native baseline is intentionally out of scope for this fast gate",
    "steady_state_x25519_relative_to_native": "dalek-positive case completed X25519 shared-secret agreement in the component; native baseline is intentionally out of scope for this fast gate",
    "success_profile": {
      "fuel_or_epoch_limit": "5000000 fuel, 5s epoch timeout",
      "memory_limit_bytes": 4194304,
      "stack_limit_bytes": 1048576
    },
    "too_low_failure_profile": {
      "error_code": "resource_limit_exceeded",
      "fuel_or_epoch_limit": "1 fuel, 1s epoch timeout",
      "memory_limit_bytes": 65536,
      "stack_limit_bytes": 1048576
    }
  },
  "schema_version": 1,
  "source_branch": "reborn-matrix-pilot",
  "source_commit": "14068fedc0173945d66898b99dd8ac7405f42cd5",
  "test_summary": {
    "group_a": "pass",
    "group_b": "pass",
    "group_c": "pass",
    "group_d": "pass"
  },
  "toolchain_versions": {
    "cargo": {
      "pin_source": "workspace package rust-version",
      "version": "cargo 1.96.0 (30a34c682 2026-05-25)"
    },
    "cargo_component": {
      "pin_source": ".github/actions/install-cargo-component/action.yml",
      "version": "cargo-component-component 0.21.1"
    },
    "rustc": {
      "pin_source": "workspace package rust-version",
      "version": "rustc 1.96.0 (ac68faa20 2026-05-25)"
    },
    "wasm_opt": {
      "pin_source": null,
      "version": null
    },
    "wasm_tools": {
      "pin_source": "scripts/dalek-wasip2-validation.sh",
      "version": "wasm-tools 1.253.0"
    },
    "wasmtime": {
      "pin_source": "workspace dependencies",
      "version": "46.0.1"
    }
  },
  "validation_name": "Dalek WASI Preview 2",
  "validation_notes": [
    "dalek-wasip2-validation is the stable source-repo name for this feasibility gate",
    "RNG failure-injection rows are fixture-level deterministic classifications, not host-level entropy injection"
  ],
  "validation_package": "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component",
  "validation_status": "success",
  "wit_package": "near:agent/sandboxed-tool@0.3.0"
}
```
