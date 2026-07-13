use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use ironclaw_wasm::{WasmError, WitToolHost, WitToolRequest, WitToolRuntime, WitToolRuntimeConfig};
use serde_json::{Value, json};
use wit_component::{ComponentEncoder, StringEncoding, embed_component_metadata};
use wit_parser::Resolve;

const RESULT_SCHEMA: &str = include_str!("fixtures/dalek-wasip2-result.schema.json");
const DALEK_WASIP2_TOOL_WAT: &str = r#"
(module
  (type (;0;) (func (param i32 i32 i32)))
  (type (;1;) (func (result i64)))
  (type (;2;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
  (type (;3;) (func (param i32 i32 i32 i32 i32)))
  (type (;4;) (func (param i32 i32) (result i32)))
  (import "near:agent/host@0.3.0" "log" (func $log (type 0)))
  (import "near:agent/host@0.3.0" "now-millis" (func $now (type 1)))
  (import "near:agent/host@0.3.0" "workspace-read" (func $workspace_read (type 0)))
  (import "near:agent/host@0.3.0" "http-request" (func $http_request (type 2)))
  (import "near:agent/host@0.3.0" "tool-invoke" (func $tool_invoke (type 3)))
  (import "near:agent/host@0.3.0" "secret-exists" (func $secret_exists (type 4)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 8192))
  (data (i32.const 1024) "{\22type\22:\22object\22,\22additionalProperties\22:false,\22required\22:[\22case\22],\22properties\22:{\22case\22:{\22type\22:\22string\22,\22enum\22:[\22metadata\22,\22rng-success\22,\22rng-denied\22,\22rng-all-zero\22,\22rng-repeated-block\22,\22rng-biased\22,\22rng-short-read\22,\22dalek-positive\22,\22dalek-negative\22,\22vodozemac-roundtrip\22,\22vodozemac-negative\22,\22resource-success\22,\22resource-too-low\22,\22benchmark\22]}}}")
  (data (i32.const 2048) "Dalek WASI Preview 2 validation fixture for dalek-family and vodozemac wasm32-wasip2 execution through the Reborn sandboxed-tool ABI. This is non-production test infrastructure.")
  (data (i32.const 3072) "{\22schema_version\22:1,\22validation_name\22:\22Dalek WASI Preview 2\22,\22validation_package\22:\22crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component\22,\22case\22:\22metadata\22,\22status\22:\22pass\22,\22error_code\22:null,\22error_class\22:null,\22message\22:\22canonical Reborn ABI metadata exports are available\22,\22iteration_count\22:1}")
  (data (i32.const 4096) "{\22schema_version\22:1,\22validation_name\22:\22Dalek WASI Preview 2\22,\22validation_package\22:\22crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component\22,\22case\22:\22rng-denied\22,\22status\22:\22fail\22,\22error_code\22:\22host_entropy_denied\22,\22error_class\22:\22validation\22,\22message\22:\22deterministic fixture failure injection\22,\22iteration_count\22:1}")
  (func $schema (result i32)
    i32.const 16
    i32.const 1024
    i32.store
    i32.const 20
    i32.const 346
    i32.store
    i32.const 16)
  (func $description (result i32)
    i32.const 32
    i32.const 2048
    i32.store
    i32.const 36
    i32.const 177
    i32.store
    i32.const 32)
  (func $execute (param i32 i32 i32 i32 i32) (result i32)
    i32.const 0
    i32.const 0
    i32.const 33
    call $log
    i32.const 48
    i32.const 1
    i32.store
    i32.const 52
    local.get 1
    i32.const 20
    i32.ge_u
    if (result i32)
      i32.const 4096
    else
      i32.const 3072
    end
    i32.store
    i32.const 56
    local.get 1
    i32.const 20
    i32.ge_u
    if (result i32)
      i32.const 313
    else
      i32.const 298
    end
    i32.store
    i32.const 60
    i32.const 0
    i32.store
    i32.const 48)
  (func $post (param i32))
  (func $realloc (param $old i32) (param $old_align i32) (param $new_size i32) (param $new_align i32) (result i32)
    (local $ret i32)
    global.get $heap
    local.set $ret
    global.get $heap
    local.get $new_size
    i32.add
    global.set $heap
    local.get $ret)
  (func $_initialize)
  (export "near:agent/tool@0.3.0#execute" (func $execute))
  (export "cabi_post_near:agent/tool@0.3.0#execute" (func $post))
  (export "near:agent/tool@0.3.0#schema" (func $schema))
  (export "cabi_post_near:agent/tool@0.3.0#schema" (func $post))
  (export "near:agent/tool@0.3.0#description" (func $description))
  (export "cabi_post_near:agent/tool@0.3.0#description" (func $post))
  (export "cabi_realloc" (func $realloc))
  (export "_initialize" (func $_initialize))
)
"#;

#[test]
fn validation_result_schema_accepts_success_and_failure_shapes() {
    let schema = serde_json::from_str::<Value>(RESULT_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    assert!(validator.is_valid(&success_result()));
    assert!(validator.is_valid(&blocker_result()));
}

#[test]
fn validation_result_schema_rejects_ambiguous_status_strings() {
    let schema = serde_json::from_str::<Value>(RESULT_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut result = success_result();
    result["validation_status"] = json!("success | fallback | blocker");

    assert!(!validator.is_valid(&result));
}

#[test]
fn validation_fixture_source_files_are_permanent_and_pinned() {
    let root = workspace_root();
    let fixture = root.join("crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component");
    assert!(fixture.join("Cargo.toml").exists());
    assert!(fixture.join("src/lib.rs").exists());
    assert!(root.join("scripts/dalek-wasip2-validation.sh").exists());
    assert!(
        root.join(".github/workflows/dalek-wasip2-validation.yml")
            .exists()
    );

    let manifest = fs::read_to_string(fixture.join("Cargo.toml")).unwrap();
    for pin in [
        "vodozemac = { version = \"=0.10.0\"",
        "ed25519-dalek = { version = \"=3.0.0\"",
        "x25519-dalek = { version = \"=3.0.0\"",
        "getrandom = { version = \"=0.4.3\"",
    ] {
        assert!(manifest.contains(pin), "missing exact pin {pin}");
    }
    assert!(!manifest.contains("wasm_js"));
}

#[test]
fn canonical_reborn_abi_harness_invokes_success_and_failure_cases() {
    let runtime = WitToolRuntime::new(WitToolRuntimeConfig::for_testing()).unwrap();
    let prepared = runtime.prepare("dalek-wasip2", &tool_component()).unwrap();

    assert_eq!(
        prepared.description(),
        "Dalek WASI Preview 2 validation fixture for dalek-family and vodozemac wasm32-wasip2 execution through the Reborn sandboxed-tool ABI. This is non-production test infrastructure."
    );
    assert_eq!(
        prepared.schema()["properties"]["case"]["enum"]
            .as_array()
            .unwrap()
            .len(),
        14
    );

    let success = runtime
        .execute(
            &prepared,
            WitToolHost::deny_all(),
            WitToolRequest {
                params_json: json!({"case":"metadata"}).to_string(),
                context_json: None,
            },
        )
        .unwrap();
    let output: Value = serde_json::from_str(success.output_json.as_deref().unwrap()).unwrap();
    assert_eq!(output["status"], "pass");
    assert_eq!(output["error_code"], Value::Null);
    assert_eq!(success.logs.len(), 1);

    let failure = runtime
        .execute(
            &prepared,
            WitToolHost::deny_all(),
            WitToolRequest {
                params_json: json!({"case":"rng-denied"}).to_string(),
                context_json: None,
            },
        )
        .unwrap();
    let output: Value = serde_json::from_str(failure.output_json.as_deref().unwrap()).unwrap();
    assert_eq!(output["status"], "fail");
    assert_eq!(output["error_code"], "host_entropy_denied");
}

#[test]
fn canonical_reborn_abi_harness_classifies_guest_trap() {
    let runtime = WitToolRuntime::new(WitToolRuntimeConfig::for_testing()).unwrap();
    let trap_component = tool_component_from_wat(
        "(module (memory (export \"memory\") 1) (func (export \"near:agent/tool@0.3.0#description\") (result i32) unreachable) (func (export \"near:agent/tool@0.3.0#schema\") (result i32) unreachable) (func (export \"near:agent/tool@0.3.0#execute\") (param i32 i32 i32 i32 i32) (result i32) unreachable) (func (export \"cabi_realloc\") (param i32 i32 i32 i32) (result i32) i32.const 0))",
    );

    let error = runtime.prepare("trap", &trap_component).unwrap_err();

    assert!(
        matches!(error, WasmError::ExecutionFailed { .. }),
        "unexpected trap classification: {error:?}"
    );
}

#[test]
fn pinned_toolchain_commands_are_declared() {
    let script =
        fs::read_to_string(workspace_root().join("scripts/dalek-wasip2-validation.sh")).unwrap();
    assert!(script.contains("CARGO_COMPONENT_VERSION=\"0.21.1\""));
    assert!(script.contains("WASM_TOOLS_VERSION=\"1.253.0\""));
    assert!(script.contains("CARGO_AUDIT_VERSION=\"0.22.2\""));
    assert!(script.contains("CARGO_DENY_VERSION=\"0.20.2\""));
    assert!(script.contains("cargo component build --release --target wasm32-wasip2"));
    assert!(script.contains("target/wasm32-wasip1/release/dalek_wasip2_component.wasm"));
    assert!(script.contains("wasm-tools validate"));
    assert!(script.contains("cargo audit --file"));
    assert!(script.contains("cargo deny --manifest-path"));
    assert!(script.contains("import near:agent/host@0.3.0"));
    assert!(script.contains("export near:agent/tool@0.3.0"));
    assert!(script.contains("import wasi:random/random@0.2.3"));
    assert!(script.contains("cargo test -p ironclaw_wasm --test dalek_wasip2_validation"));

    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/dalek-wasip2-validation.yml"))
            .unwrap();
    assert!(workflow.contains("Fetch pull request base for safety diff"));
    assert!(workflow.contains("PRE_COMMIT_SAFETY_BASE_REF"));
}

#[test]
fn source_tree_does_not_include_handoff_document() {
    let handoff_docs_dir = workspace_root().join("docs/reborn/matrix");
    let has_handoff_doc = fs::read_dir(&handoff_docs_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.path().is_file())
        })
        .unwrap_or(false);
    assert!(!has_handoff_doc);
}

#[test]
fn fixture_cargo_lock_is_committed_after_generation() {
    assert!(
        workspace_root()
            .join("crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.lock")
            .exists(),
        "run cargo generate-lockfile --manifest-path crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml before merge"
    );
}

#[test]
fn fixture_component_builds_when_component_toolchain_is_available() {
    let cargo_component_installed = Command::new("cargo")
        .args(["component", "--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !cargo_component_installed {
        eprintln!("cargo-component is not installed locally; CI installs cargo-component@0.21.1");
        return;
    }

    let status = Command::new("cargo")
        .current_dir(workspace_root())
        .args([
            "component",
            "build",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--manifest-path",
            "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ironclaw_wasm crate should live under crates/")
        .to_path_buf()
}

fn tool_component() -> Vec<u8> {
    tool_component_from_wat(DALEK_WASIP2_TOOL_WAT)
}

fn tool_component_from_wat(wat_src: &str) -> Vec<u8> {
    let mut module = wat::parse_str(wat_src).expect("fixture WAT must parse");
    let mut resolve = Resolve::default();
    let package = resolve
        .push_str("tool.wit", include_str!("../../../wit/tool.wit"))
        .expect("tool WIT must parse");
    let world = resolve
        .select_world(&[package], Some("sandboxed-tool"))
        .expect("sandboxed-tool world must exist");

    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
        .expect("component metadata must embed");

    ComponentEncoder::default()
        .module(&module)
        .expect("fixture module must decode")
        .validate(true)
        .encode()
        .expect("component must encode")
}

fn success_result() -> Value {
    json!({
        "schema_version": 1,
        "validation_name": "Dalek WASI Preview 2",
        "validation_status": "success",
        "source_branch": "feat/dalek-wasip2-validation",
        "source_commit": "0000000",
        "validation_package": "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component",
        "component_wasm_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "wit_package": "near:agent/sandboxed-tool@0.3.0",
        "toolchain_versions": toolchain_versions(),
        "dependency_config": dependency_config(),
        "test_summary": {"group_a":"pass","group_b":"pass","group_c":"pass","group_d":"pass"},
        "failure_modes": [],
        "resource_observations": resource_observations(),
        "log_artifacts": {"schema_version":1,"path_or_ci_artifact":"target/dalek-wasip2-validation/logs/local.jsonl","retention_policy":"CI artifact dalek-wasip2-validation retained by workflow defaults","redaction_status":"passed"},
        "fallback_contract": fallback_contract(false),
        "downstream_action": "proceed",
        "binding_artifacts": ["crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml"],
        "reproduction_commands": ["scripts/dalek-wasip2-validation.sh"]
    })
}

fn blocker_result() -> Value {
    let mut result = success_result();
    result["validation_status"] = json!("blocker");
    result["test_summary"] =
        json!({"group_a":"fail","group_b":"skipped","group_c":"skipped","group_d":"skipped"});
    result["failure_modes"] = json!([{"phase":"component-build","error_code":"build_failed","classification":"blocker","sanitized_summary":"fixture component did not build"}]);
    result["downstream_action"] = json!("block");
    result
}

fn toolchain_versions() -> Value {
    json!({
        "rustc": {"version":"1.96.0","pin_source":"workspace.package.rust-version"},
        "cargo": {"version":"1.96.0","pin_source":"workspace.package.rust-version"},
        "cargo_component": {"version":"0.21.1","pin_source":".github/actions/install-cargo-component/action.yml"},
        "wasm_tools": {"version":"1.253.0","pin_source":"scripts/dalek-wasip2-validation.sh"},
        "wasmtime": {"version":"46.0.1","pin_source":"workspace.dependencies"},
        "wasm_opt": {"version":null,"pin_source":null}
    })
}

fn dependency_config() -> Value {
    json!({
        "cargo_lock_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "crates": [
            {"name":"vodozemac","version":"=0.10.0","features":[],"default_features":false,"source":"registry"},
            {"name":"ed25519-dalek","version":"=3.0.0","features":["alloc","fast","zeroize"],"default_features":false,"source":"registry"},
            {"name":"x25519-dalek","version":"=3.0.0","features":["getrandom","static_secrets","zeroize"],"default_features":false,"source":"registry"},
            {"name":"getrandom","version":"=0.4.3","features":[],"default_features":false,"source":"registry"}
        ]
    })
}

fn resource_observations() -> Value {
    json!({
        "success_profile": {"memory_limit_bytes":1048576,"stack_limit_bytes":1048576,"fuel_or_epoch_limit":"100000 fuel, 5s epoch timeout"},
        "too_low_failure_profile": {"memory_limit_bytes":4096,"stack_limit_bytes":65536,"fuel_or_epoch_limit":"1 fuel","error_code":"resource_limit_exceeded"},
        "steady_state_ed25519_relative_to_native": "measured by benchmark case in validation script",
        "steady_state_x25519_relative_to_native": "measured by benchmark case in validation script",
        "component_size_bytes": 1
    })
}

fn fallback_contract(required: bool) -> Value {
    if required {
        json!({
            "required": true,
            "trigger_criteria": ["in-component validation failed"],
            "wit_namespace": "near:agent/matrix-crypto-fallback@0.1.0",
            "wit_world": "matrix-crypto-provider",
            "wit_imports": ["opaque account/session handle operations only"],
            "operations_moved_to_host": ["olm account/session operation named by failure mode"],
            "operations_remaining_in_component": ["Matrix channel orchestration"],
            "key_material_boundary": "opaque_handles",
            "host_storage_owner": "Reborn host encrypted storage",
            "authorization_scope": "per-user/per-device/per-session",
            "audit_events": ["matrix_crypto_fallback_invoked"],
            "zeroization_expectation": "host drops raw material before handle release"
        })
    } else {
        json!({
            "required": false,
            "trigger_criteria": [],
            "wit_namespace": null,
            "wit_world": null,
            "wit_imports": [],
            "operations_moved_to_host": [],
            "operations_remaining_in_component": ["dalek Ed25519/X25519", "vodozemac Olm account/session/encrypt/decrypt"],
            "key_material_boundary": null,
            "host_storage_owner": null,
            "authorization_scope": null,
            "audit_events": [],
            "zeroization_expectation": null
        })
    }
}
