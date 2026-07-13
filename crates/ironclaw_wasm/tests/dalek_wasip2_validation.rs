use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use ironclaw_wasm::wasm_sandbox_core::SandboxLimits;
use ironclaw_wasm::{WasmError, WitToolHost, WitToolRequest, WitToolRuntime, WitToolRuntimeConfig};
use serde_json::{Value, json};

const RESULT_SCHEMA: &str = include_str!("fixtures/dalek-wasip2-result.schema.json");
const FIXTURE_MANIFEST: &str =
    "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.toml";
const FIXTURE_LOCK: &str = "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/Cargo.lock";
const FIXTURE_PACKAGE: &str = "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component";
const COMPONENT_WASM: &str = "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component/target/wasm32-wasip1/release/dalek_wasip2_component.wasm";
const LOG_ARTIFACT: &str = "target/dalek-wasip2-validation/logs";
const SUCCESS_CASES: &[&str] = &[
    "rng-success",
    "dalek-positive",
    "dalek-negative",
    "vodozemac-roundtrip",
    "vodozemac-negative",
    "resource-success",
    "benchmark",
];
const EXPECTED_FAILURE_CASES: &[(&str, &str)] = &[
    ("rng-denied", "host_entropy_denied"),
    ("rng-all-zero", "weak_rng_sample"),
    ("rng-repeated-block", "weak_rng_sample"),
    ("rng-biased", "weak_rng_sample"),
    ("rng-short-read", "host_entropy_denied"),
    ("resource-too-low", "resource_limit_exceeded"),
];

#[test]
fn validation_result_schema_accepts_success_and_failure_shapes() {
    let schema = serde_json::from_str::<Value>(RESULT_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    assert!(validator.is_valid(&success_result(
        "0".repeat(64),
        "0".repeat(64),
        1,
        "target/dalek-wasip2-validation/logs/local.jsonl",
    )));
    assert!(validator.is_valid(&blocker_result()));
}

#[test]
fn validation_result_schema_rejects_ambiguous_status_strings() {
    let schema = serde_json::from_str::<Value>(RESULT_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut result = success_result(
        "0".repeat(64),
        "0".repeat(64),
        1,
        "target/dalek-wasip2-validation/logs/local.jsonl",
    );
    result["validation_status"] = json!("success | fallback | blocker");

    assert!(!validator.is_valid(&result));
}

#[test]
fn validation_fixture_source_files_are_permanent_and_pinned() {
    let root = workspace_root();
    let fixture = root.join(FIXTURE_PACKAGE);
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
fn host_harness_builds_loads_actual_fixture_component_and_executes_real_cases() {
    let Some(component_path) = ensure_component_artifact() else {
        eprintln!("cargo-component is not installed locally; CI installs cargo-component@0.21.1");
        return;
    };
    let component_bytes = fs::read(&component_path).unwrap_or_else(|error| {
        panic!(
            "failed to read component artifact {}: {error}",
            component_path.display()
        )
    });
    let component_sha256 = sha256_file(&component_path);
    let lock_sha256 = sha256_file(workspace_root().join(FIXTURE_LOCK));
    let component_size = component_bytes.len() as u64;

    let runtime = validation_runtime();
    let prepared = runtime
        .prepare("dalek-wasip2-dalek-wasip2", &component_bytes)
        .unwrap();

    assert!(
        prepared
            .description()
            .contains("Dalek WASI Preview 2 validation fixture"),
        "description should identify the validation fixture"
    );
    assert_eq!(
        prepared.schema()["properties"]["case"]["enum"]
            .as_array()
            .unwrap()
            .len(),
        14
    );

    let mut log_records = Vec::new();
    let metadata = execute_case(&runtime, &prepared, "metadata");
    assert_case_passed("metadata", &metadata);
    log_records.push(log_record("component-runtime", "metadata", &metadata));

    for case_name in SUCCESS_CASES {
        let output = execute_case(&runtime, &prepared, case_name);
        assert_case_passed(case_name, &output);
        log_records.push(log_record("component-runtime", case_name, &output));
    }

    for (case_name, expected_code) in EXPECTED_FAILURE_CASES {
        let output = execute_case(&runtime, &prepared, case_name);
        assert_eq!(output["case"], *case_name);
        assert_eq!(output["status"], "fail");
        assert_eq!(output["error_code"], *expected_code);
        log_records.push(log_record("failure-injection", case_name, &output));
    }

    let constrained_runtime = WitToolRuntime::new(WitToolRuntimeConfig {
        default_limits: SandboxLimits::default()
            .with_memory_bytes(4 * 1024 * 1024)
            .with_fuel(5_000_000)
            .with_timeout(std::time::Duration::from_secs(5)),
    })
    .unwrap();
    let constrained = constrained_runtime
        .prepare("dalek-wasip2-constrained", &component_bytes)
        .unwrap();
    assert_case_passed(
        "resource-success",
        &execute_case(&constrained_runtime, &constrained, "resource-success"),
    );

    let starved_runtime = WitToolRuntime::new(WitToolRuntimeConfig {
        default_limits: SandboxLimits::default()
            .with_memory_bytes(64 * 1024)
            .with_fuel(1)
            .with_timeout(std::time::Duration::from_secs(1)),
    })
    .unwrap();
    let starved = starved_runtime
        .prepare("dalek-wasip2-starved", &component_bytes)
        .unwrap_err();
    assert!(
        matches!(
            starved,
            WasmError::CompilationFailed(_)
                | WasmError::ExecutionFailed { .. }
                | WasmError::InstantiationFailed(_)
        ),
        "unexpected resource-limit error: {starved:?}"
    );

    maybe_write_artifacts(component_sha256, lock_sha256, component_size, &log_records);
}

#[test]
fn actual_component_artifact_is_required_when_script_requests_it() {
    if env::var_os("DALEK_WASIP2_REQUIRE_COMPONENT").is_none() {
        return;
    }
    assert!(
        workspace_root().join(COMPONENT_WASM).exists(),
        "validation script must build the fixture component before running the host harness"
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
    assert!(script.contains(COMPONENT_WASM));
    assert!(script.contains("wasm-tools validate"));
    assert!(script.contains("cargo audit --file"));
    assert!(script.contains("cargo deny --manifest-path"));
    assert!(script.contains("import near:agent/host@0.3.0"));
    assert!(script.contains("export near:agent/tool@0.3.0"));
    assert!(script.contains("import wasi:random/random@0.2.3"));
    assert!(script.contains("DALEK_WASIP2_REQUIRE_COMPONENT=1"));
    assert!(script.contains("DALEK_WASIP2_RESULT_PATH="));

    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/dalek-wasip2-validation.yml"))
            .unwrap();
    assert!(workflow.contains("dalek-wasip2-validation"));
    assert!(workflow.contains("Fetch pull request base for safety diff"));
    assert!(workflow.contains("PRE_COMMIT_SAFETY_BASE_REF"));
}

#[test]
fn fixture_cargo_lock_is_committed_after_generation() {
    assert!(
        workspace_root().join(FIXTURE_LOCK).exists(),
        "run cargo generate-lockfile --manifest-path {FIXTURE_MANIFEST} before merge"
    );
}

fn ensure_component_artifact() -> Option<PathBuf> {
    let root = workspace_root();
    let component_path = root.join(COMPONENT_WASM);
    if component_path.exists() {
        return Some(component_path);
    }

    let cargo_component_installed = Command::new("cargo")
        .args(["component", "--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !cargo_component_installed {
        return None;
    }

    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "component",
            "build",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--manifest-path",
            FIXTURE_MANIFEST,
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        component_path.exists(),
        "cargo-component completed but did not write {}",
        component_path.display()
    );
    Some(component_path)
}

fn validation_runtime() -> WitToolRuntime {
    WitToolRuntime::new(WitToolRuntimeConfig {
        default_limits: SandboxLimits::default()
            .with_memory_bytes(8 * 1024 * 1024)
            .with_fuel(500_000_000)
            .with_timeout(std::time::Duration::from_secs(10)),
    })
    .unwrap()
}

fn execute_case(
    runtime: &WitToolRuntime,
    prepared: &ironclaw_wasm::PreparedWitTool,
    case_name: &str,
) -> Value {
    let execution = runtime
        .execute(
            prepared,
            WitToolHost::deny_all(),
            WitToolRequest {
                params_json: json!({"case": case_name}).to_string(),
                context_json: None,
            },
        )
        .unwrap_or_else(|error| panic!("case {case_name} failed to execute: {error:?}"));

    assert!(
        execution.error.is_none(),
        "case {case_name} returned guest error: {:?}",
        execution.error
    );
    serde_json::from_str(execution.output_json.as_deref().unwrap())
        .unwrap_or_else(|error| panic!("case {case_name} returned invalid JSON: {error}"))
}

fn assert_case_passed(case_name: &str, output: &Value) {
    assert_eq!(output["case"], case_name);
    assert_eq!(output["status"], "pass");
    assert_eq!(output["error_code"], Value::Null);
}

fn log_record(phase: &str, operation: &str, output: &Value) -> Value {
    json!({
        "phase": phase,
        "operation": operation,
        "status": output["status"],
        "error_code": output["error_code"],
        "error_class": output["error_class"],
        "message": output["message"],
        "component_sha256": env::var("DALEK_WASIP2_COMPONENT_SHA256").unwrap_or_else(|_| "pending".to_string()),
        "wasmtime_version": "46.0.1",
        "iteration_count": output["iteration_count"],
        "memory_limit_bytes": 8 * 1024 * 1024,
        "stack_limit_bytes": 1024 * 1024
    })
}

fn maybe_write_artifacts(
    component_sha256: String,
    lock_sha256: String,
    component_size: u64,
    log_records: &[Value],
) {
    let Some(result_path) = env::var_os("DALEK_WASIP2_RESULT_PATH")
        .map(PathBuf::from)
        .map(workspace_relative_path)
    else {
        return;
    };
    let log_path = env::var_os("DALEK_WASIP2_LOG_PATH")
        .map(PathBuf::from)
        .map(workspace_relative_path)
        .unwrap_or_else(|| workspace_root().join(LOG_ARTIFACT).join("local.jsonl"));

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let jsonl = log_records
        .iter()
        .map(|record| serde_json::to_string(record).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&log_path, format!("{jsonl}\n")).unwrap();

    if let Some(parent) = result_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let result = success_result(
        component_sha256,
        lock_sha256,
        component_size,
        &path_for_result(&log_path),
    );
    let schema = serde_json::from_str::<Value>(RESULT_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&result));
    fs::write(&result_path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
}

fn path_for_result(path: &Path) -> String {
    let root = workspace_root();
    path.strip_prefix(&root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn workspace_relative_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        workspace_root().join(path)
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ironclaw_wasm crate should live under crates/")
        .to_path_buf()
}

fn sha256_file(path: impl AsRef<Path>) -> String {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path.as_ref())
        .output()
        .unwrap_or_else(|error| panic!("failed to run shasum: {error}"));
    assert!(
        output.status.success(),
        "shasum failed for {}",
        path.as_ref().display()
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn success_result(
    component_sha256: String,
    lock_sha256: String,
    component_size: u64,
    log_path: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "validation_name": "Dalek WASI Preview 2",
        "validation_status": "success",
        "source_branch": git_output(["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".to_string()),
        "source_commit": git_output(["rev-parse", "HEAD"]).unwrap_or_else(|| "0000000".to_string()),
        "validation_package": FIXTURE_PACKAGE,
        "component_wasm_sha256": component_sha256,
        "wit_package": "near:agent/sandboxed-tool@0.3.0",
        "toolchain_versions": toolchain_versions(),
        "dependency_config": dependency_config(lock_sha256),
        "test_summary": {"group_a":"pass","group_b":"pass","group_c":"pass","group_d":"pass"},
        "failure_modes": [],
        "resource_observations": resource_observations(component_size),
        "log_artifacts": {"schema_version":1,"path_or_ci_artifact":log_path,"retention_policy":"CI artifact dalek-wasip2-validation retained by workflow defaults","redaction_status":"passed"},
        "fallback_contract": fallback_contract(false),
        "downstream_action": "proceed",
        "binding_artifacts": [
            FIXTURE_MANIFEST,
            FIXTURE_LOCK,
            "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-result.schema.json",
            "crates/ironclaw_wasm/tests/dalek_wasip2_validation.rs"
        ],
        "reproduction_commands": ["scripts/dalek-wasip2-validation.sh"]
    })
}

fn blocker_result() -> Value {
    let mut result = success_result(
        "0".repeat(64),
        "0".repeat(64),
        1,
        "target/dalek-wasip2-validation/logs/local.jsonl",
    );
    result["validation_status"] = json!("blocker");
    result["test_summary"] =
        json!({"group_a":"fail","group_b":"skipped","group_c":"skipped","group_d":"skipped"});
    result["failure_modes"] = json!([{"phase":"component-build","error_code":"build_failed","classification":"blocker","sanitized_summary":"fixture component did not build"}]);
    result["downstream_action"] = json!("block");
    result
}

fn toolchain_versions() -> Value {
    json!({
        "rustc": {"version": command_version("rustc", &["--version"]), "pin_source":"workspace package rust-version"},
        "cargo": {"version": command_version("cargo", &["--version"]), "pin_source":"workspace package rust-version"},
        "cargo_component": {"version": command_version("cargo", &["component", "--version"]), "pin_source":".github/actions/install-cargo-component/action.yml"},
        "wasm_tools": {"version": command_version("wasm-tools", &["--version"]), "pin_source":"scripts/dalek-wasip2-validation.sh"},
        "wasmtime": {"version":"46.0.1","pin_source":"workspace dependencies"},
        "wasm_opt": {"version":null,"pin_source":null}
    })
}

fn command_version(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_string())
        .filter(|stdout| !stdout.is_empty())
        .unwrap_or_else(|| "unavailable in this test process".to_string())
}

fn dependency_config(lock_sha256: String) -> Value {
    json!({
        "cargo_lock_sha256": lock_sha256,
        "crates": [
            {"name":"vodozemac","version":"=0.10.0","features":[],"default_features":false,"source":"registry"},
            {"name":"ed25519-dalek","version":"=3.0.0","features":["alloc","fast","zeroize"],"default_features":false,"source":"registry"},
            {"name":"x25519-dalek","version":"=3.0.0","features":["getrandom","static_secrets","zeroize"],"default_features":false,"source":"registry"},
            {"name":"getrandom","version":"=0.4.3","features":[],"default_features":false,"source":"registry"}
        ]
    })
}

fn resource_observations(component_size: u64) -> Value {
    json!({
        "success_profile": {"memory_limit_bytes":4 * 1024 * 1024,"stack_limit_bytes":1024 * 1024,"fuel_or_epoch_limit":"5000000 fuel, 5s epoch timeout"},
        "too_low_failure_profile": {"memory_limit_bytes":64 * 1024,"stack_limit_bytes":1024 * 1024,"fuel_or_epoch_limit":"1 fuel, 1s epoch timeout","error_code":"resource_limit_exceeded"},
        "steady_state_ed25519_relative_to_native": "benchmark case completed 32 Ed25519 sign/verify iterations in the component; native baseline is intentionally out of scope for this fast gate",
        "steady_state_x25519_relative_to_native": "dalek-positive case completed X25519 shared-secret agreement in the component; native baseline is intentionally out of scope for this fast gate",
        "component_size_bytes": component_size
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
            "host_storage_owner": "host encrypted storage",
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

fn git_output<const N: usize>(args: [&str; N]) -> Option<String> {
    Command::new("git")
        .current_dir(workspace_root())
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_string())
        .filter(|stdout| !stdout.is_empty())
}
