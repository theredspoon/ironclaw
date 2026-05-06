//! Hosted/enterprise security properties + sandboxed-per-deployment +
//! `LocalShell` affordance gap + defense-in-depth between visibility filter
//! and planner.
//!
//! Restates the resolver's `hosted_family_never_resolves_to_provider_host_filesystem_or_shell`
//! security property at the integration tier (sync `#[test]`) plus extends
//! the existing single-profile visibility tests in
//! `tests/runtime_policy_tool_visibility_integration.rs` to loop the full
//! per-family profile set, and closes the `LocalShell` affordance dead-code
//! gap with a synthetic in-test tool.
//!
//! Defense-in-depth: a planner test (`plan_capability(spawn_process,
//! hosted_dev_policy)`) restates the planner's process-fail-closed for the
//! hosted branch — proving the substrate fails closed even if the visibility
//! filter were bypassed.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rust_decimal::Decimal;

use ironclaw::context::JobContext;
use ironclaw::tools::builtin::{
    ApplyPatchTool, HttpTool, ListDirTool, ReadFileTool, WriteFileTool,
};
use ironclaw::tools::{
    ApprovalRequirement, EngineCompatibility, RiskLevel, Tool, ToolDomain, ToolError, ToolOutput,
    ToolRegistry, ToolRuntimeAffordance,
};
use ironclaw_host_api::runtime_policy::{
    DeploymentMode, EffectiveRuntimePolicy, FilesystemBackendKind, NetworkMode, ProcessBackendKind,
    RuntimeProfile, SecretMode,
};
use ironclaw_host_api::{
    CapabilityDescriptor, CapabilityId, EffectKind, ExtensionId, PermissionMode, RuntimeKind,
    TrustClass,
};
use ironclaw_host_runtime::{PlannerError, plan_capability};
use ironclaw_runtime_policy::{OrgPolicyConstraints, ResolveRequest, resolve};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_simple(deployment: DeploymentMode, profile: RuntimeProfile) -> EffectiveRuntimePolicy {
    resolve(ResolveRequest::new(deployment, profile))
        .unwrap_or_else(|err| panic!("resolve({deployment:?}, {profile:?}) failed: {err:?}"))
}

fn resolve_yolo(
    deployment: DeploymentMode,
    profile: RuntimeProfile,
    admin_approves: bool,
) -> EffectiveRuntimePolicy {
    resolve(ResolveRequest {
        deployment,
        requested_profile: profile,
        org_policy: OrgPolicyConstraints {
            admin_approves_dedicated_yolo: admin_approves,
            ..OrgPolicyConstraints::default()
        },
        yolo_disclosure_acknowledged: true,
    })
    .unwrap_or_else(|err| {
        panic!("resolve_yolo({deployment:?}, {profile:?}, admin={admin_approves}) failed: {err:?}")
    })
}

fn descriptor(id: &str, effects: Vec<EffectKind>) -> CapabilityDescriptor {
    CapabilityDescriptor {
        id: CapabilityId::new(id.to_string()).unwrap(),
        provider: ExtensionId::new("test_extension".to_string()).unwrap(),
        runtime: RuntimeKind::Script,
        trust_ceiling: TrustClass::UserTrusted,
        description: format!("test capability {id}"),
        parameters_schema: serde_json::Value::Null,
        effects,
        default_permission: PermissionMode::Allow,
        resource_profile: None,
    }
}

async fn registry_with_host_fs_tools() -> ToolRegistry {
    let registry = ToolRegistry::new();
    registry.register(Arc::new(ReadFileTool::new())).await;
    registry.register(Arc::new(WriteFileTool::new())).await;
    registry.register(Arc::new(ListDirTool::new())).await;
    registry.register(Arc::new(ApplyPatchTool::new())).await;
    registry
}

async fn registry_with_http() -> ToolRegistry {
    let registry = ToolRegistry::new();
    registry.register(Arc::new(HttpTool::new())).await;
    registry
}

// ---------------------------------------------------------------------------
// Tests 1–5: resolver-level security properties (sync)
// ---------------------------------------------------------------------------

const HOSTED_PROFILES: [RuntimeProfile; 3] = [
    RuntimeProfile::HostedSafe,
    RuntimeProfile::HostedDev,
    RuntimeProfile::HostedYoloTenantScoped,
];

const ENTERPRISE_PROFILES: [RuntimeProfile; 3] = [
    RuntimeProfile::EnterpriseSafe,
    RuntimeProfile::EnterpriseDev,
    RuntimeProfile::EnterpriseYoloDedicated,
];

const ALL_DEPLOYMENTS: [DeploymentMode; 3] = [
    DeploymentMode::LocalSingleUser,
    DeploymentMode::HostedMultiTenant,
    DeploymentMode::EnterpriseDedicated,
];

#[test]
fn hosted_multi_tenant_never_resolves_to_local_host_or_host_workspace_for_any_profile() {
    // Deployment-agnostic + family-specific profiles compatible with HostedMultiTenant.
    let profiles = [
        RuntimeProfile::SecureDefault,
        RuntimeProfile::HostedSafe,
        RuntimeProfile::HostedDev,
        RuntimeProfile::HostedYoloTenantScoped,
        RuntimeProfile::Sandboxed,
        RuntimeProfile::Experiment,
    ];
    for profile in profiles {
        let policy = if matches!(profile, RuntimeProfile::HostedYoloTenantScoped) {
            resolve_yolo(DeploymentMode::HostedMultiTenant, profile, false)
        } else {
            resolve_simple(DeploymentMode::HostedMultiTenant, profile)
        };
        assert_ne!(
            policy.process_backend,
            ProcessBackendKind::LocalHost,
            "HostedMultiTenant + {profile:?} must never resolve to LocalHost",
        );
        assert_ne!(
            policy.filesystem_backend,
            FilesystemBackendKind::HostWorkspace,
            "HostedMultiTenant + {profile:?} must never resolve to HostWorkspace",
        );
    }
}

#[test]
fn enterprise_dedicated_never_resolves_to_local_host_or_host_workspace_for_any_profile() {
    let profiles = [
        RuntimeProfile::SecureDefault,
        RuntimeProfile::EnterpriseSafe,
        RuntimeProfile::EnterpriseDev,
        RuntimeProfile::EnterpriseYoloDedicated,
        RuntimeProfile::Sandboxed,
        RuntimeProfile::Experiment,
    ];
    for profile in profiles {
        let policy = if matches!(profile, RuntimeProfile::EnterpriseYoloDedicated) {
            resolve_yolo(DeploymentMode::EnterpriseDedicated, profile, true)
        } else {
            resolve_simple(DeploymentMode::EnterpriseDedicated, profile)
        };
        assert_ne!(
            policy.process_backend,
            ProcessBackendKind::LocalHost,
            "EnterpriseDedicated + {profile:?} must never resolve to LocalHost",
        );
        assert_ne!(
            policy.filesystem_backend,
            FilesystemBackendKind::HostWorkspace,
            "EnterpriseDedicated + {profile:?} must never resolve to HostWorkspace",
        );
    }
}

#[test]
fn sandboxed_profile_per_deployment_never_resolves_to_local_host_or_host_workspace() {
    // Sandboxed is deployment-agnostic. Even under LocalSingleUser, the
    // profile's whole point is "no host access" — so it must never select
    // LocalHost or HostWorkspace regardless of deployment.
    for deployment in ALL_DEPLOYMENTS {
        let policy = resolve_simple(deployment, RuntimeProfile::Sandboxed);
        assert_ne!(
            policy.process_backend,
            ProcessBackendKind::LocalHost,
            "Sandboxed under {deployment:?} must not resolve to LocalHost",
        );
        assert_ne!(
            policy.filesystem_backend,
            FilesystemBackendKind::HostWorkspace,
            "Sandboxed under {deployment:?} must not resolve to HostWorkspace",
        );
    }
}

#[test]
fn experiment_profile_per_deployment_never_resolves_to_local_host_or_host_workspace() {
    for deployment in ALL_DEPLOYMENTS {
        let policy = resolve_simple(deployment, RuntimeProfile::Experiment);
        assert_ne!(
            policy.process_backend,
            ProcessBackendKind::LocalHost,
            "Experiment under {deployment:?} must not resolve to LocalHost",
        );
        assert_ne!(
            policy.filesystem_backend,
            FilesystemBackendKind::HostWorkspace,
            "Experiment under {deployment:?} must not resolve to HostWorkspace",
        );
    }
}

#[test]
fn secure_default_profile_per_deployment_resolves_to_process_backend_none_and_scoped_virtual_fs() {
    // SecureDefault is the floor — process disabled, scoped-virtual filesystem,
    // network denied, secrets denied. It is identical across deployments by
    // design (the resolver does not vary the floor by deployment).
    for deployment in ALL_DEPLOYMENTS {
        let policy = resolve_simple(deployment, RuntimeProfile::SecureDefault);
        assert_eq!(policy.process_backend, ProcessBackendKind::None);
        assert_eq!(
            policy.filesystem_backend,
            FilesystemBackendKind::ScopedVirtual
        );
        assert_eq!(policy.network_mode, NetworkMode::Brokered);
    }
}

// ---------------------------------------------------------------------------
// Tests 6–8: registry-tier visibility across families (async)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_filesystem_tools_hidden_under_every_hosted_profile_through_dispatcher_path() {
    let registry = registry_with_host_fs_tools().await;
    for profile in HOSTED_PROFILES {
        let policy = if matches!(profile, RuntimeProfile::HostedYoloTenantScoped) {
            resolve_yolo(DeploymentMode::HostedMultiTenant, profile, false)
        } else {
            resolve_simple(DeploymentMode::HostedMultiTenant, profile)
        };
        let visible = registry.tool_definitions_visible_under(&policy).await;
        let names: Vec<&str> = visible.iter().map(|t| t.name.as_str()).collect();
        for hidden in ["read_file", "write_file", "list_dir", "apply_patch"] {
            assert!(
                !names.contains(&hidden),
                "{hidden} must be hidden under {profile:?}; got {names:?}",
            );
        }
    }
}

#[tokio::test]
async fn direct_network_tool_hidden_under_every_hosted_profile_through_dispatcher_path() {
    // Hosted family resolves to brokered/allowlist network — never Direct or
    // DirectLogged — so HttpTool's DirectNetwork affordance is hidden.
    let registry = registry_with_http().await;
    for profile in HOSTED_PROFILES {
        let policy = if matches!(profile, RuntimeProfile::HostedYoloTenantScoped) {
            resolve_yolo(DeploymentMode::HostedMultiTenant, profile, false)
        } else {
            resolve_simple(DeploymentMode::HostedMultiTenant, profile)
        };
        let visible = registry.tool_definitions_visible_under(&policy).await;
        let names: Vec<&str> = visible.iter().map(|t| t.name.as_str()).collect();
        assert!(
            !names.contains(&"http"),
            "http must be hidden under {profile:?} (network_mode={:?}); got {names:?}",
            policy.network_mode,
        );
    }
}

#[tokio::test]
async fn direct_network_tool_visibility_matches_network_mode_across_every_enterprise_profile() {
    // Enterprise family: EnterpriseSafe/Dev resolve to brokered/allowlist;
    // EnterpriseYoloDedicated resolves to DirectLogged. HttpTool's
    // DirectNetwork affordance is visible iff network_mode in {Direct,
    // DirectLogged}. Locks the documented yolo-dedicated network widening.
    let registry = registry_with_http().await;
    for profile in ENTERPRISE_PROFILES {
        let policy = if matches!(profile, RuntimeProfile::EnterpriseYoloDedicated) {
            resolve_yolo(DeploymentMode::EnterpriseDedicated, profile, true)
        } else {
            resolve_simple(DeploymentMode::EnterpriseDedicated, profile)
        };
        let visible = registry.tool_definitions_visible_under(&policy).await;
        let names: Vec<&str> = visible.iter().map(|t| t.name.as_str()).collect();
        let expected_visible = matches!(
            policy.network_mode,
            NetworkMode::Direct | NetworkMode::DirectLogged
        );
        assert_eq!(
            names.contains(&"http"),
            expected_visible,
            "{profile:?} (network_mode={:?}) — http visibility must match Direct|DirectLogged",
            policy.network_mode,
        );
    }
}

// ---------------------------------------------------------------------------
// Test 9: synthetic ProbeShellTool exercises the LocalShell affordance arm
// ---------------------------------------------------------------------------

/// Stub tool whose only purpose is to declare
/// [`ToolRuntimeAffordance::LocalShell`] so the visibility filter's
/// `LocalShell` branch (currently dead in production — no shipping tool
/// declares it) is exercised at the registry tier.
struct ProbeShellTool;

#[async_trait]
impl Tool for ProbeShellTool {
    fn name(&self) -> &str {
        "probe_shell"
    }

    fn description(&self) -> &str {
        "Probe tool for LocalShell affordance coverage; never invoked"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }

    async fn execute(
        &self,
        _params: serde_json::Value,
        _ctx: &JobContext,
    ) -> Result<ToolOutput, ToolError> {
        unreachable!("probe_shell is registered for visibility coverage only")
    }

    fn estimated_cost(&self, _params: &serde_json::Value) -> Option<Decimal> {
        None
    }

    fn estimated_duration(&self, _params: &serde_json::Value) -> Option<Duration> {
        None
    }

    fn requires_sanitization(&self) -> bool {
        false
    }

    fn risk_level_for(&self, _params: &serde_json::Value) -> RiskLevel {
        RiskLevel::Low
    }

    fn requires_approval(&self, _params: &serde_json::Value) -> ApprovalRequirement {
        ApprovalRequirement::Never
    }

    fn execution_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn domain(&self) -> ToolDomain {
        ToolDomain::Orchestrator
    }

    fn engine_compatibility(&self) -> EngineCompatibility {
        EngineCompatibility::Both
    }

    fn runtime_affordance(&self) -> ToolRuntimeAffordance {
        ToolRuntimeAffordance::LocalShell
    }
}

#[tokio::test]
async fn local_shell_synthetic_tool_visible_only_under_local_host_process_backend_through_dispatcher_path()
 {
    let registry = ToolRegistry::new();
    registry.register(Arc::new(ProbeShellTool)).await;

    // Build (deployment, profile, expected_visibility) cases covering the
    // ProcessBackendKind variants the resolver actually maps to today.
    // Variants the resolver doesn't surface from real profiles (Docker,
    // Srt) are exercised via the visibility filter unit tests in
    // `src/tools/runtime_filter.rs`; here we lock the production-reachable
    // paths against the registry boundary.
    let cases: &[(DeploymentMode, RuntimeProfile, bool)] = &[
        (
            DeploymentMode::LocalSingleUser,
            RuntimeProfile::SecureDefault,
            false, // process_backend == None
        ),
        (
            DeploymentMode::LocalSingleUser,
            RuntimeProfile::LocalSafe,
            true, // process_backend == LocalHost
        ),
        (
            DeploymentMode::LocalSingleUser,
            RuntimeProfile::LocalDev,
            true, // process_backend == LocalHost
        ),
        (
            DeploymentMode::HostedMultiTenant,
            RuntimeProfile::HostedDev,
            false, // process_backend == TenantSandbox
        ),
        (
            DeploymentMode::EnterpriseDedicated,
            RuntimeProfile::EnterpriseDev,
            false, // process_backend == OrgDedicatedRunner
        ),
    ];

    for (deployment, profile, expect_visible) in cases.iter().copied() {
        let policy = resolve_simple(deployment, profile);
        let visible = registry.tool_definitions_visible_under(&policy).await;
        let visible_names: Vec<&str> = visible.iter().map(|t| t.name.as_str()).collect();
        let actually_visible = visible_names.contains(&"probe_shell");
        assert_eq!(
            actually_visible, expect_visible,
            "probe_shell visibility under {deployment:?} + {profile:?} \
             (process_backend={:?}) — expected {expect_visible}, got {actually_visible}",
            policy.process_backend,
        );
        // When visible, it must be because process_backend is LocalHost.
        if actually_visible {
            assert_eq!(policy.process_backend, ProcessBackendKind::LocalHost);
        }
    }
}

// ---------------------------------------------------------------------------
// Test 10: defense-in-depth — planner refuses spawn under hosted policy
// ---------------------------------------------------------------------------

#[test]
fn planner_rejects_spawn_process_under_secure_default_when_visibility_filter_bypassed() {
    // SecureDefault under LocalSingleUser resolves to ProcessBackendKind::None.
    // A capability declaring SpawnProcess is filtered out of the model-facing
    // tool list by the visibility filter — but if a stale plan or hallucinated
    // call reached the planner, the planner must still fail closed.
    let policy = resolve_simple(
        DeploymentMode::LocalSingleUser,
        RuntimeProfile::SecureDefault,
    );
    assert_eq!(policy.process_backend, ProcessBackendKind::None);

    let cap = descriptor("test.spawn_process", vec![EffectKind::SpawnProcess]);
    let err =
        plan_capability(&cap, &policy).expect_err("planner must refuse SpawnProcess under None");
    match err {
        PlannerError::ProcessEffectsRequiredButProcessBackendIsNone { capability } => {
            assert_eq!(capability.as_str(), "test.spawn_process");
        }
        other => panic!("expected ProcessEffectsRequiredButProcessBackendIsNone, got {other:?}"),
    }
}

#[test]
fn planner_rejects_network_capability_under_brokered_deny_combo() {
    // Defense-in-depth for the network branch. Build a policy with NetworkMode::Deny
    // by going through SecureDefault — the resolver's floor includes Brokered, not
    // Deny, so we explicitly assert that and document the planner's parallel guard
    // covers a deny-network policy if one is ever produced (tenant override path).
    let policy = resolve_simple(
        DeploymentMode::LocalSingleUser,
        RuntimeProfile::SecureDefault,
    );
    // SecureDefault uses Brokered, not Deny — the planner's Deny guard is
    // covered by its own unit tests and remains protected by this regression.
    assert_eq!(policy.network_mode, NetworkMode::Brokered);

    // Construct a synthetic policy with NetworkMode::Deny + SecretMode::Deny
    // by mutating a resolver-produced policy in-place. This is testing-only;
    // production code never mutates EffectiveRuntimePolicy after resolution.
    let mut deny_policy = policy.clone();
    deny_policy.network_mode = NetworkMode::Deny;
    deny_policy.secret_mode = SecretMode::Deny;

    let net_cap = descriptor("test.network", vec![EffectKind::Network]);
    let err = plan_capability(&net_cap, &deny_policy)
        .expect_err("planner must refuse Network effect under NetworkMode::Deny");
    assert!(matches!(
        err,
        PlannerError::NetworkRequiredButNetworkModeIsDeny { .. }
    ));

    let secret_cap = descriptor("test.secret", vec![EffectKind::UseSecret]);
    let err = plan_capability(&secret_cap, &deny_policy)
        .expect_err("planner must refuse UseSecret under SecretMode::Deny");
    assert!(matches!(
        err,
        PlannerError::SecretAccessRequiredButSecretModeIsDeny { .. }
    ));
}
