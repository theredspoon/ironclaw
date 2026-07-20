use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use ironclaw_extensions::{
    ExtensionActivationState, ExtensionInstallation, ExtensionInstallationId,
    ExtensionManifestRecord, ExtensionManifestRef, InstallationOwner, MANIFEST_SCHEMA_VERSION,
    ManifestHash, ManifestSource,
};
use ironclaw_filesystem::{CasExpectation, ContentType, Entry};
#[cfg(feature = "libsql")]
use ironclaw_host_api::runtime_policy::{
    ApprovalPolicy, AuditMode, DeploymentMode, EffectiveRuntimePolicy, FilesystemBackendKind,
    NetworkMode, ProcessBackendKind, RuntimeProfile, SecretMode,
};
use ironclaw_host_api::{
    AgentId, CapabilityId, ExtensionId, HostPortCatalog, ProjectId, TenantId, ThreadId, UserId,
};
#[cfg(feature = "libsql")]
use ironclaw_host_api::{NetworkMethod, SecretHandle};
use ironclaw_loop_host::{
    HostManagedModelError, HostManagedModelErrorKind, HostManagedModelGateway,
    HostManagedModelMessageRole, HostManagedModelRequest, HostManagedModelResponse,
};
use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactBinding, ComponentArtifactId, EgressTargetIndex,
    InstallationAuditMetadata, MatrixActivationState, MatrixHomeserverOrigin,
    MatrixInstallationMutation, MatrixInstallationPolicy, MatrixInstallationProjectionCache,
    MatrixProductAdapterInstallation, MatrixRoomId as AdapterMatrixRoomId,
    MatrixRuntimeArtifactEvidence, MatrixUserId, PolicyRevision, StaticManifestBinding,
    WitPackageName, WitWorldName,
};
#[cfg(feature = "libsql")]
use ironclaw_network::{NetworkHttpEgress, NetworkHttpRequest, NetworkHttpResponse, NetworkUsage};
use ironclaw_outbound::{
    CommunicationDeliveryIntent, CommunicationDeliveryResolutionRequest, CommunicationModality,
    OutboundDeliveryStatus, PrepareCommunicationDeliveryRequest, ProjectionUpdateRef,
    RunNotificationContext, RunNotificationEventKind, RunNotificationOrigin, SourceRouteContext,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, DeclaredEgressHost, DeclaredEgressTarget, EgressCredentialHandle,
    FinalReplyView, ProductAdapterId, ProductOutboundPayload, ProductRenderOutcome,
    ProjectionCursor as ProductProjectionCursor,
};
use ironclaw_product_workflow::{
    ProductOutboundDeliveryOutcome, RebornOutboundDeliveryTargetCapabilities,
    RebornOutboundDeliveryTargetId, RebornOutboundDeliveryTargetSummary, RebornServicesError,
    WebUiAuthenticatedCaller,
};
use ironclaw_threads::{LoadContextMessagesRequest, MessageKind, ThreadHistoryRequest};
use ironclaw_turns::{
    ReplyTargetBindingRef, TurnActor, TurnRunId, TurnScope, TurnStatus,
    run_profile::{LoopCapabilityPort, ProviderToolCall, RegisterProviderToolCallRequest},
};

#[cfg(feature = "libsql")]
use crate::RebornRuntimeProcessBinding;
use crate::input::RebornBuildInput;
use crate::matrix_outbound::{
    DeliveryReasonCode, FilesystemMatrixOutboundMetadataStore, FilesystemMatrixPendingIntentStore,
    MatrixPolicyProviderScope,
};
use crate::matrix_product_outbound::{
    FilesystemMatrixPolicySnapshotSource, MatrixPolicyMutationRequest,
    MatrixProductOutboundDeliveryInput, matrix_policy_projection_cache_path_for_route_scope,
    matrix_policy_projection_commit_marker_entry,
    matrix_policy_projection_commit_marker_path_for_cache_path,
    matrix_policy_projection_resource_scope,
    matrix_policy_projection_resource_scope_for_provider_scope,
};
use crate::outbound::outbound_preferences::OutboundDeliveryTargetEntry;
use crate::outbound::{OutboundDeliveryTargetProvider, OutboundDeliveryTargetRegistrationOutcome};
use crate::runtime_input::{PollSettings, RebornRuntimeIdentity, RebornRuntimeInput};
use crate::{
    MatrixOutboundRoomTargetConfig, MatrixOutboundTargetMountConfig,
    MatrixOutboundTargetMountConfigInput, RebornCompositionProfile,
};

use super::build_reborn_runtime;

const RUNTIME_SEND_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Default)]
struct OutboundDeliveryTriggerGateway {
    calls: StdMutex<usize>,
    requests: StdMutex<Vec<HostManagedModelRequest>>,
}

#[cfg(feature = "libsql")]
#[derive(Debug)]
struct RecordingRuntimeNetworkEgress {
    requests: StdMutex<Vec<NetworkHttpRequest>>,
    response: StdMutex<NetworkHttpResponse>,
}

#[cfg(feature = "libsql")]
impl RecordingRuntimeNetworkEgress {
    fn matrix_success() -> Self {
        Self::with_response(
            200,
            br#"{"event_id":"$event:runtime-production-delivery-proof"}"#.to_vec(),
        )
    }

    fn malformed_success_evidence() -> Self {
        Self::with_response(200, br#"{"ok":true}"#.to_vec())
    }

    fn set_malformed_success_evidence(&self) {
        *self
            .response
            .lock()
            .expect("Matrix runtime network response lock poisoned") =
            Self::malformed_success_evidence()
                .response
                .into_inner()
                .expect("fresh response lock");
    }

    fn with_response(status: u16, body: Vec<u8>) -> Self {
        Self {
            requests: StdMutex::new(Vec::new()),
            response: StdMutex::new(NetworkHttpResponse {
                status,
                headers: Vec::new(),
                body,
                usage: NetworkUsage {
                    request_bytes: 128,
                    response_bytes: 64,
                    resolved_ip: None,
                },
            }),
        }
    }

    fn requests(&self) -> Vec<NetworkHttpRequest> {
        self.requests
            .lock()
            .expect("Matrix runtime network requests lock poisoned")
            .clone()
    }
}

#[cfg(feature = "libsql")]
#[async_trait]
impl NetworkHttpEgress for RecordingRuntimeNetworkEgress {
    async fn execute(
        &self,
        request: NetworkHttpRequest,
    ) -> Result<NetworkHttpResponse, ironclaw_network::NetworkHttpError> {
        self.requests
            .lock()
            .expect("Matrix runtime network requests lock poisoned")
            .push(request);
        Ok(self
            .response
            .lock()
            .expect("Matrix runtime network response lock poisoned")
            .clone())
    }
}

#[cfg(feature = "libsql")]
#[derive(Debug)]
struct RecordingSandboxTransport;

#[cfg(feature = "libsql")]
#[async_trait]
impl ironclaw_host_runtime::SandboxCommandTransport for RecordingSandboxTransport {
    async fn run_command(
        &self,
        _request: ironclaw_host_runtime::CommandExecutionRequest,
    ) -> Result<
        ironclaw_host_runtime::CommandExecutionOutput,
        ironclaw_host_runtime::RuntimeProcessError,
    > {
        Ok(ironclaw_host_runtime::CommandExecutionOutput {
            output: String::new(),
            saved_output: None,
            exit_code: 0,
            sandboxed: true,
            duration: Duration::ZERO,
        })
    }
}

#[derive(Clone)]
struct StaticOutboundDeliveryTargetProvider {
    entry: OutboundDeliveryTargetEntry,
}

#[async_trait]
impl OutboundDeliveryTargetProvider for StaticOutboundDeliveryTargetProvider {
    async fn list_outbound_delivery_targets(
        &self,
        _caller: &WebUiAuthenticatedCaller,
    ) -> Result<Vec<OutboundDeliveryTargetEntry>, RebornServicesError> {
        Ok(vec![self.entry.clone()])
    }
}

#[async_trait]
impl HostManagedModelGateway for OutboundDeliveryTriggerGateway {
    async fn stream_model(
        &self,
        request: HostManagedModelRequest,
    ) -> Result<HostManagedModelResponse, HostManagedModelError> {
        self.requests
            .lock()
            .expect("outbound trigger gateway requests lock poisoned")
            .push(request);
        Err(HostManagedModelError::safe(
            HostManagedModelErrorKind::InvalidRequest,
            "expected capability-aware model path",
        ))
    }

    async fn stream_model_with_capabilities(
        &self,
        request: HostManagedModelRequest,
        capabilities: Arc<dyn LoopCapabilityPort>,
    ) -> Result<HostManagedModelResponse, HostManagedModelError> {
        let call_index = {
            let mut calls = self
                .calls
                .lock()
                .expect("outbound trigger gateway call lock poisoned");
            let call_index = *calls;
            *calls += 1;
            call_index
        };
        self.requests
            .lock()
            .expect("outbound trigger gateway requests lock poisoned")
            .push(request.clone());

        if call_index >= 3 {
            let tool_result_count = request
                .messages
                .iter()
                .filter(|message| message.role == HostManagedModelMessageRole::ToolResult)
                .count();
            assert_eq!(
                tool_result_count, 3,
                "final model request should observe list, set, and trigger_create results"
            );
            return Ok(HostManagedModelResponse::assistant_reply(
                "trigger delivery target selected",
            ));
        }

        let tool_definitions = capabilities
            .tool_definitions()
            .map_err(model_capability_error)?;
        let call = match call_index {
            0 => provider_tool_call(
                &tool_definitions,
                "builtin.outbound_delivery_targets_list",
                "call-list-outbound-delivery-targets",
                serde_json::json!({"channel": "slack"}),
            ),
            1 => provider_tool_call(
                &tool_definitions,
                "builtin.outbound_delivery_target_set",
                "call-set-outbound-delivery-target",
                serde_json::json!({"target_id": "slack:test-dm"}),
            ),
            2 => provider_tool_call(
                &tool_definitions,
                "builtin.trigger_create",
                "call-trigger-create",
                serde_json::json!({
                    "name": "Slack status digest",
                    "prompt": "Send the status digest to Slack.",
                    "cron": "0 9 * * *",
                    "timezone": "UTC"
                }),
            ),
            _ => unreachable!("handled above"),
        };
        let candidate = capabilities
            .register_provider_tool_call(RegisterProviderToolCallRequest::new(call))
            .await
            .map_err(model_capability_error)?;
        Ok(HostManagedModelResponse::capability_calls(
            vec![candidate],
            "",
        ))
    }
}

fn runtime_matrix_policy_installation(
    installation_id: &AdapterInstallationId,
    room_id: &str,
) -> MatrixProductAdapterInstallation {
    let credential_handle =
        EgressCredentialHandle::new("matrix-access-token").expect("credential handle");
    let homeserver =
        MatrixHomeserverOrigin::parse("https://matrix.example.org").expect("homeserver origin");
    let allowed_rooms =
        std::collections::BTreeSet::from([AdapterMatrixRoomId::new(room_id).expect("matrix room")]);
    let allowed_senders =
        std::collections::BTreeSet::from([
            MatrixUserId::new("@runtime-user:example.org").expect("matrix user")
        ]);
    let component = ComponentArtifactBinding {
        artifact_id: ComponentArtifactId::new("matrix-component").expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("artifact sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
        manifest: StaticManifestBinding::new("manifest-hash-matrix").expect("manifest hash"),
        declared_egress_targets: vec![DeclaredEgressTarget::new(
            DeclaredEgressHost::new("matrix.example.org").expect("declared host"),
            Some(credential_handle.clone()),
        )],
    };
    let policy = MatrixInstallationPolicy::new(
        homeserver,
        allowed_rooms,
        allowed_senders,
        EgressTargetIndex::new(0),
        credential_handle,
    )
    .expect("matrix policy");
    MatrixProductAdapterInstallation::new(
        ProductAdapterId::new("matrix").expect("adapter id"),
        installation_id.clone(),
        component,
        policy,
        MatrixActivationState::Enabled,
        PolicyRevision::new(7).expect("policy revision"),
        InstallationAuditMetadata::new("runtime-matrix-owner", 1_710_000_000_000)
            .expect("audit metadata"),
    )
    .expect("matrix installation projection")
}

fn runtime_matrix_artifact_evidence() -> MatrixRuntimeArtifactEvidence {
    MatrixRuntimeArtifactEvidence {
        artifact_id: ComponentArtifactId::new("matrix-component").expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("artifact sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
    }
}

fn runtime_matrix_extension_manifest() -> ExtensionManifestRecord {
    ExtensionManifestRecord::from_toml(
        format!(
            r#"
schema_version = "{schema}"
id = "matrix-component"
name = "Matrix Component"
version = "0.1.0"
description = "Matrix ProductAdapter runtime test component"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/matrix.wasm"

[[capabilities]]
id = "matrix-component.echo"
description = "Echoes input"
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/matrix/echo.input.v1.json"
output_schema_ref = "schemas/matrix/echo.output.v1.json"
prompt_doc_ref = "prompts/matrix/echo.md"
"#,
            schema = MANIFEST_SCHEMA_VERSION
        )
        .as_str(),
        ManifestSource::HostBundled,
        &HostPortCatalog::empty(),
        Some(ManifestHash::new("sha256:matrix-component").expect("manifest hash")),
    )
    .expect("matrix manifest")
}

fn runtime_matrix_product_adapter_manifest() -> ExtensionManifestRecord {
    let host_ports =
        ironclaw_host_runtime::default_host_port_catalog().expect("default host port catalog");
    let contracts =
        crate::extension_host::host_api_contracts::product_extension_host_api_contract_registry()
            .expect("host API contracts");
    ExtensionManifestRecord::from_toml_with_contracts(
        format!(
            r#"
schema_version = "{schema}"
id = "matrix-product-adapter"
name = "Matrix ProductAdapter"
version = "0.1.0"
description = "Matrix ProductAdapter runtime mutation test component"
trust = "first_party_requested"

[runtime]
kind = "wasm"
module = "wasm/matrix.wasm"

[[host_api]]
id = "ironclaw.product_adapter/v1"
section = "product_adapter.inbound"

[product_adapter.inbound]
surface_kind = "external_channel"

[product_adapter.inbound.auth]
kind = "shared_secret_header"
header_name = "x-matrix-webhook-secret"

[product_adapter.inbound.capabilities]
flags = ["inbound_messages", "external_final_reply_push"]

[[product_adapter.inbound.required_credentials]]
handle = "runtime-matrix-credential"

[[product_adapter.inbound.egress]]
host = "matrix.example.org"
credential_handle = "runtime-matrix-credential"
"#,
            schema = MANIFEST_SCHEMA_VERSION,
        )
        .as_str(),
        ManifestSource::HostBundled,
        &host_ports,
        Some(ManifestHash::new("sha256:runtime-matrix-product-adapter").expect("manifest hash")),
        &contracts,
    )
    .expect("matrix product adapter manifest")
}

fn runtime_matrix_delivery_request(
    scope: TurnScope,
    actor_user_id: UserId,
    reply_target: ReplyTargetBindingRef,
) -> PrepareCommunicationDeliveryRequest {
    PrepareCommunicationDeliveryRequest {
        resolution_request: CommunicationDeliveryResolutionRequest {
            scope,
            actor: TurnActor::new(actor_user_id),
            modality: CommunicationModality::Text,
            intent: CommunicationDeliveryIntent::RunNotification(RunNotificationContext {
                event_kind: RunNotificationEventKind::FinalReplyReady,
                origin: RunNotificationOrigin::LiveSourceRoute {
                    source_route: SourceRouteContext {
                        reply_target_binding_ref: reply_target,
                    },
                },
            }),
        },
        turn_run_id: Some(TurnRunId::new()),
        projection_ref: ProjectionUpdateRef::new("projection:runtime-matrix-live-caller")
            .expect("projection ref"),
        attempted_at: Utc::now(),
    }
}

fn runtime_matrix_payload() -> ProductOutboundPayload {
    ProductOutboundPayload::FinalReply(FinalReplyView {
        turn_run_id: TurnRunId::new(),
        text: "hello Matrix through runtime".to_string(),
        generated_at: Utc::now(),
    })
}

fn provider_tool_call(
    tool_definitions: &[ironclaw_turns::run_profile::ProviderToolDefinition],
    capability_id: &str,
    call_id: &str,
    arguments: serde_json::Value,
) -> ProviderToolCall {
    let capability_id = CapabilityId::new(capability_id).expect("capability id");
    let tool = tool_definitions
        .iter()
        .find(|definition| definition.capability_id == capability_id)
        .unwrap_or_else(|| panic!("{capability_id} provider tool definition should exist"));
    ProviderToolCall {
        provider_id: "test-provider".to_string(),
        provider_model_id: "test-model".to_string(),
        turn_id: Some("provider-turn-1".to_string()),
        id: call_id.to_string(),
        name: tool.name.clone(),
        arguments,
        response_reasoning: None,
        reasoning: None,
        signature: None,
    }
}

fn model_capability_error(error: impl std::fmt::Display) -> HostManagedModelError {
    let safe_summary = error.to_string();
    HostManagedModelError::safe(HostManagedModelErrorKind::Unavailable, safe_summary)
}

#[tokio::test]
async fn local_dev_runtime_registers_private_matrix_outbound_target_provider_at_build() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let tenant_id = TenantId::new("runtime-matrix-target-tenant").expect("tenant");
    let user_id = UserId::new("runtime-matrix-target-user").expect("user");
    let agent_id = AgentId::new("runtime-matrix-target-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-target-project").expect("project");

    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            "runtime-matrix-target-owner",
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_matrix_outbound_target_mount(MatrixOutboundTargetMountConfig::new(
        MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: AdapterInstallationId::new("runtime-matrix-installation")
                .expect("installation"),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new("!runtime-room:example.org")
                    .expect("valid Matrix room id"),
                user_id.clone(),
                MatrixUserId::new("@runtime-target:example.org").expect("matrix sender"),
            )],
        },
    ));

    let runtime = build_reborn_runtime(input).await.expect("runtime builds");
    let provider = runtime
        .outbound_delivery_target_provider()
        .expect("local runtime outbound target provider");
    let listed = provider
        .list_outbound_delivery_targets(&WebUiAuthenticatedCaller::new(
            tenant_id,
            user_id,
            Some(agent_id),
            Some(project_id),
        ))
        .await
        .expect("Matrix target listing");

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].summary.channel.as_str(), "matrix");
    assert!(listed[0].capabilities.final_replies);
}

#[tokio::test]
async fn local_dev_runtime_accepts_multiple_matrix_outbound_installations() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let tenant_id = TenantId::new("runtime-matrix-multi-install-tenant").expect("tenant");
    let user_id = UserId::new("runtime-matrix-multi-install-user").expect("user");
    let agent_id = AgentId::new("runtime-matrix-multi-install-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-multi-install-project").expect("project");

    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            "runtime-matrix-multi-install-owner",
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_matrix_outbound_target_mounts([
        MatrixOutboundTargetMountConfig::new(MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: AdapterInstallationId::new("runtime-matrix-multi-install-alpha")
                .expect("alpha installation"),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new("!runtime-alpha:example.org")
                    .expect("alpha room"),
                user_id.clone(),
                MatrixUserId::new("@runtime-alpha:example.org").expect("matrix sender"),
            )],
        }),
        MatrixOutboundTargetMountConfig::new(MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: AdapterInstallationId::new("runtime-matrix-multi-install-beta")
                .expect("beta installation"),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new("!runtime-beta:example.org")
                    .expect("beta room"),
                user_id.clone(),
                MatrixUserId::new("@runtime-beta:example.org").expect("matrix sender"),
            )],
        }),
    ]);

    let runtime = build_reborn_runtime(input).await.expect("runtime builds");
    let provider = runtime
        .outbound_delivery_target_provider()
        .expect("local runtime outbound target provider");
    let listed = provider
        .list_outbound_delivery_targets(&WebUiAuthenticatedCaller::new(
            tenant_id,
            user_id,
            Some(agent_id),
            Some(project_id),
        ))
        .await
        .expect("Matrix target listing");

    assert_eq!(listed.len(), 2);
    runtime.shutdown().await.expect("runtime shutdown");
}

#[tokio::test]
async fn local_dev_runtime_applies_matrix_policy_mutation_through_runtime_authority() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let tenant_id = TenantId::new("runtime-matrix-policy-tenant").expect("tenant");
    let user_id = UserId::new("runtime-matrix-policy-owner").expect("user");
    let agent_id = AgentId::new("runtime-matrix-policy-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-policy-project").expect("project");
    let installation_id =
        AdapterInstallationId::new("runtime-matrix-policy-installation").expect("installation");
    let room_id =
        crate::matrix_outbound::MatrixRoomId::new("!runtime-policy-room:example.org".to_string())
            .expect("room");
    let matrix_sender = MatrixUserId::new("@runtime-policy:example.org").expect("matrix sender");
    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            user_id.as_str(),
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_identity(RebornRuntimeIdentity {
        tenant_id: tenant_id.as_str().to_string(),
        agent_id: agent_id.as_str().to_string(),
        source_binding_id: "runtime-matrix-policy-source".to_string(),
        reply_target_binding_id: "runtime-matrix-policy-reply".to_string(),
    })
    .with_default_project_id(project_id.clone())
    .with_matrix_policy_projection_cache(
        crate::MatrixPolicyProjectionCacheConfig::new(
            runtime_matrix_artifact_evidence(),
            "runtime-matrix-owner",
        )
        .expect("Matrix policy projection cache config"),
    )
    .with_matrix_outbound_target_mount(MatrixOutboundTargetMountConfig::new(
        MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                room_id.clone(),
                user_id.clone(),
                matrix_sender.clone(),
            )],
        },
    ));

    let runtime = build_reborn_runtime(input).await.expect("runtime builds");
    let local_runtime = runtime
        .services
        .local_runtime
        .as_ref()
        .expect("local runtime services");
    let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
    local_runtime
        .extension_management
        .as_ref()
        .expect("extension management")
        .installation_store()
        .upsert_manifest_and_installation(
            runtime_matrix_product_adapter_manifest(),
            ExtensionInstallation::new(
                ExtensionInstallationId::new(installation_id.as_str()).expect("extension install"),
                extension_id.clone(),
                ExtensionActivationState::Enabled,
                ExtensionManifestRef::new(
                    extension_id,
                    Some(
                        ManifestHash::new("sha256:runtime-matrix-product-adapter")
                            .expect("manifest hash"),
                    ),
                ),
                vec![],
                Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("extension installation"),
        )
        .await
        .expect("seed Matrix ProductAdapter lifecycle state");

    let upsert = runtime
        .upsert_matrix_room_binding(crate::MatrixRoomBindingUpsertRequest {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            room_id: room_id.clone(),
            subject_user_id: user_id.clone(),
            matrix_sender_user_id: matrix_sender,
        })
        .await
        .expect("runtime room binding mutation initializes Matrix policy source cache");
    assert_eq!(upsert, crate::MatrixRoomBindingUpsertOutcome::Unchanged);

    let policy_scope = matrix_policy_projection_resource_scope_for_provider_scope(
        &TurnScope::new(
            tenant_id.clone(),
            Some(agent_id.clone()),
            Some(project_id.clone()),
            ThreadId::new("runtime-matrix-policy-thread").expect("thread"),
        )
        .to_resource_scope(),
        &MatrixPolicyProviderScope {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
        },
    );
    let policy_cache_path = matrix_policy_projection_cache_path_for_route_scope(
        &tenant_id,
        Some(&agent_id),
        Some(&project_id),
        &installation_id,
    )
    .expect("policy cache path");
    let source = FilesystemMatrixPolicySnapshotSource::new(
        crate::wrap_scoped(Arc::clone(&local_runtime.extension_filesystem)),
        policy_scope,
        policy_cache_path,
    );
    let initial_snapshot = source
        .resolve_enabled_matrix_policy_snapshot_for_installation(&installation_id)
        .await
        .expect("initial runtime-published Matrix policy snapshot");
    assert_eq!(
        initial_snapshot.policy_revision,
        PolicyRevision::new(1).expect("revision")
    );
    let policy = MatrixInstallationPolicy::new(
        initial_snapshot.homeserver.clone(),
        initial_snapshot.allowed_rooms.clone(),
        initial_snapshot.allowed_senders.clone(),
        initial_snapshot.egress_target_index,
        initial_snapshot.credential_handle.clone(),
    )
    .expect("policy from snapshot");

    let outcome = runtime
        .apply_matrix_policy_mutation(MatrixPolicyMutationRequest {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            mutation: MatrixInstallationMutation::UpdatePolicy { policy },
            actor: user_id.as_str().to_string(),
        })
        .await
        .expect("runtime policy mutation reaches MatrixPolicyMutationAuthority");

    assert_eq!(
        outcome.previous_revision,
        PolicyRevision::new(1).expect("previous revision")
    );
    assert_eq!(
        outcome.next_revision,
        PolicyRevision::new(2).expect("next revision")
    );
    let refreshed_snapshot = source
        .resolve_enabled_matrix_policy_snapshot_for_installation(&installation_id)
        .await
        .expect("refreshed runtime-published Matrix policy snapshot");
    assert_eq!(refreshed_snapshot.policy_revision, outcome.next_revision);

    let reconcile_upsert = runtime
        .upsert_matrix_room_binding(crate::MatrixRoomBindingUpsertRequest {
            tenant_id,
            agent_id,
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            room_id,
            subject_user_id: user_id,
            matrix_sender_user_id: MatrixUserId::new("@runtime-policy:example.org")
                .expect("matrix sender"),
        })
        .await
        .expect("runtime room binding refresh reconciles Matrix policy projection");
    assert_eq!(
        reconcile_upsert,
        crate::MatrixRoomBindingUpsertOutcome::Unchanged
    );
    let reconciled_snapshot = source
        .resolve_enabled_matrix_policy_snapshot_for_installation(&installation_id)
        .await
        .expect("reconciled Matrix policy snapshot keeps source revision");
    assert_eq!(
        reconciled_snapshot.policy_revision, outcome.next_revision,
        "ReconcileFromRuntime must not demote a source-owned policy revision"
    );
    runtime.shutdown().await.expect("runtime shutdown");
}

#[tokio::test]
async fn local_dev_runtime_exposes_matrix_product_outbound_live_caller() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let tenant_id = TenantId::new("runtime-matrix-live-caller-tenant").expect("tenant");
    let lifecycle_tenant_id =
        TenantId::new("runtime-matrix-live-caller-lifecycle-tenant").expect("lifecycle tenant");
    let user_id = UserId::new("runtime-matrix-live-caller-owner").expect("user");
    let agent_id = AgentId::new("runtime-matrix-live-caller-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-live-caller-project").expect("project");
    let installation_id = AdapterInstallationId::new("runtime-matrix-live-caller-installation")
        .expect("installation");
    let room_id = "!runtime-live-caller-room:example.org";
    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            user_id.as_str(),
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_identity(RebornRuntimeIdentity {
        tenant_id: tenant_id.as_str().to_string(),
        agent_id: agent_id.as_str().to_string(),
        source_binding_id: "runtime-matrix-live-caller-source".to_string(),
        reply_target_binding_id: "runtime-matrix-live-caller-reply".to_string(),
    })
    .with_default_project_id(project_id.clone())
    .with_matrix_policy_projection_cache(
        crate::MatrixPolicyProjectionCacheConfig::new(
            runtime_matrix_artifact_evidence(),
            "runtime-matrix-owner",
        )
        .expect("Matrix policy projection cache config"),
    )
    .with_matrix_outbound_target_mount(MatrixOutboundTargetMountConfig::new(
        MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new(room_id).expect("room"),
                user_id.clone(),
                MatrixUserId::new("@runtime:example.org").expect("matrix sender"),
            )],
        },
    ));

    let runtime = build_reborn_runtime(input).await.expect("runtime builds");
    let local_runtime = runtime
        .services
        .local_runtime
        .as_ref()
        .expect("local runtime services");
    let workflow_scope = TurnScope::new(
        tenant_id.clone(),
        Some(agent_id.clone()),
        Some(project_id.clone()),
        ThreadId::new("runtime-matrix-live-caller-thread").expect("thread"),
    );
    let lifecycle_scope = TurnScope::new(
        lifecycle_tenant_id,
        Some(agent_id.clone()),
        Some(project_id.clone()),
        ThreadId::new("runtime-matrix-live-caller-lifecycle-thread").expect("thread"),
    )
    .to_resource_scope();
    let policy_provider_scope = MatrixPolicyProviderScope {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        project_id: Some(project_id.clone()),
    };
    let mut policy_cache = MatrixInstallationProjectionCache::new();
    policy_cache
        .insert_projection(
            runtime_matrix_policy_installation(&installation_id, room_id),
            "runtime-matrix-owner",
            1_710_000_000_001,
        )
        .expect("policy projection");
    let policy_filesystem = crate::wrap_scoped(Arc::clone(&local_runtime.extension_filesystem));
    let policy_cache_scope = matrix_policy_projection_resource_scope_for_provider_scope(
        &lifecycle_scope,
        &policy_provider_scope,
    );
    let policy_cache_path = matrix_policy_projection_cache_path_for_route_scope(
        &tenant_id,
        Some(&agent_id),
        Some(&project_id),
        &installation_id,
    )
    .expect("policy cache path");
    let policy_cache_bytes = policy_cache.to_json_bytes().expect("policy cache json");
    policy_filesystem
        .put(
            &policy_cache_scope,
            &policy_cache_path,
            Entry::bytes(policy_cache_bytes.clone()).with_content_type(ContentType::json()),
            CasExpectation::Any,
        )
        .await
        .expect("write Matrix policy projection cache");
    policy_filesystem
        .put(
            &policy_cache_scope,
            &matrix_policy_projection_commit_marker_path_for_cache_path(&policy_cache_path)
                .expect("policy cache commit marker path"),
            matrix_policy_projection_commit_marker_entry(&policy_cache_bytes),
            CasExpectation::Any,
        )
        .await
        .expect("write Matrix policy projection cache commit marker");
    let extension_installation_store = local_runtime
        .extension_management
        .as_ref()
        .expect("extension management")
        .installation_store();
    extension_installation_store
        .upsert_manifest_and_installation(
            runtime_matrix_extension_manifest(),
            ExtensionInstallation::new(
                ExtensionInstallationId::new(installation_id.as_str()).expect("extension install"),
                ExtensionId::new("matrix-component").expect("extension id"),
                ExtensionActivationState::Enabled,
                ExtensionManifestRef::new(
                    ExtensionId::new("matrix-component").expect("extension id"),
                    Some(ManifestHash::new("sha256:matrix-component").expect("manifest hash")),
                ),
                vec![],
                Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("extension installation"),
        )
        .await
        .expect("seed extension lifecycle");
    let provider = runtime
        .outbound_delivery_target_provider()
        .expect("runtime outbound target provider");
    let listed = provider
        .list_outbound_delivery_targets(&WebUiAuthenticatedCaller::new(
            tenant_id.clone(),
            user_id.clone(),
            Some(agent_id.clone()),
            Some(project_id.clone()),
        ))
        .await
        .expect("list Matrix target");
    let reply_target = listed
        .first()
        .expect("configured Matrix target")
        .reply_target_binding_ref
        .clone();

    let outcome = runtime
        .prepare_matrix_product_outbound(MatrixProductOutboundDeliveryInput {
            delivery: runtime_matrix_delivery_request(
                workflow_scope.clone(),
                user_id.clone(),
                reply_target.clone(),
            ),
            payload: runtime_matrix_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:runtime-matrix-live-caller")
                .expect("projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect("Matrix product outbound should route through the composition-owned entrypoint");
    let ProductOutboundDeliveryOutcome::Rendered {
        attempt,
        render_outcome,
    } = outcome
    else {
        panic!("expected Matrix runtime caller to render a deferred delivery");
    };
    assert!(matches!(render_outcome, ProductRenderOutcome::Deferred));
    let attempts = local_runtime
        .outbound_state
        .list_delivery_attempts(workflow_scope.clone())
        .await
        .expect("delivery attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].delivery_id, attempt.delivery_id);
    assert_eq!(attempts[0].status, OutboundDeliveryStatus::Pending);
    let pending_store = FilesystemMatrixPendingIntentStore::new(crate::wrap_scoped(Arc::clone(
        &local_runtime.extension_filesystem,
    )));
    let pending_command = pending_store
        .load_pending_command(
            workflow_scope.clone(),
            attempts[0].delivery_id,
            attempts[0].delivery_id.as_uuid(),
        )
        .await
        .expect("load durable Matrix pending command")
        .expect("runtime caller persists R003A pending Matrix command");
    assert_eq!(pending_command.room_id.as_str(), room_id);
    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        crate::wrap_scoped(Arc::clone(&local_runtime.extension_filesystem)),
        Arc::clone(&local_runtime.outbound_state),
    );
    let retry_schedule = metadata_store
        .load_retry_schedule(workflow_scope.clone(), attempts[0].delivery_id)
        .await
        .expect("load Matrix initial retry schedule")
        .expect("runtime caller persists a due R003A schedule");
    assert_eq!(retry_schedule.attempt_number, 0);
    assert_eq!(retry_schedule.retry_after, Duration::ZERO);
    assert_eq!(retry_schedule.reason, DeliveryReasonCode::MatrixTimeout);
    let retry_context = metadata_store
        .load_retry_execution_context(workflow_scope, attempts[0].delivery_id)
        .await
        .expect("load Matrix retry execution context")
        .expect("runtime caller persists R003A route/grant context");
    assert_eq!(
        retry_context.route().matrix_metadata().room_fingerprint,
        pending_command.room_id.fingerprint()
    );
    assert_eq!(
        retry_context
            .route()
            .matrix_metadata()
            .policy_provider_scope
            .as_ref(),
        Some(&policy_provider_scope)
    );
    runtime.shutdown().await.expect("runtime shutdown");
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn runtime_matrix_pending_final_reply_is_recovered_by_configured_production_retry_worker() {
    let root = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(
        libsql::Builder::new_local(root.path().join("reborn.db"))
            .build()
            .await
            .expect("libsql db"),
    );
    let tenant_id = TenantId::new("runtime-matrix-production-proof-tenant").expect("tenant");
    let user_id = UserId::new("runtime-matrix-production-proof-owner").expect("user");
    let agent_id = AgentId::new("runtime-matrix-production-proof-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-production-proof-project").expect("project");
    let installation_id =
        AdapterInstallationId::new("runtime-matrix-production-proof-installation")
            .expect("installation");
    let room_id = "!runtime-production-proof-room:example.org";
    let workflow_scope = TurnScope::new_with_owner(
        tenant_id.clone(),
        Some(agent_id.clone()),
        Some(project_id.clone()),
        ThreadId::new("runtime-matrix-production-proof-thread").expect("thread"),
        Some(user_id.clone()),
    );
    let discovery_root = TurnScope::new_with_owner(
        tenant_id.clone(),
        Some(agent_id.clone()),
        Some(project_id.clone()),
        ThreadId::new("runtime-matrix-production-proof-discovery-root").expect("thread"),
        Some(user_id.clone()),
    );
    assert_ne!(
        discovery_root, workflow_scope,
        "fixture must not prelist the exact delivery TurnScope"
    );
    let network_egress = Arc::new(RecordingRuntimeNetworkEgress::matrix_success());
    let credential_handle_fingerprint = format!(
        "sha256:{}",
        ironclaw_common::hashing::sha256_hex(b"matrix-access-token")
    );
    let credential_secret =
        SecretHandle::new("matrix_access_token").expect("Matrix credential secret handle");
    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::libsql(
            RebornCompositionProfile::Production,
            "runtime-matrix-production-proof-owner",
            db,
            root.path().join("events.db").to_string_lossy(),
            None,
            ironclaw_secrets::SecretMaterial::from("01234567890123456789012345678901"),
        )
        .with_production_trust_policy(Arc::new(
            crate::builtin_first_party_trust_policy().expect("trust policy"),
        ))
        .with_runtime_policy(EffectiveRuntimePolicy {
            deployment: DeploymentMode::HostedMultiTenant,
            requested_profile: RuntimeProfile::SecureDefault,
            resolved_profile: RuntimeProfile::SecureDefault,
            filesystem_backend: FilesystemBackendKind::ScopedVirtual,
            process_backend: ProcessBackendKind::TenantSandbox,
            network_mode: NetworkMode::Deny,
            secret_mode: SecretMode::BrokeredHandles,
            approval_policy: ApprovalPolicy::AskAlways,
            audit_mode: AuditMode::Standard,
        })
        .with_runtime_process_binding(RebornRuntimeProcessBinding::tenant_sandbox(Arc::new(
            ironclaw_host_runtime::TenantSandboxProcessPort::new(Arc::new(
                RecordingSandboxTransport,
            )),
        )))
        .with_network_http_egress_for_test(network_egress.clone())
        .with_matrix_retry_production_config(
            crate::input::MatrixRetryWorkerProductionConfig::new(
                crate::input::MatrixRetryWorkerProductionConfigInput {
                    settings: crate::matrix_outbound::MatrixRetryWorkerSettings {
                        enabled: true,
                        poll_interval: Duration::from_millis(25),
                        startup_jitter_max: Duration::ZERO,
                        tick_jitter_max: Duration::ZERO,
                        max_entries_per_scope: 10,
                    },
                    scopes: vec![discovery_root],
                    homeserver_origin: "https://matrix.example.org".to_string(),
                    credential_secret: credential_secret.clone(),
                    credential_handle_fingerprint: credential_handle_fingerprint.clone(),
                    capability_id: CapabilityId::new("matrix.send")
                        .expect("Matrix send capability id"),
                },
            ),
        ),
    )
    .with_identity(RebornRuntimeIdentity {
        tenant_id: tenant_id.as_str().to_string(),
        agent_id: agent_id.as_str().to_string(),
        source_binding_id: "runtime-matrix-production-proof-source".to_string(),
        reply_target_binding_id: "runtime-matrix-production-proof-reply".to_string(),
    })
    .with_default_project_id(project_id.clone())
    .with_matrix_policy_projection_cache(
        crate::MatrixPolicyProjectionCacheConfig::new(
            runtime_matrix_artifact_evidence(),
            "runtime-matrix-owner",
        )
        .expect("Matrix policy projection cache config"),
    )
    .with_matrix_outbound_target_mount(MatrixOutboundTargetMountConfig::new(
        MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new(room_id).expect("room"),
                user_id.clone(),
                MatrixUserId::new("@runtime:example.org").expect("matrix sender"),
            )],
        },
    ));

    let mut runtime = build_reborn_runtime(input).await.expect("runtime builds");
    assert!(
        runtime.services.local_runtime.is_none(),
        "fixture must use production-shaped services"
    );
    assert!(
        runtime.matrix_retry_worker_is_running_for_test(),
        "Matrix retry production config should spawn the production retry worker"
    );
    runtime.shutdown_matrix_retry_worker_for_test().await;
    runtime
        .seed_local_dev_secret(
            workflow_scope.to_resource_scope(),
            credential_secret,
            "matrix-access-token".to_string(),
        )
        .await
        .expect("seed Matrix credential material");
    let production_runtime = runtime
        .services
        .production_runtime
        .as_ref()
        .expect("production runtime services");
    let policy_filesystem = production_runtime.scoped_filesystem();
    let outbound_state = production_runtime.outbound_state();
    let extension_installation_store = production_runtime.extension_installation_store();
    let lifecycle_scope = workflow_scope.to_resource_scope();
    let policy_provider_scope = MatrixPolicyProviderScope {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        project_id: Some(project_id.clone()),
    };
    let mut policy_cache = MatrixInstallationProjectionCache::new();
    policy_cache
        .insert_projection(
            runtime_matrix_policy_installation(&installation_id, room_id),
            "runtime-matrix-owner",
            1_710_000_000_001,
        )
        .expect("policy projection");
    let policy_cache_scope = matrix_policy_projection_resource_scope_for_provider_scope(
        &lifecycle_scope,
        &policy_provider_scope,
    );
    let policy_cache_path = matrix_policy_projection_cache_path_for_route_scope(
        &tenant_id,
        Some(&agent_id),
        Some(&project_id),
        &installation_id,
    )
    .expect("policy cache path");
    let policy_cache_bytes = policy_cache.to_json_bytes().expect("policy cache json");
    policy_filesystem
        .put(
            &policy_cache_scope,
            &policy_cache_path,
            Entry::bytes(policy_cache_bytes.clone()).with_content_type(ContentType::json()),
            CasExpectation::Any,
        )
        .await
        .expect("write Matrix policy projection cache");
    policy_filesystem
        .put(
            &policy_cache_scope,
            &matrix_policy_projection_commit_marker_path_for_cache_path(&policy_cache_path)
                .expect("policy cache commit marker path"),
            matrix_policy_projection_commit_marker_entry(&policy_cache_bytes),
            CasExpectation::Any,
        )
        .await
        .expect("write Matrix policy projection cache commit marker");
    extension_installation_store
        .upsert_manifest_and_installation(
            runtime_matrix_extension_manifest(),
            ExtensionInstallation::new(
                ExtensionInstallationId::new(installation_id.as_str()).expect("extension install"),
                ExtensionId::new("matrix-component").expect("extension id"),
                ExtensionActivationState::Enabled,
                ExtensionManifestRef::new(
                    ExtensionId::new("matrix-component").expect("extension id"),
                    Some(ManifestHash::new("sha256:matrix-component").expect("manifest hash")),
                ),
                vec![],
                Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("extension installation"),
        )
        .await
        .expect("seed extension lifecycle");
    let reply_target = runtime
        .outbound_delivery_target_provider()
        .expect("runtime outbound target provider")
        .list_outbound_delivery_targets(&WebUiAuthenticatedCaller::new(
            tenant_id.clone(),
            user_id.clone(),
            Some(agent_id.clone()),
            Some(project_id.clone()),
        ))
        .await
        .expect("list Matrix target")
        .first()
        .expect("configured Matrix target")
        .reply_target_binding_ref
        .clone();

    let outcome = runtime
        .prepare_matrix_product_outbound(MatrixProductOutboundDeliveryInput {
            delivery: runtime_matrix_delivery_request(
                workflow_scope.clone(),
                user_id.clone(),
                reply_target.clone(),
            ),
            payload: runtime_matrix_payload(),
            projection_cursor: ProductProjectionCursor::new(
                "cursor:runtime-matrix-production-proof",
            )
            .expect("projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect("Matrix final reply is persisted as a pending retry intent");
    let ProductOutboundDeliveryOutcome::Rendered {
        attempt,
        render_outcome: ProductRenderOutcome::Deferred,
    } = outcome
    else {
        panic!("expected Matrix runtime caller to render a deferred delivery");
    };

    let metadata_store = FilesystemMatrixOutboundMetadataStore::new(
        Arc::clone(&policy_filesystem),
        Arc::clone(&outbound_state),
    );
    let retry_schedule = metadata_store
        .load_retry_schedule(workflow_scope.clone(), attempt.delivery_id)
        .await
        .expect("load Matrix initial retry schedule")
        .expect("runtime caller persists a due R003A schedule");
    assert_eq!(retry_schedule.attempt_number, 0);
    assert_eq!(retry_schedule.retry_after, Duration::ZERO);
    assert_eq!(retry_schedule.reason, DeliveryReasonCode::MatrixTimeout);
    let due_tick = retry_schedule.recorded_at
        + chrono::Duration::from_std(retry_schedule.retry_after).expect("retry delay");
    assert_eq!(
        due_tick, retry_schedule.recorded_at,
        "initial Matrix retry schedule must be due immediately"
    );

    let report = runtime
        .execute_matrix_retry_tick_once_for_test(due_tick)
        .await
        .expect("runtime should expose the configured production Matrix retry tick for tests");
    assert_eq!(report.scopes_scanned, 1);
    assert_eq!(report.due_schedules, 1);
    assert_eq!(
        report.attempted, 1,
        "production retry proof must consume the durable due schedule through the worker"
    );
    let requests = network_egress.requests();
    assert_eq!(report.delivered, 1);
    assert_eq!(report.retry_scheduled, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.failed, 0);

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, NetworkMethod::Put);
    assert!(requests[0].url.contains("/_matrix/client/v3/rooms/"));
    assert!(requests[0].url.contains("/send/m.room.message/"));
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value.starts_with("Bearer ")),
        "Matrix retry must send with host-staged authorization material"
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .all(|(_, value)| !value.contains("matrix_access_token")),
        "Matrix retry must not leak the adapter credential handle into HTTP headers"
    );

    let status = metadata_store
        .load_delivery_status(workflow_scope.clone(), attempt.delivery_id)
        .await
        .expect("load Matrix shared outbound status")
        .expect("Matrix shared outbound status should be recorded");
    assert_eq!(status.status, OutboundDeliveryStatus::Delivered);
    let shared_attempts = outbound_state
        .list_delivery_attempts(workflow_scope.clone())
        .await
        .expect("load shared outbound attempts");
    assert_eq!(shared_attempts.len(), 1);
    assert_eq!(shared_attempts[0].delivery_id, attempt.delivery_id);
    assert_eq!(shared_attempts[0].status, OutboundDeliveryStatus::Delivered);
    assert!(
        metadata_store
            .load_retry_schedule(workflow_scope.clone(), attempt.delivery_id)
            .await
            .expect("load Matrix retry schedule after worker delivery")
            .is_none(),
        "worker delivery should consume the durable retry schedule"
    );
    let evidence = metadata_store
        .load_evidence(workflow_scope.clone(), attempt.delivery_id)
        .await
        .expect("load Matrix delivery evidence")
        .expect("Matrix evidence should be persisted");
    assert_eq!(evidence.delivery_id, attempt.delivery_id);
    assert_eq!(evidence.attempt_number, 1);
    assert_eq!(evidence.http_status, 200);
    assert_eq!(
        evidence.event_id_fingerprint,
        format!(
            "sha256:{}",
            ironclaw_common::hashing::sha256_hex(b"$event:runtime-production-delivery-proof")
        )
    );
    assert_ne!(
        evidence.event_id_fingerprint,
        "$event:runtime-production-delivery-proof"
    );
    assert_eq!(
        evidence.installation_scoped_credential_ref,
        credential_handle_fingerprint
    );
    assert_ne!(
        evidence.installation_scoped_credential_ref,
        "matrix-access-token"
    );

    network_egress.set_malformed_success_evidence();
    let negative_outcome = runtime
        .prepare_matrix_product_outbound(MatrixProductOutboundDeliveryInput {
            delivery: runtime_matrix_delivery_request(
                workflow_scope.clone(),
                user_id.clone(),
                reply_target,
            ),
            payload: runtime_matrix_payload(),
            projection_cursor: ProductProjectionCursor::new(
                "cursor:runtime-matrix-production-negative-proof",
            )
            .expect("projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect("Matrix negative proof final reply is persisted as pending retry intent");
    let ProductOutboundDeliveryOutcome::Rendered {
        attempt: negative_attempt,
        render_outcome: ProductRenderOutcome::Deferred,
    } = negative_outcome
    else {
        panic!("expected Matrix runtime caller to render a deferred negative delivery");
    };
    let negative_schedule = metadata_store
        .load_retry_schedule(workflow_scope.clone(), negative_attempt.delivery_id)
        .await
        .expect("load negative Matrix initial retry schedule")
        .expect("negative proof starts with a due schedule");
    assert_eq!(negative_schedule.retry_after, Duration::ZERO);
    let negative_due_tick = negative_schedule.recorded_at;
    let negative_report = runtime
        .execute_matrix_retry_tick_once_for_test(negative_due_tick)
        .await
        .expect("negative proof retry tick uses configured production dependencies");
    assert_eq!(negative_report.due_schedules, 1);
    assert_eq!(negative_report.attempted, 1);
    assert_eq!(negative_report.delivered, 0);
    assert_eq!(negative_report.retry_scheduled, 1);
    assert_eq!(negative_report.failed, 0);
    let negative_requests = network_egress.requests();
    assert_eq!(negative_requests.len(), 2);
    assert!(
        metadata_store
            .load_evidence(workflow_scope.clone(), negative_attempt.delivery_id)
            .await
            .expect("load negative Matrix evidence")
            .is_none(),
        "malformed success evidence must not be recorded as delivered evidence"
    );
    let negative_status = metadata_store
        .load_delivery_status(workflow_scope.clone(), negative_attempt.delivery_id)
        .await
        .expect("load negative Matrix delivery status");
    assert!(
        !matches!(
            negative_status.as_ref().map(|status| status.status),
            Some(OutboundDeliveryStatus::Delivered)
        ),
        "malformed success evidence must not mark Matrix metadata delivered"
    );
    let negative_shared_attempt = outbound_state
        .list_delivery_attempts(workflow_scope.clone())
        .await
        .expect("load negative shared outbound attempts")
        .into_iter()
        .find(|attempt| attempt.delivery_id == negative_attempt.delivery_id)
        .expect("negative shared outbound attempt should exist");
    assert_eq!(
        negative_shared_attempt.status,
        OutboundDeliveryStatus::Pending
    );
    let rescheduled = metadata_store
        .load_retry_schedule(workflow_scope.clone(), negative_attempt.delivery_id)
        .await
        .expect("load rescheduled Matrix retry")
        .expect("malformed success evidence should keep retry state");
    assert_eq!(rescheduled.attempt_number, 1);
    assert_eq!(
        rescheduled.reason,
        DeliveryReasonCode::MatrixMalformedResponse
    );

    runtime.shutdown().await.expect("runtime shutdown");
}

#[tokio::test]
async fn local_dev_runtime_matrix_product_outbound_disabled_extension_fails_before_handoff() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let tenant_id = TenantId::new("runtime-matrix-disabled-tenant").expect("tenant");
    let user_id = UserId::new("runtime-matrix-live-caller-owner").expect("user");
    let agent_id = AgentId::new("runtime-matrix-disabled-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-disabled-project").expect("project");
    let installation_id =
        AdapterInstallationId::new("runtime-matrix-disabled-installation").expect("installation");
    let room_id = "!runtime-disabled-room:example.org";
    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            user_id.as_str(),
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_identity(RebornRuntimeIdentity {
        tenant_id: tenant_id.as_str().to_string(),
        agent_id: agent_id.as_str().to_string(),
        source_binding_id: "runtime-matrix-disabled-source".to_string(),
        reply_target_binding_id: "runtime-matrix-disabled-reply".to_string(),
    })
    .with_default_project_id(project_id.clone())
    .with_matrix_policy_projection_cache(
        crate::MatrixPolicyProjectionCacheConfig::new(
            runtime_matrix_artifact_evidence(),
            "runtime-matrix-owner",
        )
        .expect("Matrix policy projection cache config"),
    )
    .with_matrix_outbound_target_mount(MatrixOutboundTargetMountConfig::new(
        MatrixOutboundTargetMountConfigInput {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            installation_id: installation_id.clone(),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new(room_id).expect("room"),
                user_id.clone(),
                MatrixUserId::new("@runtime:example.org").expect("matrix sender"),
            )],
        },
    ));

    let runtime = build_reborn_runtime(input).await.expect("runtime builds");
    let local_runtime = runtime
        .services
        .local_runtime
        .as_ref()
        .expect("local runtime services");
    let workflow_scope = TurnScope::new(
        tenant_id.clone(),
        Some(agent_id.clone()),
        Some(project_id.clone()),
        ThreadId::new("runtime-matrix-disabled-thread").expect("thread"),
    );
    let mut policy_cache = MatrixInstallationProjectionCache::new();
    policy_cache
        .insert_projection(
            runtime_matrix_policy_installation(&installation_id, room_id),
            "runtime-matrix-owner",
            1_710_000_000_001,
        )
        .expect("policy projection");
    let policy_cache_bytes = policy_cache.to_json_bytes().expect("policy cache json");
    let policy_cache_path = matrix_policy_projection_cache_path_for_route_scope(
        &tenant_id,
        Some(&agent_id),
        Some(&project_id),
        &installation_id,
    )
    .expect("policy cache path");
    let policy_cache_scope =
        matrix_policy_projection_resource_scope(&workflow_scope.to_resource_scope());
    let policy_filesystem = crate::wrap_scoped(Arc::clone(&local_runtime.extension_filesystem));
    policy_filesystem
        .put(
            &policy_cache_scope,
            &policy_cache_path,
            Entry::bytes(policy_cache_bytes.clone()).with_content_type(ContentType::json()),
            CasExpectation::Any,
        )
        .await
        .expect("write Matrix policy projection cache");
    policy_filesystem
        .put(
            &policy_cache_scope,
            &matrix_policy_projection_commit_marker_path_for_cache_path(&policy_cache_path)
                .expect("policy cache commit marker path"),
            matrix_policy_projection_commit_marker_entry(&policy_cache_bytes),
            CasExpectation::Any,
        )
        .await
        .expect("write Matrix policy projection cache commit marker");
    local_runtime
        .extension_management
        .as_ref()
        .expect("extension management")
        .installation_store()
        .upsert_manifest_and_installation(
            runtime_matrix_extension_manifest(),
            ExtensionInstallation::new(
                ExtensionInstallationId::new(installation_id.as_str()).expect("extension install"),
                ExtensionId::new("matrix-component").expect("extension id"),
                ExtensionActivationState::Disabled,
                ExtensionManifestRef::new(
                    ExtensionId::new("matrix-component").expect("extension id"),
                    Some(ManifestHash::new("sha256:matrix-component").expect("manifest hash")),
                ),
                vec![],
                Utc::now(),
                InstallationOwner::Tenant,
            )
            .expect("extension installation"),
        )
        .await
        .expect("seed disabled extension lifecycle");
    let reply_target = runtime
        .outbound_delivery_target_provider()
        .expect("runtime outbound target provider")
        .list_outbound_delivery_targets(&WebUiAuthenticatedCaller::new(
            tenant_id.clone(),
            user_id.clone(),
            Some(agent_id.clone()),
            Some(project_id.clone()),
        ))
        .await
        .expect("list Matrix target")
        .into_iter()
        .next()
        .expect("configured Matrix target")
        .reply_target_binding_ref;

    let error = runtime
        .prepare_matrix_product_outbound(MatrixProductOutboundDeliveryInput {
            delivery: runtime_matrix_delivery_request(
                workflow_scope.clone(),
                user_id.clone(),
                reply_target,
            ),
            payload: runtime_matrix_payload(),
            projection_cursor: ProductProjectionCursor::new("cursor:runtime-matrix-disabled")
                .expect("projection cursor"),
            require_direct_message_target: false,
        })
        .await
        .expect_err("disabled Matrix extension fails before R003A handoff");

    assert!(matches!(
        error,
        crate::matrix_product_outbound::MatrixProductOutboundDeliveryError::Lifecycle(_)
    ));
    let attempts = local_runtime
        .outbound_state
        .list_delivery_attempts(workflow_scope)
        .await
        .expect("delivery attempts");
    assert!(attempts.is_empty());
    runtime.shutdown().await.expect("runtime shutdown");
}

#[tokio::test]
async fn local_dev_runtime_rejects_duplicate_matrix_outbound_target_provider_scope() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let tenant_id = TenantId::new("runtime-matrix-duplicate-tenant").expect("tenant");
    let user_id = UserId::new("runtime-matrix-duplicate-user").expect("user");
    let agent_id = AgentId::new("runtime-matrix-duplicate-agent").expect("agent");
    let project_id = ProjectId::new("runtime-matrix-duplicate-project").expect("project");
    let duplicate_config =
        MatrixOutboundTargetMountConfig::new(MatrixOutboundTargetMountConfigInput {
            tenant_id,
            agent_id,
            project_id: Some(project_id),
            installation_id: AdapterInstallationId::new("runtime-matrix-duplicate-installation")
                .expect("installation"),
            room_targets: vec![MatrixOutboundRoomTargetConfig::new(
                crate::matrix_outbound::MatrixRoomId::new("!runtime-duplicate-room:example.org")
                    .expect("valid Matrix room id"),
                user_id,
                MatrixUserId::new("@runtime-duplicate:example.org").expect("matrix sender"),
            )],
        });

    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            "runtime-matrix-duplicate-owner",
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_matrix_outbound_target_mounts([duplicate_config.clone(), duplicate_config]);

    let error = match build_reborn_runtime(input).await {
        Ok(_) => panic!("duplicate Matrix provider scope should fail runtime build"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("duplicate Matrix outbound"),
        "unexpected duplicate provider error: {error}"
    );
}

#[tokio::test]
async fn local_dev_runtime_selects_outbound_delivery_target_before_trigger_create() {
    let root = tempfile::tempdir().expect("tempdir");
    let host_home = root.path().join("host-home");
    std::fs::create_dir_all(&host_home).expect("host home");
    let gateway = Arc::new(OutboundDeliveryTriggerGateway::default());
    let gateway_for_runtime: Arc<dyn HostManagedModelGateway> = gateway.clone();
    let input = RebornRuntimeInput::from_services(
        RebornBuildInput::local_dev_with_profile(
            RebornCompositionProfile::LocalDevYolo,
            "runtime-outbound-trigger-owner",
            root.path().join("local-dev"),
        )
        .with_runtime_policy(
            crate::local_dev_yolo_runtime_policy(true).expect("local-yolo policy resolves"),
        )
        .with_local_dev_confirmed_host_home_root(host_home),
    )
    .with_identity(RebornRuntimeIdentity {
        tenant_id: "runtime-outbound-trigger-tenant".to_string(),
        agent_id: "runtime-outbound-trigger-agent".to_string(),
        source_binding_id: "runtime-outbound-trigger-source".to_string(),
        reply_target_binding_id: "runtime-outbound-trigger-reply".to_string(),
    })
    .with_poll_settings(PollSettings {
        interval: Duration::from_millis(10),
        max_total: RUNTIME_SEND_TIMEOUT,
    })
    .with_model_gateway_override(gateway_for_runtime);

    let runtime = build_reborn_runtime(input).await.expect("runtime builds");
    let slack_target_id = RebornOutboundDeliveryTargetId::new("slack:test-dm").expect("target id");
    let registered = runtime.register_outbound_delivery_target_provider(
        "slack:test",
        Arc::new(StaticOutboundDeliveryTargetProvider {
            entry: OutboundDeliveryTargetEntry {
                summary: RebornOutboundDeliveryTargetSummary::new(
                    slack_target_id,
                    "slack",
                    "Slack DM",
                    Some("Personal Slack direct message".to_string()),
                )
                .expect("target summary"),
                capabilities: RebornOutboundDeliveryTargetCapabilities {
                    final_replies: true,
                    gate_prompts: false,
                    auth_prompts: false,
                },
                reply_target_binding_ref: ReplyTargetBindingRef::new("reply:test:slack-dm")
                    .expect("reply target"),
            },
        }),
    );
    assert_eq!(
        registered.expect("test Slack target provider should register"),
        OutboundDeliveryTargetRegistrationOutcome::Registered
    );

    let conversation = runtime.new_conversation().await.expect("conversation");
    let reply = tokio::time::timeout(
        RUNTIME_SEND_TIMEOUT,
        runtime.send_user_message(
            &conversation,
            "Create a daily trigger and send the result to my Slack DM.",
        ),
    )
    .await
    .expect("runtime send should finish")
    .expect("runtime send should succeed");

    assert_eq!(reply.status, TurnStatus::Completed);
    assert_eq!(
        reply.text.as_deref(),
        Some("trigger delivery target selected")
    );
    let history = runtime
        .thread_service
        .list_thread_history(ThreadHistoryRequest {
            scope: runtime.thread_scope.clone(),
            thread_id: conversation.0.clone(),
        })
        .await
        .expect("thread history");
    let tool_result_ids = history
        .messages
        .iter()
        .filter(|message| message.kind == MessageKind::ToolResultReference)
        .map(|message| message.message_id)
        .collect::<Vec<_>>();
    assert_eq!(
        tool_result_ids.len(),
        3,
        "runtime should persist list, set, and trigger_create tool results"
    );
    let context = runtime
        .thread_service
        .load_context_messages(LoadContextMessagesRequest {
            scope: runtime.thread_scope.clone(),
            thread_id: conversation.0.clone(),
            message_ids: tool_result_ids,
        })
        .await
        .expect("tool result context");
    let invoked_capability_ids = context
        .messages
        .iter()
        .map(|message| {
            message
                .tool_result_provider_call
                .as_ref()
                .expect("provider replay metadata")
                .capability_id
                .as_str()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        invoked_capability_ids,
        vec![
            "builtin.outbound_delivery_targets_list",
            "builtin.outbound_delivery_target_set",
            "builtin.trigger_create",
        ],
        "Slack trigger delivery should list targets, select one, then create the trigger"
    );

    runtime.shutdown().await.expect("runtime shutdown");
}
