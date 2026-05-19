use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex as StdMutex},
};

use chrono::Utc;
use uuid::Uuid;

use ironclaw_host_api::{
    CapabilityGrant, CapabilityGrantId, CapabilityId, CapabilitySet, EffectKind, ExecutionContext,
    ExtensionId, GrantConstraints, MountAlias, MountGrant, MountPermissions, MountView,
    NetworkPolicy, Principal, RuntimeKind, TrustClass, UserId, VirtualPath,
};
use ironclaw_host_runtime::{
    CapabilitySurfacePolicy, HostRuntime, SurfaceKind,
    VisibleCapabilityRequest as HostVisibleCapabilityRequest,
};
use ironclaw_loop_support::{
    HostManagedModelError, HostManagedModelErrorKind, HostManagedModelGateway,
    HostManagedModelMessageRole, HostManagedModelRequest, HostManagedModelResponse,
    HostRuntimeLoopCapabilityPortFactory, LoopCapabilityInputResolver, LoopCapabilityResultWriter,
    loop_driver_execution_extension_id,
};
use ironclaw_reborn::loop_driver_host::LoopCapabilityPortFactory;
use ironclaw_threads::{ToolResultReferenceEnvelope, ToolResultSafeSummary};
use ironclaw_trust::{AuthorityCeiling, EffectiveTrustClass, TrustDecision, TrustProvenance};
use ironclaw_turns::{
    LoopResultRef,
    run_profile::{
        AgentLoopHostError, AgentLoopHostErrorKind, CapabilityInputRef, LoopCapabilityPort,
        LoopHostMilestoneSink, LoopRunContext, ProviderToolCall,
    },
};

pub(super) struct LocalDevCapabilityWiring {
    pub(super) capability_factory: Arc<dyn LoopCapabilityPortFactory>,
    pub(super) model_gateway: Arc<dyn HostManagedModelGateway>,
}

pub(super) fn capability_wiring(
    runtime: Arc<dyn HostRuntime>,
    user_id: UserId,
    model_gateway: Arc<dyn HostManagedModelGateway>,
    milestone_sink: Option<Arc<dyn LoopHostMilestoneSink>>,
) -> LocalDevCapabilityWiring {
    let capability_io = Arc::new(LocalDevCapabilityIo::default());
    let capability_input_resolver: Arc<dyn LoopCapabilityInputResolver> = capability_io.clone();
    let capability_result_writer: Arc<dyn LoopCapabilityResultWriter> = capability_io.clone();
    let capability_factory: Arc<dyn LoopCapabilityPortFactory> =
        Arc::new(LocalDevLoopCapabilityPortFactory::new(
            runtime,
            user_id,
            capability_input_resolver,
            capability_result_writer,
            milestone_sink,
        ));
    let model_gateway: Arc<dyn HostManagedModelGateway> = Arc::new(
        LocalDevResultHydratingModelGateway::new(model_gateway, capability_io),
    );

    LocalDevCapabilityWiring {
        capability_factory,
        model_gateway,
    }
}

#[derive(Clone)]
struct LocalDevLoopCapabilityPortFactory {
    runtime: Arc<dyn HostRuntime>,
    user_id: UserId,
    input_resolver: Arc<dyn LoopCapabilityInputResolver>,
    result_writer: Arc<dyn LoopCapabilityResultWriter>,
    milestone_sink: Option<Arc<dyn LoopHostMilestoneSink>>,
}

impl LocalDevLoopCapabilityPortFactory {
    fn new(
        runtime: Arc<dyn HostRuntime>,
        user_id: UserId,
        input_resolver: Arc<dyn LoopCapabilityInputResolver>,
        result_writer: Arc<dyn LoopCapabilityResultWriter>,
        milestone_sink: Option<Arc<dyn LoopHostMilestoneSink>>,
    ) -> Self {
        Self {
            runtime,
            user_id,
            input_resolver,
            result_writer,
            milestone_sink,
        }
    }
}

#[async_trait::async_trait]
impl LoopCapabilityPortFactory for LocalDevLoopCapabilityPortFactory {
    async fn create_capability_port(
        &self,
        run_context: &LoopRunContext,
    ) -> Result<Arc<dyn LoopCapabilityPort>, AgentLoopHostError> {
        let execution_mounts = local_dev_workspace_mounts()?;
        let visible_request = local_dev_visible_capability_request(
            run_context,
            self.user_id.clone(),
            execution_mounts.clone(),
        )?;
        let factory = HostRuntimeLoopCapabilityPortFactory::new(
            Arc::clone(&self.runtime),
            visible_request,
            Arc::clone(&self.input_resolver),
            Arc::clone(&self.result_writer),
            self.milestone_sink.clone(),
        )
        .with_execution_mounts(execution_mounts);
        Ok(factory.for_run_context(run_context.clone()))
    }
}

const LOCAL_DEV_CAPABILITY_IO_MAX_STAGED_REFS: usize = 1024;

#[derive(Default)]
struct LocalDevCapabilityIo {
    inputs: StdMutex<HashMap<String, serde_json::Value>>,
    results: StdMutex<HashMap<String, serde_json::Value>>,
}

impl LocalDevCapabilityIo {
    fn result_output(
        &self,
        result_ref: &str,
    ) -> Result<Option<serde_json::Value>, AgentLoopHostError> {
        self.results
            .lock()
            .map_err(|_| capability_io_error())
            .map(|results| results.get(result_ref).cloned())
    }
}

#[async_trait::async_trait]
impl LoopCapabilityInputResolver for LocalDevCapabilityIo {
    async fn resolve_capability_input(
        &self,
        run_context: &LoopRunContext,
        input_ref: &CapabilityInputRef,
    ) -> Result<serde_json::Value, AgentLoopHostError> {
        ensure_local_dev_ref_scope("input", input_ref.as_str(), run_context)?;
        let mut inputs = self.inputs.lock().map_err(|_| capability_io_error())?;
        inputs.remove(input_ref.as_str()).ok_or_else(|| {
            AgentLoopHostError::new(
                AgentLoopHostErrorKind::InvalidInvocation,
                "capability input ref was not staged for this loop run",
            )
        })
    }

    async fn register_provider_tool_call_input(
        &self,
        run_context: &LoopRunContext,
        tool_call: &ProviderToolCall,
    ) -> Result<CapabilityInputRef, AgentLoopHostError> {
        let input_ref =
            CapabilityInputRef::new(format!("input:{}:{}", run_context.run_id, Uuid::new_v4()))
                .map_err(|_| {
                    AgentLoopHostError::new(
                        AgentLoopHostErrorKind::Internal,
                        "capability input ref could not be represented",
                    )
                })?;
        let mut inputs = self.inputs.lock().map_err(|_| capability_io_error())?;
        if inputs.len() >= LOCAL_DEV_CAPABILITY_IO_MAX_STAGED_REFS {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::BudgetExceeded,
                "local-dev capability input staging is full",
            ));
        }
        inputs.insert(input_ref.as_str().to_string(), tool_call.arguments.clone());
        Ok(input_ref)
    }
}

#[async_trait::async_trait]
impl LoopCapabilityResultWriter for LocalDevCapabilityIo {
    async fn write_capability_result(
        &self,
        run_context: &LoopRunContext,
        _capability_id: &CapabilityId,
        output: serde_json::Value,
    ) -> Result<LoopResultRef, AgentLoopHostError> {
        let result_ref =
            LoopResultRef::new(format!("result:{}.{}", run_context.run_id, Uuid::new_v4()))
                .map_err(|_| {
                    AgentLoopHostError::new(
                        AgentLoopHostErrorKind::Internal,
                        "capability result ref could not be represented",
                    )
                })?;
        let mut results = self.results.lock().map_err(|_| capability_io_error())?;
        if results.len() >= LOCAL_DEV_CAPABILITY_IO_MAX_STAGED_REFS {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::BudgetExceeded,
                "local-dev capability result staging is full",
            ));
        }
        results.insert(result_ref.as_str().to_string(), output);
        Ok(result_ref)
    }
}

/// Local-dev replay shim for model-visible tool results.
///
/// Thread transcripts store safe result refs. This runtime-local shim dereferences outputs staged
/// by `LocalDevCapabilityIo` before delegating to the selected model gateway, so REPL follow-up
/// turns see actual host-runtime tool output without making CLI own capability storage.
#[derive(Clone)]
struct LocalDevResultHydratingModelGateway {
    inner: Arc<dyn HostManagedModelGateway>,
    capability_io: Arc<LocalDevCapabilityIo>,
}

impl LocalDevResultHydratingModelGateway {
    fn new(
        inner: Arc<dyn HostManagedModelGateway>,
        capability_io: Arc<LocalDevCapabilityIo>,
    ) -> Self {
        Self {
            inner,
            capability_io,
        }
    }

    fn hydrate_request(
        &self,
        request: HostManagedModelRequest,
    ) -> Result<HostManagedModelRequest, HostManagedModelError> {
        hydrate_tool_result_messages(request, self.capability_io.as_ref())
    }
}

#[async_trait::async_trait]
impl HostManagedModelGateway for LocalDevResultHydratingModelGateway {
    async fn stream_model(
        &self,
        request: HostManagedModelRequest,
    ) -> Result<HostManagedModelResponse, HostManagedModelError> {
        self.inner
            .stream_model(self.hydrate_request(request)?)
            .await
    }

    async fn stream_model_with_capabilities(
        &self,
        request: HostManagedModelRequest,
        capabilities: Arc<dyn LoopCapabilityPort>,
    ) -> Result<HostManagedModelResponse, HostManagedModelError> {
        self.inner
            .stream_model_with_capabilities(self.hydrate_request(request)?, capabilities)
            .await
    }
}

fn hydrate_tool_result_messages(
    mut request: HostManagedModelRequest,
    capability_io: &LocalDevCapabilityIo,
) -> Result<HostManagedModelRequest, HostManagedModelError> {
    for message in &mut request.messages {
        if message.role != HostManagedModelMessageRole::ToolResult {
            continue;
        }
        let mut envelope: ToolResultReferenceEnvelope = serde_json::from_str(&message.content)
            .map_err(|_| {
                HostManagedModelError::safe(
                    HostManagedModelErrorKind::InvalidRequest,
                    "tool result reference transcript content is invalid",
                )
            })?;
        let output = capability_io
            .result_output(&envelope.result_ref)
            .map_err(model_capability_io_error)?;
        let Some(output) = output else {
            continue;
        };
        envelope.safe_summary = ToolResultSafeSummary::new(model_visible_tool_output(&output))
            .map_err(|_| {
                HostManagedModelError::safe(
                    HostManagedModelErrorKind::InvalidRequest,
                    "tool result output could not be represented safely for model replay",
                )
            })?;
        message.content = serde_json::to_string(&envelope).map_err(|error| {
            HostManagedModelError::safe(
                HostManagedModelErrorKind::InvalidRequest,
                error.to_string(),
            )
        })?;
    }
    Ok(request)
}

/// Convert local-dev tool output into a `ToolResultSafeSummary`-compatible replay string.
/// This is not product-live canonical result storage; it is a bounded local-dev bridge so provider
/// follow-up calls receive useful output while preserving the transcript safe-summary contract.
fn model_visible_tool_output(output: &serde_json::Value) -> String {
    let raw = match output {
        serde_json::Value::String(text) => format!("tool output {text}"),
        value => format!("tool output {value}"),
    };
    let mut sanitized = raw
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '{' | '}' | '[' | ']' | '`' | '<' | '>' | '/' | '\\'
                )
            {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if sanitized.len() > 480 {
        sanitized.truncate(480);
    }
    let sanitized = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    if ToolResultSafeSummary::new(sanitized.clone()).is_ok() {
        sanitized
    } else {
        "tool output available".to_string()
    }
}

fn model_capability_io_error(error: AgentLoopHostError) -> HostManagedModelError {
    HostManagedModelError::safe(HostManagedModelErrorKind::Unavailable, error.safe_summary)
}

fn local_dev_visible_capability_request(
    run_context: &LoopRunContext,
    user_id: UserId,
    execution_mounts: MountView,
) -> Result<HostVisibleCapabilityRequest, AgentLoopHostError> {
    let extension_id = loop_driver_execution_extension_id(run_context)?;
    let grants = local_dev_builtin_grants(&extension_id, execution_mounts)?;
    let mut context = ExecutionContext::local_default(
        user_id,
        extension_id,
        RuntimeKind::FirstParty,
        TrustClass::UserTrusted,
        grants,
        MountView::default(),
    )
    .map_err(host_api_agent_loop_error)?;
    context.tenant_id = run_context.scope.tenant_id.clone();
    context.agent_id = run_context.scope.agent_id.clone();
    context.project_id = run_context.scope.project_id.clone();
    context.thread_id = Some(run_context.thread_id.clone());
    context.resource_scope.tenant_id = context.tenant_id.clone();
    context.resource_scope.agent_id = context.agent_id.clone();
    context.resource_scope.project_id = context.project_id.clone();
    context.resource_scope.thread_id = context.thread_id.clone();
    context.validate().map_err(host_api_agent_loop_error)?;

    let builtin_provider = ExtensionId::new("builtin").map_err(host_api_agent_loop_error)?;
    let mut provider_trust = BTreeMap::new();
    provider_trust.insert(
        builtin_provider,
        TrustDecision {
            effective_trust: EffectiveTrustClass::user_trusted(),
            authority_ceiling: AuthorityCeiling {
                allowed_effects: local_dev_allowed_effects(),
                max_resource_ceiling: None,
            },
            provenance: TrustProvenance::AdminConfig,
            evaluated_at: Utc::now(),
        },
    );

    Ok(HostVisibleCapabilityRequest::new(
        context,
        SurfaceKind::new("agent_loop").map_err(host_api_agent_loop_error)?,
    )
    .with_policy(CapabilitySurfacePolicy::allow_all())
    .with_provider_trust(provider_trust))
}

fn local_dev_builtin_grants(
    grantee: &ExtensionId,
    mounts: MountView,
) -> Result<CapabilitySet, AgentLoopHostError> {
    let mut grants = Vec::new();
    for capability_id in local_dev_builtin_capability_ids() {
        grants.push(CapabilityGrant {
            id: CapabilityGrantId::new(),
            capability: CapabilityId::new(capability_id).map_err(host_api_agent_loop_error)?,
            grantee: Principal::Extension(grantee.clone()),
            issued_by: Principal::HostRuntime,
            constraints: GrantConstraints {
                allowed_effects: local_dev_allowed_effects(),
                mounts: mounts.clone(),
                network: NetworkPolicy::default(),
                secrets: Vec::new(),
                resource_ceiling: None,
                expires_at: None,
                max_invocations: None,
            },
        });
    }
    Ok(CapabilitySet { grants })
}

fn local_dev_builtin_capability_ids() -> [&'static str; 9] {
    [
        "builtin.echo",
        "builtin.time",
        "builtin.json",
        "builtin.read_file",
        "builtin.write_file",
        "builtin.list_dir",
        "builtin.glob",
        "builtin.grep",
        "builtin.apply_patch",
    ]
}

fn local_dev_allowed_effects() -> Vec<EffectKind> {
    vec![
        EffectKind::DispatchCapability,
        EffectKind::ReadFilesystem,
        EffectKind::WriteFilesystem,
    ]
}

fn local_dev_workspace_mounts() -> Result<MountView, AgentLoopHostError> {
    MountView::new(vec![MountGrant::new(
        MountAlias::new("/workspace").map_err(host_api_agent_loop_error)?,
        VirtualPath::new("/projects/workspace").map_err(host_api_agent_loop_error)?,
        MountPermissions::read_write(),
    )])
    .map_err(host_api_agent_loop_error)
}

fn ensure_local_dev_ref_scope(
    prefix: &str,
    reference: &str,
    run_context: &LoopRunContext,
) -> Result<(), AgentLoopHostError> {
    let expected_prefix = format!("{prefix}:{}:", run_context.run_id);
    if reference.starts_with(&expected_prefix) {
        Ok(())
    } else {
        Err(AgentLoopHostError::new(
            AgentLoopHostErrorKind::ScopeMismatch,
            "capability input ref is not scoped to this loop run",
        ))
    }
}

fn capability_io_error() -> AgentLoopHostError {
    AgentLoopHostError::new(
        AgentLoopHostErrorKind::Internal,
        "capability io store is unavailable",
    )
}

fn host_api_agent_loop_error(error: impl std::fmt::Display) -> AgentLoopHostError {
    AgentLoopHostError::new(AgentLoopHostErrorKind::InvalidInvocation, error.to_string())
}
