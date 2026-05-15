use ironclaw_agent_loop::test_support::{MockAgentLoopDriverHost, ScenarioScript};
use ironclaw_reborn::{PlannedDriver, build_loop_family_registry};
use ironclaw_turns::{
    AgentLoopDriverResumeRequest, AgentLoopDriverRunRequest, LoopExit, LoopMessageRef,
    TurnCheckpointId,
    run_profile::{
        AgentLoopDriver, AgentLoopDriverError, AgentLoopHostError, AgentLoopHostErrorKind,
        AppendCapabilityResultRef, BeginAssistantDraft, CapabilityBatchInvocation,
        CapabilityBatchOutcome, CapabilityInvocation, CapabilityOutcome, FinalizeAssistantMessage,
        LoadCheckpointPayloadRequest, LoadedCheckpointPayload, LoopCapabilityPort,
        LoopCheckpointPort, LoopCheckpointRequest, LoopCheckpointStateRef, LoopContextBundle,
        LoopContextPort, LoopContextRequest, LoopInputBatch, LoopInputCursor, LoopInputPort,
        LoopModelPort, LoopModelRequest, LoopModelResponse, LoopProgressEvent, LoopProgressPort,
        LoopPromptBundle, LoopPromptBundleRequest, LoopPromptPort, LoopRunContext, LoopRunInfoPort,
        LoopTranscriptPort, StageCheckpointPayloadRequest, UpdateAssistantDraft,
        VisibleCapabilityRequest, VisibleCapabilitySurface,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn run_request(
    driver: &PlannedDriver,
    host: &MockAgentLoopDriverHost,
) -> AgentLoopDriverRunRequest {
    let mut profile = host.run_context().resolved_run_profile.clone();
    let descriptor = driver.descriptor();
    profile.loop_driver = descriptor.clone();
    profile.checkpoint_schema_id = descriptor
        .checkpoint_schema_id
        .clone()
        .expect("planned driver descriptor should carry checkpoint schema");
    profile.checkpoint_schema_version = descriptor
        .checkpoint_schema_version
        .expect("planned driver descriptor should carry checkpoint version");
    AgentLoopDriverRunRequest {
        turn_id: host.run_context().turn_id,
        run_id: host.run_context().run_id,
        resolved_run_profile: profile,
    }
}

fn resume_request(
    context: &LoopRunContext,
    checkpoint_id: TurnCheckpointId,
) -> AgentLoopDriverResumeRequest {
    AgentLoopDriverResumeRequest {
        turn_id: context.turn_id,
        run_id: context.run_id,
        checkpoint_id,
        resolved_run_profile: context.resolved_run_profile.clone(),
    }
}

fn run_context_for_driver(driver: &PlannedDriver) -> LoopRunContext {
    let (host, _) = MockAgentLoopDriverHost::builder()
        .script(ScenarioScript::reply_only("hi"))
        .build();
    let mut context = host.run_context().clone();
    let descriptor = driver.descriptor();
    context.resolved_run_profile.loop_driver = descriptor.clone();
    context.resolved_run_profile.checkpoint_schema_id = descriptor
        .checkpoint_schema_id
        .clone()
        .expect("planned driver descriptor should carry checkpoint schema");
    context.resolved_run_profile.checkpoint_schema_version = descriptor
        .checkpoint_schema_version
        .expect("planned driver descriptor should carry checkpoint version");
    context.loop_driver_id = descriptor.id;
    context.loop_driver_version = descriptor.version;
    context.checkpoint_schema_id = context.resolved_run_profile.checkpoint_schema_id.clone();
    context.checkpoint_schema_version = context.resolved_run_profile.checkpoint_schema_version;
    context
}

#[tokio::test]
async fn default_planned_driver_smoke() {
    let registry = build_loop_family_registry().expect("registry should build");
    let driver = PlannedDriver::default_from_registry(&registry).expect("driver should build");
    let (host, _) = MockAgentLoopDriverHost::builder()
        .script(ScenarioScript::reply_only("hi"))
        .build();

    let exit = driver
        .run(run_request(&driver, &host), &host)
        .await
        .expect("planned driver run should succeed");

    assert!(matches!(exit, LoopExit::Completed(_)));
    assert_eq!(driver.descriptor().id.as_str(), "reborn:planned-default");
}

#[tokio::test]
async fn planned_driver_executor_error_maps_to_unavailable() {
    let registry = build_loop_family_registry().expect("registry should build");
    let driver = PlannedDriver::default_from_registry(&registry).expect("driver should build");
    let (host, _) = MockAgentLoopDriverHost::builder()
        .script(ScenarioScript::reply_only("hi"))
        .fail_prompt_with(AgentLoopHostErrorKind::Unavailable)
        .build();

    let error = driver
        .run(run_request(&driver, &host), &host)
        .await
        .expect_err("model unavailability should map to driver error");

    assert_eq!(
        error,
        AgentLoopDriverError::Unavailable {
            reason: "Prompt: unavailable".to_string()
        }
    );
    let debug = format!("{error:?}");
    assert!(!debug.contains("sk-fake"));
    assert!(!debug.contains("/host/path"));
}

#[tokio::test]
async fn planned_driver_rejects_mismatched_profile_assignment() {
    let registry = build_loop_family_registry().expect("registry should build");
    let driver = PlannedDriver::default_from_registry(&registry).expect("driver should build");
    let (host, _) = MockAgentLoopDriverHost::builder()
        .script(ScenarioScript::reply_only("hi"))
        .build();
    let mut request = run_request(&driver, &host);
    request.resolved_run_profile.loop_driver.version = ironclaw_turns::RunProfileVersion::new(99);

    let error = driver
        .run(request, &host)
        .await
        .expect_err("mismatched descriptor should be rejected");

    assert!(matches!(error, AgentLoopDriverError::InvalidRequest { .. }));
}

#[tokio::test]
async fn planned_driver_resume_rejects_mismatched_ids_before_checkpoint_load() {
    let registry = build_loop_family_registry().expect("registry should build");
    let driver = PlannedDriver::default_from_registry(&registry).expect("driver should build");
    let context = run_context_for_driver(&driver);
    let host = ForbiddenResumeHost::new(context.clone());
    let mut request = resume_request(&context, TurnCheckpointId::new());
    let other_context = ironclaw_agent_loop::test_support::test_run_context("foreign-run");
    request.turn_id = other_context.turn_id;
    request.run_id = other_context.run_id;

    let error = driver
        .resume(request, &host)
        .await
        .expect_err("mismatched request ids should be rejected");

    assert_eq!(
        error,
        AgentLoopDriverError::InvalidRequest {
            reason: "driver request does not match loop host run context".to_string()
        }
    );
    host.assert_no_checkpoint_load_or_host_side_effects();
}

#[tokio::test]
async fn planned_driver_resume_rejects_mismatched_profile_before_checkpoint_load() {
    let registry = build_loop_family_registry().expect("registry should build");
    let driver = PlannedDriver::default_from_registry(&registry).expect("driver should build");
    let context = run_context_for_driver(&driver);
    let host = ForbiddenResumeHost::new(context.clone());
    let mut request = resume_request(&context, TurnCheckpointId::new());
    let other_context = ironclaw_agent_loop::test_support::test_run_context("foreign-profile");
    request.resolved_run_profile.context_profile_id =
        other_context.resolved_run_profile.context_profile_id;

    let error = driver
        .resume(request, &host)
        .await
        .expect_err("mismatched request profile should be rejected");

    assert_eq!(
        error,
        AgentLoopDriverError::InvalidRequest {
            reason: "driver request profile does not match loop host run context".to_string()
        }
    );
    host.assert_no_checkpoint_load_or_host_side_effects();
}

struct ForbiddenResumeHost {
    context: LoopRunContext,
    checkpoint_load_calls: AtomicUsize,
    host_side_effect_calls: AtomicUsize,
}

impl ForbiddenResumeHost {
    fn new(context: LoopRunContext) -> Self {
        Self {
            context,
            checkpoint_load_calls: AtomicUsize::new(0),
            host_side_effect_calls: AtomicUsize::new(0),
        }
    }

    fn forbidden_call(&self, method: &'static str) -> AgentLoopHostError {
        self.host_side_effect_calls.fetch_add(1, Ordering::SeqCst);
        AgentLoopHostError::new(
            AgentLoopHostErrorKind::Internal,
            format!("{method} should not be called for invalid resume request context"),
        )
    }

    fn assert_no_checkpoint_load_or_host_side_effects(&self) {
        assert_eq!(
            self.checkpoint_load_calls.load(Ordering::SeqCst),
            0,
            "invalid resume context must fail before checkpoint payload load"
        );
        assert_eq!(
            self.host_side_effect_calls.load(Ordering::SeqCst),
            0,
            "invalid resume context must fail before host side effects"
        );
    }
}

impl LoopRunInfoPort for ForbiddenResumeHost {
    fn run_context(&self) -> &LoopRunContext {
        &self.context
    }
}

#[async_trait::async_trait]
impl LoopContextPort for ForbiddenResumeHost {
    async fn load_loop_context(
        &self,
        _request: LoopContextRequest,
    ) -> Result<LoopContextBundle, AgentLoopHostError> {
        Err(self.forbidden_call("load_loop_context"))
    }
}

#[async_trait::async_trait]
impl LoopPromptPort for ForbiddenResumeHost {
    async fn build_prompt_bundle(
        &self,
        _request: LoopPromptBundleRequest,
    ) -> Result<LoopPromptBundle, AgentLoopHostError> {
        Err(self.forbidden_call("build_prompt_bundle"))
    }
}

#[async_trait::async_trait]
impl LoopInputPort for ForbiddenResumeHost {
    async fn poll_inputs(
        &self,
        _after: LoopInputCursor,
        _limit: usize,
    ) -> Result<LoopInputBatch, AgentLoopHostError> {
        Err(self.forbidden_call("poll_inputs"))
    }

    async fn ack_inputs(&self, _cursor: LoopInputCursor) -> Result<(), AgentLoopHostError> {
        Err(self.forbidden_call("ack_inputs"))
    }
}

#[async_trait::async_trait]
impl LoopModelPort for ForbiddenResumeHost {
    async fn stream_model(
        &self,
        _request: LoopModelRequest,
    ) -> Result<LoopModelResponse, AgentLoopHostError> {
        Err(self.forbidden_call("stream_model"))
    }
}

#[async_trait::async_trait]
impl LoopCapabilityPort for ForbiddenResumeHost {
    async fn visible_capabilities(
        &self,
        _request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, AgentLoopHostError> {
        Err(self.forbidden_call("visible_capabilities"))
    }

    async fn invoke_capability(
        &self,
        _request: CapabilityInvocation,
    ) -> Result<CapabilityOutcome, AgentLoopHostError> {
        Err(self.forbidden_call("invoke_capability"))
    }

    async fn invoke_capability_batch(
        &self,
        _request: CapabilityBatchInvocation,
    ) -> Result<CapabilityBatchOutcome, AgentLoopHostError> {
        Err(self.forbidden_call("invoke_capability_batch"))
    }
}

#[async_trait::async_trait]
impl LoopTranscriptPort for ForbiddenResumeHost {
    async fn begin_assistant_draft(
        &self,
        _request: BeginAssistantDraft,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        Err(self.forbidden_call("begin_assistant_draft"))
    }

    async fn update_assistant_draft(
        &self,
        _request: UpdateAssistantDraft,
    ) -> Result<(), AgentLoopHostError> {
        Err(self.forbidden_call("update_assistant_draft"))
    }

    async fn finalize_assistant_message(
        &self,
        _request: FinalizeAssistantMessage,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        Err(self.forbidden_call("finalize_assistant_message"))
    }

    async fn append_capability_result_ref(
        &self,
        _request: AppendCapabilityResultRef,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        Err(self.forbidden_call("append_capability_result_ref"))
    }
}

#[async_trait::async_trait]
impl LoopCheckpointPort for ForbiddenResumeHost {
    async fn checkpoint(
        &self,
        _request: LoopCheckpointRequest,
    ) -> Result<TurnCheckpointId, AgentLoopHostError> {
        Err(self.forbidden_call("checkpoint"))
    }

    async fn stage_checkpoint_payload(
        &self,
        _request: StageCheckpointPayloadRequest,
    ) -> Result<LoopCheckpointStateRef, AgentLoopHostError> {
        Err(self.forbidden_call("stage_checkpoint_payload"))
    }

    async fn load_checkpoint_payload(
        &self,
        _request: LoadCheckpointPayloadRequest,
    ) -> Result<LoadedCheckpointPayload, AgentLoopHostError> {
        self.checkpoint_load_calls.fetch_add(1, Ordering::SeqCst);
        Err(self.forbidden_call("load_checkpoint_payload"))
    }
}

#[async_trait::async_trait]
impl LoopProgressPort for ForbiddenResumeHost {
    async fn emit_loop_progress(
        &self,
        _event: LoopProgressEvent,
    ) -> Result<(), AgentLoopHostError> {
        Err(self.forbidden_call("emit_loop_progress"))
    }
}
