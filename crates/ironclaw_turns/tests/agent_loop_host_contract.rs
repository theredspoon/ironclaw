use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use ironclaw_host_api::{
    AgentId, CapabilityId, ProjectId, RuntimeKind, TenantId, ThreadId, UserId,
};
use ironclaw_turns::{
    AcceptedMessageRef, AgentLoopDriver, AgentLoopDriverDescriptor, AgentLoopDriverError,
    DefaultTurnCoordinator, IdempotencyKey, InMemoryTurnStateStore, LoopBlocked, LoopBlockedKind,
    LoopCompleted, LoopCompletionKind, LoopExit, LoopExitId, LoopGateRef, LoopMessageRef,
    ReplyTargetBindingRef, RunProfileRequest, RunProfileVersion, SourceBindingRef,
    SubmitTurnRequest, SubmitTurnResponse, TurnActor, TurnCheckpointId, TurnCoordinator,
    TurnLeaseToken, TurnRunId, TurnRunnerId,
    run_profile::{
        AgentLoopDriverHost, AgentLoopHostError, AgentLoopHostErrorKind, AssistantReply,
        CapabilityBatchInvocation, CapabilityBatchOutcome, CapabilityDescriptorView,
        CapabilityInputRef, CapabilityInvocation, CapabilityOutcome, CapabilitySurfaceVersion,
        FinalizeAssistantMessage, LoopCapabilityPort, LoopCheckpointKind, LoopCheckpointPort,
        LoopCheckpointRequest, LoopCheckpointStateRef, LoopContextBundle, LoopContextMessage,
        LoopContextPort, LoopContextRequest, LoopDriverNoteKind, LoopInputBatch, LoopInputCursor,
        LoopInputCursorToken, LoopInputPort, LoopModelMessage, LoopModelPort, LoopModelRequest,
        LoopModelResponse, LoopProgressEvent, LoopProgressPort, LoopRunContext, LoopRunInfoPort,
        LoopTranscriptPort, ParentLoopOutput, VisibleCapabilityRequest, VisibleCapabilitySurface,
    },
    runner::{ClaimRunRequest, TurnRunTransitionPort},
};

#[tokio::test]
async fn two_fake_drivers_use_the_same_per_run_agent_loop_host_contract() {
    let host = Arc::new(RecordingAgentLoopHost::new(claimed_run_context().await));
    host.push_model_response(LoopModelResponse {
        chunks: Vec::new(),
        output: ParentLoopOutput::AssistantReply(AssistantReply {
            content: "done".to_string(),
        }),
        effective_model_profile_id: host.context.resolved_run_profile.model_profile_id.clone(),
    });
    host.push_capability_outcome(CapabilityOutcome::ApprovalRequired {
        gate_ref: LoopGateRef::new("gate:approval-needed").unwrap(),
        safe_summary: "approval required".to_string(),
    });

    let reply_exit = ReplyDriver
        .run(driver_run_request(&host), host.as_ref())
        .await
        .unwrap();
    let capability_exit = CapabilityDriver
        .run(driver_run_request(&host), host.as_ref())
        .await
        .unwrap();

    assert!(matches!(reply_exit, LoopExit::Completed(_)));
    assert!(matches!(capability_exit, LoopExit::Blocked(_)));
    assert_eq!(
        host.effects(),
        vec![
            "context",
            "visible_capabilities",
            "model",
            "finalize_assistant",
            "progress:driver_note",
            "visible_capabilities",
            "invoke:demo.echo",
            "checkpoint:before_block",
            "progress:driver_note",
        ]
    );
    assert_eq!(host.run_context().run_id, host.context.run_id);
    assert_eq!(
        host.run_context().thread_id,
        ThreadId::new("thread-loop-host").unwrap()
    );
}

#[tokio::test]
async fn capability_invocations_must_cite_visible_surface_before_host_dispatch() {
    let host = Arc::new(RecordingAgentLoopHost::new(claimed_run_context().await));
    let foreign = CapabilityId::new("demo.foreign").unwrap();

    let error = host
        .invoke_capability(CapabilityInvocation {
            surface_version: CapabilitySurfaceVersion::new("surface-v1").unwrap(),
            capability_id: foreign,
            input_ref: CapabilityInputRef::new("input:opaque-agent-loop-host-sentinel").unwrap(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.kind, AgentLoopHostErrorKind::InvalidInvocation);
    assert_eq!(host.effects(), Vec::<String>::new());
    let serialized = serde_json::to_string(&error).unwrap();
    assert!(!serialized.contains("RAW_AGENT_LOOP_HOST_SENTINEL"));
}

#[test]
fn loop_host_refs_are_bounded_opaque_tokens() {
    assert!(CapabilityInputRef::new("input:opaque-tool-arguments").is_ok());
    assert!(CapabilityInputRef::new("{\"raw\":\"payload\"}").is_err());
    assert!(CapabilityInputRef::new(format!("input:{}", "x".repeat(256))).is_err());
    assert!(LoopCheckpointStateRef::new("checkpoint:state-ref").is_ok());
    assert!(LoopCheckpointStateRef::new("/host/path/checkpoint.json").is_err());
    assert!(LoopInputCursorToken::new("input-cursor:seen-1").is_ok());
    assert!(LoopInputCursorToken::new("999").is_err());
}

#[test]
fn loop_host_refs_validate_when_deserialized() {
    let invalid_invocation = serde_json::json!({
        "surface_version": "surface-v1",
        "capability_id": "demo.echo",
        "input_ref": {"raw": "RAW_AGENT_LOOP_HOST_SENTINEL"}
    });
    assert!(serde_json::from_value::<CapabilityInvocation>(invalid_invocation).is_err());

    let invalid_checkpoint = serde_json::json!({
        "kind": "before_block",
        "state_ref": "raw-checkpoint-json"
    });
    assert!(serde_json::from_value::<LoopCheckpointRequest>(invalid_checkpoint).is_err());

    let invalid_surface = serde_json::json!("surface\n1");
    assert!(serde_json::from_value::<CapabilitySurfaceVersion>(invalid_surface).is_err());
}

#[tokio::test]
async fn input_cursors_are_bound_to_the_claimed_run_context() {
    let context = claimed_run_context().await;
    let cursor = LoopInputCursor::from_host_token(
        &context,
        LoopInputCursorToken::new("input-cursor:seen-1").unwrap(),
    );
    assert!(cursor.is_for_run(&context));

    let other_context = LoopRunContext::new(
        context.scope.clone(),
        context.turn_id,
        TurnRunId::new(),
        context.resolved_run_profile.clone(),
    );
    assert!(!cursor.is_for_run(&other_context));
}

struct ReplyDriver;

#[async_trait]
impl AgentLoopDriver for ReplyDriver {
    fn descriptor(&self) -> AgentLoopDriverDescriptor {
        AgentLoopDriverDescriptor::new("lightweight_loop", RunProfileVersion::new(1)).unwrap()
    }

    async fn run(
        &self,
        request: ironclaw_turns::AgentLoopDriverRunRequest,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        assert_eq!(host.run_context().turn_id, request.turn_id);
        assert_eq!(host.run_context().run_id, request.run_id);
        let context = host
            .load_loop_context(LoopContextRequest {
                after: None,
                limit: 8,
            })
            .await
            .map_err(driver_error)?;
        assert_eq!(context.messages.len(), 1);
        host.visible_capabilities(VisibleCapabilityRequest)
            .await
            .map_err(driver_error)?;
        let response = host
            .stream_model(LoopModelRequest {
                messages: vec![LoopModelMessage {
                    role: "user".to_string(),
                    content_ref: context.messages[0].message_ref.clone(),
                }],
                surface_version: Some(CapabilitySurfaceVersion::new("surface-v1").unwrap()),
                model_preference: Some(
                    host.run_context()
                        .resolved_run_profile
                        .model_profile_id
                        .clone(),
                ),
            })
            .await
            .map_err(driver_error)?;
        let ParentLoopOutput::AssistantReply(reply) = response.output else {
            return Err(AgentLoopDriverError::Failed {
                reason_kind: "unexpected_model_output".to_string(),
            });
        };
        let message_ref = host
            .finalize_assistant_message(FinalizeAssistantMessage { reply })
            .await
            .map_err(driver_error)?;
        host.emit_loop_progress(LoopProgressEvent::driver_note(
            LoopDriverNoteKind::Planning,
            "assistant transcript finalized",
        ))
        .await
        .map_err(driver_error)?;
        Ok(LoopExit::Completed(LoopCompleted {
            completion_kind: LoopCompletionKind::FinalReply,
            reply_message_refs: vec![message_ref],
            result_refs: Vec::new(),
            final_checkpoint_id: None,
            usage_summary_ref: None,
            exit_id: LoopExitId::new("exit:reply-driver").unwrap(),
        }))
    }

    async fn resume(
        &self,
        request: ironclaw_turns::AgentLoopDriverResumeRequest,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        self.run(
            ironclaw_turns::AgentLoopDriverRunRequest {
                turn_id: request.turn_id,
                run_id: request.run_id,
                resolved_run_profile: request.resolved_run_profile,
            },
            host,
        )
        .await
    }
}

struct CapabilityDriver;

#[async_trait]
impl AgentLoopDriver for CapabilityDriver {
    fn descriptor(&self) -> AgentLoopDriverDescriptor {
        AgentLoopDriverDescriptor::new("codeact_loop", RunProfileVersion::new(1)).unwrap()
    }

    async fn run(
        &self,
        _request: ironclaw_turns::AgentLoopDriverRunRequest,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        let surface = host
            .visible_capabilities(VisibleCapabilityRequest)
            .await
            .map_err(driver_error)?;
        let outcome = host
            .invoke_capability(CapabilityInvocation {
                surface_version: surface.version,
                capability_id: surface.descriptors[0].capability_id.clone(),
                input_ref: CapabilityInputRef::new("input:opaque-tool-arguments").unwrap(),
            })
            .await
            .map_err(driver_error)?;
        let CapabilityOutcome::ApprovalRequired { gate_ref, .. } = outcome else {
            return Err(AgentLoopDriverError::Failed {
                reason_kind: "expected_approval".to_string(),
            });
        };
        let checkpoint_id = host
            .checkpoint(LoopCheckpointRequest {
                kind: LoopCheckpointKind::BeforeBlock,
                state_ref: LoopCheckpointStateRef::new("checkpoint:approval-state").unwrap(),
            })
            .await
            .map_err(driver_error)?;
        host.emit_loop_progress(LoopProgressEvent::driver_note(
            LoopDriverNoteKind::Waiting,
            "blocked on approval gate",
        ))
        .await
        .map_err(driver_error)?;
        Ok(LoopExit::Blocked(LoopBlocked {
            kind: LoopBlockedKind::Approval,
            gate_ref,
            checkpoint_id,
            exit_id: LoopExitId::new("exit:capability-driver").unwrap(),
        }))
    }

    async fn resume(
        &self,
        request: ironclaw_turns::AgentLoopDriverResumeRequest,
        host: &(dyn AgentLoopDriverHost + Send + Sync),
    ) -> Result<LoopExit, AgentLoopDriverError> {
        self.run(
            ironclaw_turns::AgentLoopDriverRunRequest {
                turn_id: request.turn_id,
                run_id: request.run_id,
                resolved_run_profile: request.resolved_run_profile,
            },
            host,
        )
        .await
    }
}

struct RecordingAgentLoopHost {
    context: LoopRunContext,
    effects: Mutex<Vec<String>>,
    model_responses: Mutex<Vec<LoopModelResponse>>,
    capability_outcomes: Mutex<Vec<CapabilityOutcome>>,
    visible_surface: VisibleCapabilitySurface,
}

impl RecordingAgentLoopHost {
    fn new(context: LoopRunContext) -> Self {
        Self {
            context,
            effects: Mutex::new(Vec::new()),
            model_responses: Mutex::new(Vec::new()),
            capability_outcomes: Mutex::new(Vec::new()),
            visible_surface: VisibleCapabilitySurface {
                version: CapabilitySurfaceVersion::new("surface-v1").unwrap(),
                descriptors: vec![CapabilityDescriptorView {
                    capability_id: CapabilityId::new("demo.echo").unwrap(),
                    provider: None,
                    runtime: RuntimeKind::Wasm,
                    safe_name: "Echo".to_string(),
                    safe_description: "Returns an opaque result ref".to_string(),
                }],
            },
        }
    }

    fn push_model_response(&self, response: LoopModelResponse) {
        self.model_responses.lock().unwrap().push(response);
    }

    fn push_capability_outcome(&self, outcome: CapabilityOutcome) {
        self.capability_outcomes.lock().unwrap().push(outcome);
    }

    fn effects(&self) -> Vec<String> {
        self.effects.lock().unwrap().clone()
    }

    fn record(&self, effect: impl Into<String>) {
        self.effects.lock().unwrap().push(effect.into());
    }
}

impl LoopRunInfoPort for RecordingAgentLoopHost {
    fn run_context(&self) -> &LoopRunContext {
        &self.context
    }
}

#[async_trait]
impl LoopContextPort for RecordingAgentLoopHost {
    async fn load_loop_context(
        &self,
        _request: LoopContextRequest,
    ) -> Result<LoopContextBundle, AgentLoopHostError> {
        self.record("context");
        Ok(LoopContextBundle {
            messages: vec![LoopContextMessage {
                message_ref: LoopMessageRef::new("msg:user-message").unwrap(),
                role: "user".to_string(),
                safe_summary: "hello".to_string(),
            }],
            instruction_snippets: Vec::new(),
            memory_snippets: Vec::new(),
        })
    }
}

#[async_trait]
impl LoopInputPort for RecordingAgentLoopHost {
    async fn poll_inputs(
        &self,
        _after: LoopInputCursor,
        _limit: usize,
    ) -> Result<LoopInputBatch, AgentLoopHostError> {
        Ok(LoopInputBatch {
            inputs: Vec::new(),
            next_cursor: LoopInputCursor::from_host_token(
                &self.context,
                LoopInputCursorToken::new("input-cursor:0").unwrap(),
            ),
        })
    }

    async fn ack_inputs(&self, _cursor: LoopInputCursor) -> Result<(), AgentLoopHostError> {
        Ok(())
    }
}

#[async_trait]
impl LoopModelPort for RecordingAgentLoopHost {
    async fn stream_model(
        &self,
        _request: LoopModelRequest,
    ) -> Result<LoopModelResponse, AgentLoopHostError> {
        self.record("model");
        self.model_responses.lock().unwrap().pop().ok_or_else(|| {
            AgentLoopHostError::new(
                AgentLoopHostErrorKind::Unavailable,
                "model response unavailable",
            )
        })
    }
}

#[async_trait]
impl LoopCapabilityPort for RecordingAgentLoopHost {
    async fn visible_capabilities(
        &self,
        _request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, AgentLoopHostError> {
        self.record("visible_capabilities");
        Ok(self.visible_surface.clone())
    }

    async fn invoke_capability(
        &self,
        request: CapabilityInvocation,
    ) -> Result<CapabilityOutcome, AgentLoopHostError> {
        if request.surface_version != self.visible_surface.version
            || !self
                .visible_surface
                .descriptors
                .iter()
                .any(|descriptor| descriptor.capability_id == request.capability_id)
        {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::InvalidInvocation,
                "capability was not present in the cited visible surface",
            ));
        }
        self.record(format!("invoke:{}", request.capability_id));
        self.capability_outcomes
            .lock()
            .unwrap()
            .pop()
            .ok_or_else(|| {
                AgentLoopHostError::new(
                    AgentLoopHostErrorKind::Unavailable,
                    "capability outcome unavailable",
                )
            })
    }

    async fn invoke_capability_batch(
        &self,
        _request: CapabilityBatchInvocation,
    ) -> Result<CapabilityBatchOutcome, AgentLoopHostError> {
        Ok(CapabilityBatchOutcome {
            outcomes: Vec::new(),
            stopped_on_suspension: false,
        })
    }
}

#[async_trait]
impl LoopTranscriptPort for RecordingAgentLoopHost {
    async fn finalize_assistant_message(
        &self,
        request: FinalizeAssistantMessage,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        assert_eq!(request.reply.content, "done");
        self.record("finalize_assistant");
        LoopMessageRef::new("msg:assistant-final")
            .map_err(|reason| AgentLoopHostError::new(AgentLoopHostErrorKind::Internal, reason))
    }
}

#[async_trait]
impl LoopCheckpointPort for RecordingAgentLoopHost {
    async fn checkpoint(
        &self,
        request: LoopCheckpointRequest,
    ) -> Result<TurnCheckpointId, AgentLoopHostError> {
        self.record(format!("checkpoint:{}", request.kind.as_str()));
        Ok(TurnCheckpointId::new())
    }
}

#[async_trait]
impl LoopProgressPort for RecordingAgentLoopHost {
    async fn emit_loop_progress(&self, event: LoopProgressEvent) -> Result<(), AgentLoopHostError> {
        self.record(format!("progress:{}", event.kind_name()));
        Ok(())
    }
}

async fn claimed_run_context() -> LoopRunContext {
    let scope = ironclaw_turns::TurnScope::new(
        TenantId::new("tenant-loop").unwrap(),
        Some(AgentId::new("agent-loop").unwrap()),
        Some(ProjectId::new("project-loop").unwrap()),
        ThreadId::new("thread-loop-host").unwrap(),
    );
    let store = Arc::new(InMemoryTurnStateStore::default());
    let coordinator = DefaultTurnCoordinator::new(store.clone());
    let response = coordinator
        .submit_turn(SubmitTurnRequest {
            scope: scope.clone(),
            actor: TurnActor::new(UserId::new("user-loop").unwrap()),
            accepted_message_ref: AcceptedMessageRef::new("message-loop-host").unwrap(),
            source_binding_ref: SourceBindingRef::new("source-loop-host").unwrap(),
            reply_target_binding_ref: ReplyTargetBindingRef::new("reply-loop-host").unwrap(),
            requested_run_profile: Some(RunProfileRequest::new("default").unwrap()),
            idempotency_key: IdempotencyKey::new("idem-loop-host").unwrap(),
            received_at: Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap(),
        })
        .await
        .unwrap();
    let SubmitTurnResponse::Accepted { run_id, .. } = response;
    let claimed = store
        .claim_next_run(ClaimRunRequest {
            runner_id: TurnRunnerId::new(),
            lease_token: TurnLeaseToken::new(),
            scope_filter: Some(scope),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.state.run_id, run_id);
    LoopRunContext::new(
        claimed.state.scope,
        claimed.state.turn_id,
        claimed.state.run_id,
        claimed.resolved_run_profile,
    )
}

fn driver_run_request(host: &RecordingAgentLoopHost) -> ironclaw_turns::AgentLoopDriverRunRequest {
    ironclaw_turns::AgentLoopDriverRunRequest {
        turn_id: host.context.turn_id,
        run_id: host.context.run_id,
        resolved_run_profile: host.context.resolved_run_profile.clone(),
    }
}

fn driver_error(error: AgentLoopHostError) -> AgentLoopDriverError {
    AgentLoopDriverError::Failed {
        reason_kind: error.kind.as_str().to_string(),
    }
}
