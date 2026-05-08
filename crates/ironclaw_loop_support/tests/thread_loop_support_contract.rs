use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ironclaw_host_api::{AgentId, CapabilityId, ProjectId, TenantId, ThreadId, UserId};
use ironclaw_loop_support::{
    EmptyLoopCapabilityPort, HostManagedModelError, HostManagedModelErrorKind,
    HostManagedModelGateway, HostManagedModelMessageRole, HostManagedModelRequest,
    HostManagedModelResponse, ThreadBackedLoopContextPort, ThreadBackedLoopModelPort,
    ThreadBackedLoopTranscriptPort,
};
use ironclaw_threads::{
    AcceptInboundMessageRequest, CreateSummaryArtifactRequest, EnsureThreadRequest,
    InMemorySessionThreadService, MessageContent, MessageKind, MessageStatus, SessionThreadService,
    ThreadHistoryRequest, ThreadScope,
};
use ironclaw_turns::{
    LoopMessageRef, RunProfileResolutionRequest, RunProfileResolver, TurnActor, TurnId, TurnRunId,
    TurnScope,
    run_profile::{
        AgentLoopHostErrorKind, AssistantReply, CapabilityInputRef, CapabilityInvocation,
        CapabilitySurfaceVersion, FinalizeAssistantMessage, InMemoryRunProfileResolver,
        LoopCapabilityPort, LoopContextPort, LoopContextRequest, LoopModelMessage, LoopModelPort,
        LoopModelRequest, LoopRunContext, LoopTranscriptPort, ParentLoopOutput,
        VisibleCapabilityRequest,
    },
};

#[tokio::test]
async fn thread_context_port_loads_policy_filtered_transcript_messages() {
    let fixture = ThreadFixture::new().await;
    let adapter = ThreadBackedLoopContextPort::new(
        Arc::clone(&fixture.thread_service),
        fixture.thread_scope.clone(),
        fixture.run_context.clone(),
        16,
    );

    let bundle = adapter
        .load_loop_context(LoopContextRequest {
            after: None,
            limit: 16,
        })
        .await
        .unwrap();

    assert_eq!(bundle.messages.len(), 1);
    assert_eq!(bundle.messages[0].role, "user");
    assert_eq!(bundle.messages[0].safe_summary, "hello reborn");
    assert_eq!(
        bundle.messages[0].message_ref.as_str(),
        format!("msg:{}", fixture.user_message_id).as_str()
    );
    assert!(bundle.memory_snippets.is_empty());
}

#[tokio::test]
async fn thread_context_port_preserves_summary_replacements_as_system_messages() {
    let fixture = ThreadFixture::new().await;
    fixture
        .thread_service
        .create_summary_artifact(CreateSummaryArtifactRequest {
            scope: fixture.thread_scope.clone(),
            thread_id: fixture.thread_id.clone(),
            start_sequence: 1,
            end_sequence: 1,
            summary_kind: "model_context".to_string(),
            content: MessageContent::text("summarized hello"),
            model_context_policy: Some("replace_range_when_selected".to_string()),
        })
        .await
        .unwrap();
    let adapter = ThreadBackedLoopContextPort::new(
        Arc::clone(&fixture.thread_service),
        fixture.thread_scope.clone(),
        fixture.run_context.clone(),
        16,
    );

    let bundle = adapter
        .load_loop_context(LoopContextRequest {
            after: None,
            limit: 16,
        })
        .await
        .unwrap();

    assert_eq!(bundle.messages.len(), 1);
    assert_eq!(bundle.messages[0].role, "system");
    assert_eq!(bundle.messages[0].safe_summary, "summarized hello");
    assert!(
        bundle.messages[0]
            .message_ref
            .as_str()
            .starts_with("msg:summary-")
    );
    assert!(bundle.instruction_snippets.is_empty());
}

#[tokio::test]
async fn thread_ports_reject_thread_scope_mismatch_before_thread_access() {
    let fixture = ThreadFixture::new().await;
    let mut wrong_scope = fixture.thread_scope.clone();
    wrong_scope.tenant_id = TenantId::new("different-tenant").unwrap();
    let adapter = ThreadBackedLoopContextPort::new(
        Arc::clone(&fixture.thread_service),
        wrong_scope,
        fixture.run_context.clone(),
        16,
    );

    let error = adapter
        .load_loop_context(LoopContextRequest {
            after: None,
            limit: 16,
        })
        .await
        .unwrap_err();

    assert_eq!(error.kind, AgentLoopHostErrorKind::ScopeMismatch);
}

#[tokio::test]
async fn transcript_port_finalizes_assistant_reply_into_durable_thread_history() {
    let fixture = ThreadFixture::new().await;
    let adapter = ThreadBackedLoopTranscriptPort::new(
        Arc::clone(&fixture.thread_service),
        fixture.thread_scope.clone(),
        fixture.run_context.clone(),
    );

    let message_ref = adapter
        .finalize_assistant_message(FinalizeAssistantMessage {
            reply: AssistantReply {
                content: "hi from reborn".to_string(),
            },
        })
        .await
        .unwrap();

    assert!(message_ref.as_str().starts_with("msg:"));
    let history = fixture
        .thread_service
        .list_thread_history(ThreadHistoryRequest {
            scope: fixture.thread_scope.clone(),
            thread_id: fixture.thread_id.clone(),
        })
        .await
        .unwrap();
    let assistant = history
        .messages
        .iter()
        .find(|message| message.kind == MessageKind::Assistant)
        .expect("assistant reply must be persisted");
    assert_eq!(assistant.status, MessageStatus::Finalized);
    assert_eq!(assistant.content.as_deref(), Some("hi from reborn"));
    assert_eq!(
        message_ref.as_str(),
        format!("msg:{}", assistant.message_id)
    );
}

#[tokio::test]
async fn empty_capability_port_exposes_empty_surface_and_rejects_invocations() {
    let port = EmptyLoopCapabilityPort;

    let surface = port
        .visible_capabilities(VisibleCapabilityRequest)
        .await
        .unwrap();
    assert_eq!(surface.version.as_str(), "empty:v1");
    assert!(surface.descriptors.is_empty());

    let error = port
        .invoke_capability(CapabilityInvocation {
            surface_version: CapabilitySurfaceVersion::new("empty:v1").unwrap(),
            capability_id: CapabilityId::new("demo.echo").unwrap(),
            input_ref: CapabilityInputRef::new("input:opaque").unwrap(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.kind, AgentLoopHostErrorKind::InvalidInvocation);
    assert!(!serde_json::to_string(&error).unwrap().contains("opaque"));
}

#[tokio::test]
async fn empty_capability_batch_rejects_stale_surface() {
    let port = EmptyLoopCapabilityPort;

    let error = port
        .invoke_capability_batch(ironclaw_turns::run_profile::CapabilityBatchInvocation {
            invocations: vec![CapabilityInvocation {
                surface_version: CapabilitySurfaceVersion::new("nonempty:v1").unwrap(),
                capability_id: CapabilityId::new("demo.echo").unwrap(),
                input_ref: CapabilityInputRef::new("input:opaque").unwrap(),
            }],
            stop_on_first_suspension: true,
        })
        .await
        .unwrap_err();

    assert_eq!(error.kind, AgentLoopHostErrorKind::StaleSurface);
}

#[tokio::test]
async fn model_port_resolves_thread_message_refs_and_delegates_to_gateway() {
    let fixture = ThreadFixture::new().await;
    let gateway = Arc::new(RecordingGateway::reply("model says hi"));
    let port = ThreadBackedLoopModelPort::new(
        Arc::clone(&fixture.thread_service),
        fixture.thread_scope.clone(),
        fixture.run_context.clone(),
        gateway.clone(),
        16,
    );

    let response = port
        .stream_model(LoopModelRequest {
            messages: vec![LoopModelMessage {
                role: "user".to_string(),
                content_ref: LoopMessageRef::new(format!("msg:{}", fixture.user_message_id))
                    .unwrap(),
            }],
            surface_version: None,
            model_preference: None,
        })
        .await
        .unwrap();

    assert_eq!(response.chunks[0].safe_text_delta, "model says hi");
    assert_eq!(
        response.effective_model_profile_id.as_str(),
        "interactive_model"
    );
    assert!(matches!(
        response.output,
        ParentLoopOutput::AssistantReply(AssistantReply { ref content }) if content == "model says hi"
    ));
    let calls = gateway.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].model_profile_id.as_str(), "interactive_model");
    assert_eq!(calls[0].messages[0].role, HostManagedModelMessageRole::User);
    assert_eq!(calls[0].messages[0].content, "hello reborn");
}

#[tokio::test]
async fn model_port_surfaces_fail_closed_gateway_policy_errors_without_raw_details() {
    let fixture = ThreadFixture::new().await;
    let gateway = Arc::new(RecordingGateway::deny("RAW_PROVIDER_SECRET"));
    let port = ThreadBackedLoopModelPort::new(
        Arc::clone(&fixture.thread_service),
        fixture.thread_scope.clone(),
        fixture.run_context.clone(),
        gateway,
        16,
    );

    let error = port
        .stream_model(LoopModelRequest {
            messages: vec![LoopModelMessage {
                role: "user".to_string(),
                content_ref: LoopMessageRef::new(format!("msg:{}", fixture.user_message_id))
                    .unwrap(),
            }],
            surface_version: None,
            model_preference: None,
        })
        .await
        .unwrap_err();

    assert_eq!(error.kind, AgentLoopHostErrorKind::PolicyDenied);
    let wire = serde_json::to_string(&error).unwrap();
    assert!(!wire.contains("RAW_PROVIDER_SECRET"));
}

struct ThreadFixture {
    thread_service: Arc<InMemorySessionThreadService>,
    thread_scope: ThreadScope,
    thread_id: ThreadId,
    user_message_id: ironclaw_threads::ThreadMessageId,
    run_context: LoopRunContext,
}

impl ThreadFixture {
    async fn new() -> Self {
        let thread_service = Arc::new(InMemorySessionThreadService::default());
        let tenant_id = TenantId::new("tenant-loop-support").unwrap();
        let agent_id = AgentId::new("agent-loop-support").unwrap();
        let project_id = ProjectId::new("project-loop-support").unwrap();
        let user_id = UserId::new("user-loop-support").unwrap();
        let thread_id = ThreadId::new("thread-loop-support").unwrap();
        let thread_scope = ThreadScope {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: Some(project_id.clone()),
            owner_user_id: Some(user_id.clone()),
            mission_id: None,
        };
        thread_service
            .ensure_thread(EnsureThreadRequest {
                scope: thread_scope.clone(),
                thread_id: Some(thread_id.clone()),
                created_by_actor_id: user_id.as_str().to_string(),
                title: None,
                metadata_json: None,
            })
            .await
            .unwrap();
        let accepted = thread_service
            .accept_inbound_message(AcceptInboundMessageRequest {
                scope: thread_scope.clone(),
                thread_id: thread_id.clone(),
                actor_id: user_id.as_str().to_string(),
                source_binding_id: Some("source-web".to_string()),
                reply_target_binding_id: Some("reply-web".to_string()),
                external_event_id: Some("event-1".to_string()),
                content: MessageContent::text("hello reborn"),
            })
            .await
            .unwrap();
        let turn_scope = TurnScope::new(
            tenant_id,
            Some(agent_id),
            Some(project_id),
            thread_id.clone(),
        );
        let resolved = InMemoryRunProfileResolver::default()
            .resolve_run_profile(RunProfileResolutionRequest::interactive_default())
            .await
            .unwrap();
        let run_context =
            LoopRunContext::new(turn_scope, TurnId::new(), TurnRunId::new(), resolved);
        let _actor = TurnActor::new(user_id);
        Self {
            thread_service,
            thread_scope,
            thread_id,
            user_message_id: accepted.message_id,
            run_context,
        }
    }
}

struct RecordingGateway {
    calls: Mutex<Vec<HostManagedModelRequest>>,
    response: Result<HostManagedModelResponse, HostManagedModelError>,
}

impl RecordingGateway {
    fn reply(content: &str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response: Ok(HostManagedModelResponse::assistant_reply(
                content.to_string(),
            )),
        }
    }

    fn deny(raw_detail: &str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response: Err(HostManagedModelError::new(
                HostManagedModelErrorKind::PolicyDenied,
                raw_detail,
            )),
        }
    }
}

#[async_trait]
impl HostManagedModelGateway for RecordingGateway {
    async fn stream_model(
        &self,
        request: HostManagedModelRequest,
    ) -> Result<HostManagedModelResponse, HostManagedModelError> {
        self.calls.lock().unwrap().push(request);
        self.response.clone()
    }
}
