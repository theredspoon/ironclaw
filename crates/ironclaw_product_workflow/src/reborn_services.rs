//! WebUI-facing Reborn service facade.
//!
//! This module is the stable high-level API beta WebUI route handlers use
//! instead of reaching into turn coordination, thread stores, runtime lanes, DB
//! stores, dispatchers, or capability hosts directly.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use ironclaw_host_api::{AgentId, ThreadId};
use ironclaw_product_adapters::{
    ProductAdapterError, ProductOutboundEnvelope, ProjectionCursor, ProjectionStream,
    ProjectionSubscriptionRequest,
};
use ironclaw_threads::{
    AcceptInboundMessageRequest, EnsureThreadRequest, MessageContent, MessageStatus,
    ReplayAcceptedInboundMessageRequest, SessionThreadError, SessionThreadRecord,
    SessionThreadService, SummaryArtifact, ThreadHistoryRequest, ThreadMessageId,
    ThreadMessageRecord, ThreadScope,
};
use ironclaw_turns::{
    AcceptedMessageRef, CancelRunResponse, EventCursor, GetRunStateRequest, ReplyTargetBindingRef,
    ResumeTurnRequest, ResumeTurnResponse, SanitizedCancelReason, SourceBindingRef,
    SubmitTurnRequest, SubmitTurnResponse, TurnActor, TurnCoordinator, TurnError, TurnRunId,
    TurnScope, TurnStatus,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    WebUiAuthenticatedCaller, WebUiCancelRunRequest, WebUiCreateThreadRequest, WebUiGateResolution,
    WebUiInboundCommand, WebUiInboundValidationCode, WebUiInboundValidationError,
    WebUiResolveGateRequest, WebUiSendMessageRequest,
};

/// Stable WebUI-facing facade surface for beta Reborn routes.
#[async_trait]
pub trait RebornServicesApi: Send + Sync {
    async fn submit_turn(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiSendMessageRequest,
    ) -> Result<RebornSubmitTurnResponse, RebornServicesError>;

    async fn get_timeline(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: RebornTimelineRequest,
    ) -> Result<RebornTimelineResponse, RebornServicesError>;

    async fn stream_events(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: RebornStreamEventsRequest,
    ) -> Result<RebornStreamEventsResponse, RebornServicesError>;

    async fn cancel_run(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiCancelRunRequest,
    ) -> Result<RebornCancelRunResponse, RebornServicesError>;

    async fn resolve_gate(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiResolveGateRequest,
    ) -> Result<RebornResolveGateResponse, RebornServicesError>;
}

/// Default facade implementation composed at the WebUI boundary.
#[derive(Clone)]
pub struct RebornServices {
    thread_service: Arc<dyn SessionThreadService>,
    turn_coordinator: Arc<dyn TurnCoordinator>,
    event_stream: Option<Arc<dyn ProjectionStream>>,
}

impl RebornServices {
    pub fn new(
        thread_service: Arc<dyn SessionThreadService>,
        turn_coordinator: Arc<dyn TurnCoordinator>,
    ) -> Self {
        Self {
            thread_service,
            turn_coordinator,
            event_stream: None,
        }
    }

    pub fn with_event_stream(mut self, event_stream: Arc<dyn ProjectionStream>) -> Self {
        self.event_stream = Some(event_stream);
        self
    }
}

#[async_trait]
impl RebornServicesApi for RebornServices {
    async fn submit_turn(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiSendMessageRequest,
    ) -> Result<RebornSubmitTurnResponse, RebornServicesError> {
        let command = request.into_command(caller)?;
        let WebUiInboundCommand::SendMessage {
            scope,
            actor,
            client_action_id,
            content,
        } = command
        else {
            return Err(RebornServicesError::internal_invariant());
        };

        let thread_scope = thread_scope_from_turn_scope(&scope, Some(actor.user_id.clone()))?;
        let source_binding_id = webui_source_binding_id(&scope, &actor);
        let external_event_id = client_action_id.as_str().to_string();

        let handoff = if let Some(replay) = self
            .thread_service
            .replay_accepted_inbound_message(ReplayAcceptedInboundMessageRequest {
                source_binding_id: source_binding_id.clone(),
                external_event_id: external_event_id.clone(),
            })
            .await
            .map_err(map_thread_error)?
        {
            match replay.status {
                MessageStatus::Submitted => {
                    let run_id = parse_replay_run_id(replay.turn_run_id)?;
                    let state = self
                        .turn_coordinator
                        .get_run_state(GetRunStateRequest {
                            scope: scope.clone(),
                            run_id,
                        })
                        .await
                        .map_err(map_turn_error)?;
                    return Ok(RebornSubmitTurnResponse::AlreadySubmitted {
                        thread_id: replay.thread_id,
                        accepted_message_ref: accepted_message_ref(replay.message_id.to_string())?,
                        run_id,
                        status: state.status,
                        event_cursor: state.event_cursor,
                    });
                }
                MessageStatus::Accepted | MessageStatus::DeferredBusy => AcceptedWebUiMessage {
                    thread_id: replay.thread_id,
                    message_id: replay.message_id,
                    reply_target_binding_id: replay
                        .reply_target_binding_id
                        .unwrap_or_else(|| source_binding_id.clone()),
                },
                _ => {
                    return Err(RebornServicesError::from_status(
                        RebornServicesErrorCode::Conflict,
                        409,
                        false,
                    ));
                }
            }
        } else {
            self.thread_service
                .ensure_thread(EnsureThreadRequest {
                    scope: thread_scope.clone(),
                    thread_id: Some(scope.thread_id.clone()),
                    created_by_actor_id: actor.user_id.as_str().to_string(),
                    title: None,
                    metadata_json: None,
                })
                .await
                .map_err(map_thread_error)?;

            let accepted = self
                .thread_service
                .accept_inbound_message(AcceptInboundMessageRequest {
                    scope: thread_scope.clone(),
                    thread_id: scope.thread_id.clone(),
                    actor_id: actor.user_id.as_str().to_string(),
                    source_binding_id: Some(source_binding_id.clone()),
                    reply_target_binding_id: Some(source_binding_id.clone()),
                    external_event_id: Some(external_event_id),
                    content: MessageContent::text(content),
                })
                .await
                .map_err(map_thread_error)?;
            AcceptedWebUiMessage {
                thread_id: accepted.thread_id,
                message_id: accepted.message_id,
                reply_target_binding_id: source_binding_id.clone(),
            }
        };

        let accepted_message_ref = accepted_message_ref(handoff.message_id.to_string())?;
        let source_binding_ref = bounded_ref::<SourceBindingRef>("webui-src", &source_binding_id)?;
        let reply_target_binding_ref =
            bounded_ref::<ReplyTargetBindingRef>("webui-reply", &handoff.reply_target_binding_id)?;

        let submit = SubmitTurnRequest {
            scope,
            actor,
            accepted_message_ref: accepted_message_ref.clone(),
            source_binding_ref,
            reply_target_binding_ref,
            requested_run_profile: None,
            idempotency_key: client_action_id,
            received_at: Utc::now(),
        };

        match self.turn_coordinator.submit_turn(submit).await {
            Ok(SubmitTurnResponse::Accepted {
                turn_id,
                run_id,
                status,
                resolved_run_profile_id,
                resolved_run_profile_version,
                event_cursor,
                ..
            }) => {
                self.thread_service
                    .mark_message_submitted(
                        &thread_scope,
                        &handoff.thread_id,
                        handoff.message_id,
                        turn_id.to_string(),
                        run_id.to_string(),
                    )
                    .await
                    .map_err(map_thread_error)?;

                Ok(RebornSubmitTurnResponse::Submitted {
                    thread_id: handoff.thread_id,
                    accepted_message_ref,
                    turn_id: turn_id.to_string(),
                    run_id,
                    status,
                    resolved_run_profile_id: resolved_run_profile_id.as_str().to_string(),
                    resolved_run_profile_version: resolved_run_profile_version.as_u64(),
                    event_cursor,
                })
            }
            Err(TurnError::ThreadBusy(busy)) => {
                self.thread_service
                    .mark_message_deferred_busy(
                        &thread_scope,
                        &handoff.thread_id,
                        handoff.message_id,
                    )
                    .await
                    .map_err(map_thread_error)?;

                Ok(RebornSubmitTurnResponse::DeferredBusy {
                    thread_id: handoff.thread_id,
                    accepted_message_ref,
                    active_run_id: busy.active_run_id,
                    status: busy.status,
                    event_cursor: busy.event_cursor,
                })
            }
            Err(error) => Err(map_turn_error(error)),
        }
    }

    async fn get_timeline(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: RebornTimelineRequest,
    ) -> Result<RebornTimelineResponse, RebornServicesError> {
        let thread_id = parse_thread_id_field("thread_id", request.thread_id)?;
        let scope = caller.turn_scope(thread_id.clone());
        let thread_scope = thread_scope_from_turn_scope(&scope, Some(caller.user_id.clone()))?;
        let history = self
            .thread_service
            .list_thread_history(ThreadHistoryRequest {
                scope: thread_scope,
                thread_id,
            })
            .await
            .map_err(map_thread_error)?;

        Ok(RebornTimelineResponse {
            thread: history.thread,
            messages: history.messages,
            summary_artifacts: history.summary_artifacts,
        })
    }

    async fn stream_events(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: RebornStreamEventsRequest,
    ) -> Result<RebornStreamEventsResponse, RebornServicesError> {
        let thread_id = parse_thread_id_field("thread_id", request.thread_id)?;
        let Some(event_stream) = &self.event_stream else {
            return Err(RebornServicesError::service_unavailable(false));
        };
        let events = event_stream
            .drain(ProjectionSubscriptionRequest {
                actor: caller.actor(),
                scope: caller.turn_scope(thread_id),
                after_cursor: request.after_cursor,
            })
            .await
            .map_err(map_adapter_error)?;
        Ok(RebornStreamEventsResponse { events })
    }

    async fn cancel_run(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiCancelRunRequest,
    ) -> Result<RebornCancelRunResponse, RebornServicesError> {
        let command = request.into_command(caller)?;
        let WebUiInboundCommand::CancelRun { request } = command else {
            return Err(RebornServicesError::internal_invariant());
        };
        let response = self
            .turn_coordinator
            .cancel_run(request)
            .await
            .map_err(map_turn_error)?;
        Ok(response.into())
    }

    async fn resolve_gate(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiResolveGateRequest,
    ) -> Result<RebornResolveGateResponse, RebornServicesError> {
        let command = request.into_command(caller)?;
        let WebUiInboundCommand::ResolveGate {
            scope,
            actor,
            run_id,
            gate_ref,
            client_action_id,
            resolution,
        } = command
        else {
            return Err(RebornServicesError::internal_invariant());
        };

        match resolution {
            WebUiGateResolution::Approved { .. } => {
                let binding_id = webui_gate_binding_id(&scope, &gate_ref_string(&gate_ref));
                let response = self
                    .turn_coordinator
                    .resume_turn(ResumeTurnRequest {
                        scope,
                        actor,
                        run_id,
                        gate_resolution_ref: gate_ref,
                        source_binding_ref: bounded_ref::<SourceBindingRef>(
                            "webui-gate-src",
                            &binding_id,
                        )?,
                        reply_target_binding_ref: bounded_ref::<ReplyTargetBindingRef>(
                            "webui-gate-reply",
                            &binding_id,
                        )?,
                        idempotency_key: client_action_id,
                    })
                    .await
                    .map_err(map_turn_error)?;
                Ok(RebornResolveGateResponse::Resumed(response.into()))
            }
            WebUiGateResolution::CredentialProvided { .. } => Err(
                RebornServicesError::from_status(RebornServicesErrorCode::Unavailable, 503, false),
            ),
            WebUiGateResolution::Denied | WebUiGateResolution::Cancelled => {
                let response = self
                    .turn_coordinator
                    .cancel_run(ironclaw_turns::CancelRunRequest {
                        scope,
                        actor,
                        run_id,
                        reason: SanitizedCancelReason::UserRequested,
                        idempotency_key: client_action_id,
                    })
                    .await
                    .map_err(map_turn_error)?;
                Ok(RebornResolveGateResponse::Cancelled(response.into()))
            }
        }
    }
}

struct AcceptedWebUiMessage {
    thread_id: ThreadId,
    message_id: ThreadMessageId,
    reply_target_binding_id: String,
}

/// Optional create-thread helper for routes that want an explicit allocation
/// before first turn submission.
impl RebornServices {
    pub async fn create_thread(
        &self,
        caller: WebUiAuthenticatedCaller,
        request: WebUiCreateThreadRequest,
    ) -> Result<RebornCreateThreadResponse, RebornServicesError> {
        let command = request.into_command(caller)?;
        let WebUiInboundCommand::CreateThread {
            caller,
            client_action_id,
            requested_thread_id,
        } = command
        else {
            return Err(RebornServicesError::internal_invariant());
        };
        let thread_id =
            requested_thread_id.unwrap_or_else(|| generated_thread_id(&caller, &client_action_id));
        let scope = caller.turn_scope(thread_id.clone());
        let thread_scope = thread_scope_from_turn_scope(&scope, Some(caller.user_id.clone()))?;
        let thread = self
            .thread_service
            .ensure_thread(EnsureThreadRequest {
                scope: thread_scope,
                thread_id: Some(thread_id),
                created_by_actor_id: caller.user_id.as_str().to_string(),
                title: None,
                metadata_json: Some(format!(
                    "{{\"client_action_id\":\"{}\"}}",
                    escape_json_string(client_action_id.as_str())
                )),
            })
            .await
            .map_err(map_thread_error)?;
        Ok(RebornCreateThreadResponse { thread })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornCreateThreadResponse {
    pub thread: SessionThreadRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RebornSubmitTurnResponse {
    Submitted {
        thread_id: ThreadId,
        accepted_message_ref: AcceptedMessageRef,
        turn_id: String,
        run_id: TurnRunId,
        status: TurnStatus,
        resolved_run_profile_id: String,
        resolved_run_profile_version: u64,
        event_cursor: EventCursor,
    },
    DeferredBusy {
        thread_id: ThreadId,
        accepted_message_ref: AcceptedMessageRef,
        active_run_id: TurnRunId,
        status: TurnStatus,
        event_cursor: EventCursor,
    },
    AlreadySubmitted {
        thread_id: ThreadId,
        accepted_message_ref: AcceptedMessageRef,
        run_id: TurnRunId,
        status: TurnStatus,
        event_cursor: EventCursor,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornTimelineRequest {
    pub thread_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornTimelineResponse {
    pub thread: SessionThreadRecord,
    pub messages: Vec<ThreadMessageRecord>,
    pub summary_artifacts: Vec<SummaryArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornStreamEventsRequest {
    pub thread_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_cursor: Option<ProjectionCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornStreamEventsResponse {
    pub events: Vec<ProductOutboundEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornCancelRunResponse {
    pub run_id: TurnRunId,
    pub status: TurnStatus,
    pub event_cursor: EventCursor,
    pub already_terminal: bool,
}

impl From<CancelRunResponse> for RebornCancelRunResponse {
    fn from(value: CancelRunResponse) -> Self {
        Self {
            run_id: value.run_id,
            status: value.status,
            event_cursor: value.event_cursor,
            already_terminal: value.already_terminal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornResumeGateResponse {
    pub run_id: TurnRunId,
    pub status: TurnStatus,
    pub event_cursor: EventCursor,
}

impl From<ResumeTurnResponse> for RebornResumeGateResponse {
    fn from(value: ResumeTurnResponse) -> Self {
        Self {
            run_id: value.run_id,
            status: value.status,
            event_cursor: value.event_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RebornResolveGateResponse {
    Resumed(RebornResumeGateResponse),
    Cancelled(RebornCancelRunResponse),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornServicesErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    RateLimited,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("Reborn WebUI service error: {code:?}")]
pub struct RebornServicesError {
    pub code: RebornServicesErrorCode,
    pub status_code: u16,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_code: Option<WebUiInboundValidationCode>,
}

impl RebornServicesError {
    fn validation(error: WebUiInboundValidationError) -> Self {
        Self {
            code: RebornServicesErrorCode::InvalidRequest,
            status_code: 400,
            retryable: false,
            field: Some(error.field),
            validation_code: Some(error.code),
        }
    }

    fn from_status(code: RebornServicesErrorCode, status_code: u16, retryable: bool) -> Self {
        Self {
            code,
            status_code,
            retryable,
            field: None,
            validation_code: None,
        }
    }

    fn internal_invariant() -> Self {
        Self::from_status(RebornServicesErrorCode::Internal, 500, false)
    }

    fn service_unavailable(retryable: bool) -> Self {
        Self::from_status(RebornServicesErrorCode::Unavailable, 503, retryable)
    }
}

impl From<WebUiInboundValidationError> for RebornServicesError {
    fn from(value: WebUiInboundValidationError) -> Self {
        Self::validation(value)
    }
}

fn thread_scope_from_turn_scope(
    scope: &TurnScope,
    owner_user_id: Option<ironclaw_host_api::UserId>,
) -> Result<ThreadScope, RebornServicesError> {
    let Some(agent_id) = scope.agent_id.clone() else {
        return Err(RebornServicesError::from_status(
            RebornServicesErrorCode::InvalidRequest,
            400,
            false,
        ));
    };
    Ok(ThreadScope {
        tenant_id: scope.tenant_id.clone(),
        agent_id,
        project_id: scope.project_id.clone(),
        owner_user_id,
        mission_id: None,
    })
}

fn parse_thread_id_field(
    field: &'static str,
    value: String,
) -> Result<ThreadId, RebornServicesError> {
    ThreadId::new(value).map_err(|_| {
        RebornServicesError::validation(WebUiInboundValidationError::new(
            field,
            WebUiInboundValidationCode::InvalidId,
        ))
    })
}

fn accepted_message_ref(message_id: String) -> Result<AcceptedMessageRef, RebornServicesError> {
    AcceptedMessageRef::new(format!("msg:{message_id}")).map_err(|_| {
        RebornServicesError::from_status(RebornServicesErrorCode::Internal, 500, false)
    })
}

fn parse_replay_run_id(value: Option<String>) -> Result<TurnRunId, RebornServicesError> {
    let Some(value) = value else {
        return Err(RebornServicesError::from_status(
            RebornServicesErrorCode::Conflict,
            409,
            false,
        ));
    };
    Uuid::parse_str(&value)
        .map(TurnRunId::from_uuid)
        .map_err(|_| {
            RebornServicesError::from_status(RebornServicesErrorCode::Conflict, 409, false)
        })
}

trait RefFactory: Sized {
    fn build(value: String) -> Result<Self, String>;
}

impl RefFactory for SourceBindingRef {
    fn build(value: String) -> Result<Self, String> {
        Self::new(value)
    }
}

impl RefFactory for ReplyTargetBindingRef {
    fn build(value: String) -> Result<Self, String> {
        Self::new(value)
    }
}

fn bounded_ref<T: RefFactory>(prefix: &str, raw: &str) -> Result<T, RebornServicesError> {
    let value = if raw.len() <= 240 && !raw.chars().any(|c| c == '\0' || c.is_control()) {
        format!("{prefix}:{raw}")
    } else {
        let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, raw.as_bytes());
        format!("{prefix}:{id}")
    };
    T::build(value).map_err(|_| {
        RebornServicesError::from_status(RebornServicesErrorCode::Internal, 500, false)
    })
}

fn webui_source_binding_id(scope: &TurnScope, actor: &TurnActor) -> String {
    format!(
        "{}{}{}{}{}",
        segment("surface", "webui"),
        segment("tenant", scope.tenant_id.as_str()),
        segment(
            "agent",
            scope.agent_id.as_ref().map(AgentId::as_str).unwrap_or("")
        ),
        segment("thread", scope.thread_id.as_str()),
        segment("actor", actor.user_id.as_str())
    )
}

fn webui_gate_binding_id(scope: &TurnScope, gate_ref: &str) -> String {
    format!(
        "{}{}{}{}",
        segment("surface", "webui"),
        segment("tenant", scope.tenant_id.as_str()),
        segment("thread", scope.thread_id.as_str()),
        segment("gate", gate_ref)
    )
}

fn gate_ref_string(gate_ref: &ironclaw_turns::GateRef) -> String {
    gate_ref.as_str().to_string()
}

fn segment(name: &str, value: &str) -> String {
    format!("{name}:{}:{value};", value.len())
}

fn map_thread_error(error: SessionThreadError) -> RebornServicesError {
    match error {
        SessionThreadError::UnknownThread { .. } | SessionThreadError::UnknownMessage { .. } => {
            RebornServicesError::from_status(RebornServicesErrorCode::NotFound, 404, false)
        }
        SessionThreadError::ThreadScopeMismatch { .. }
        | SessionThreadError::IdempotentReplayThreadMismatch { .. }
        | SessionThreadError::InvalidMessageTransition { .. }
        | SessionThreadError::MessageNotDraft { .. }
        | SessionThreadError::InvalidSummaryRange { .. }
        | SessionThreadError::OverlappingSummaryRange { .. } => {
            RebornServicesError::from_status(RebornServicesErrorCode::Conflict, 409, false)
        }
        SessionThreadError::GeneratedThreadId(_)
        | SessionThreadError::Serialization(_)
        | SessionThreadError::Deserialization(_)
        | SessionThreadError::Backend(_) => RebornServicesError::service_unavailable(true),
    }
}

fn map_turn_error(error: TurnError) -> RebornServicesError {
    let (code, status_code, retryable) = match error.category() {
        ironclaw_turns::TurnErrorCategory::ThreadBusy
        | ironclaw_turns::TurnErrorCategory::Conflict => {
            (RebornServicesErrorCode::Conflict, 409, false)
        }
        ironclaw_turns::TurnErrorCategory::AdmissionRejected => {
            (RebornServicesErrorCode::RateLimited, 429, true)
        }
        ironclaw_turns::TurnErrorCategory::ScopeNotFound => {
            (RebornServicesErrorCode::NotFound, 404, false)
        }
        ironclaw_turns::TurnErrorCategory::Unauthorized => {
            (RebornServicesErrorCode::Unauthorized, 403, false)
        }
        ironclaw_turns::TurnErrorCategory::InvalidRequest => {
            (RebornServicesErrorCode::InvalidRequest, 400, false)
        }
        ironclaw_turns::TurnErrorCategory::Unavailable => {
            (RebornServicesErrorCode::Unavailable, 503, true)
        }
    };
    RebornServicesError::from_status(code, status_code, retryable)
}

fn map_adapter_error(error: ProductAdapterError) -> RebornServicesError {
    match error {
        ProductAdapterError::WorkflowRejected {
            status_code,
            retryable,
            ..
        } => {
            let code = match status_code {
                400 => RebornServicesErrorCode::InvalidRequest,
                403 => RebornServicesErrorCode::Unauthorized,
                404 => RebornServicesErrorCode::NotFound,
                409 => RebornServicesErrorCode::Conflict,
                429 => RebornServicesErrorCode::RateLimited,
                503 => RebornServicesErrorCode::Unavailable,
                _ => RebornServicesErrorCode::Internal,
            };
            RebornServicesError::from_status(code, status_code, retryable)
        }
        ProductAdapterError::WorkflowTransient { .. }
        | ProductAdapterError::EgressTransient { .. } => {
            RebornServicesError::service_unavailable(true)
        }
        ProductAdapterError::Authentication(_) => {
            RebornServicesError::from_status(RebornServicesErrorCode::Unauthorized, 401, false)
        }
        ProductAdapterError::MalformedInboundPayload { .. }
        | ProductAdapterError::InvalidIdentifier { .. } => {
            RebornServicesError::from_status(RebornServicesErrorCode::InvalidRequest, 400, false)
        }
        ProductAdapterError::EgressDenied { .. }
        | ProductAdapterError::EgressUndeclaredHost { .. } => {
            RebornServicesError::from_status(RebornServicesErrorCode::Unauthorized, 403, false)
        }
        ProductAdapterError::Internal { .. } => {
            RebornServicesError::from_status(RebornServicesErrorCode::Internal, 500, false)
        }
    }
}

fn escape_json_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

fn generated_thread_id(
    caller: &WebUiAuthenticatedCaller,
    client_action_id: &ironclaw_turns::IdempotencyKey,
) -> ThreadId {
    let seed = format!(
        "{}{}{}{}{}{}",
        segment("surface", "webui-create-thread"),
        segment("tenant", caller.tenant_id.as_str()),
        segment("user", caller.user_id.as_str()),
        segment(
            "agent",
            caller.agent_id.as_ref().map(AgentId::as_str).unwrap_or("")
        ),
        segment(
            "project",
            caller
                .project_id
                .as_ref()
                .map(ironclaw_host_api::ProjectId::as_str)
                .unwrap_or("")
        ),
        segment("action", client_action_id.as_str())
    );
    let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, seed.as_bytes());
    // UUID text contains no path separators/control characters and is accepted by ThreadId.
    match ThreadId::new(id.to_string()) {
        Ok(thread_id) => thread_id,
        Err(error) => {
            debug_assert!(false, "generated UUID thread id should be valid: {error}");
            // Fallback remains valid under ThreadId validation rules.
            ThreadId::new("generated-thread-fallback").unwrap_or_else(|_| unreachable!())
        }
    }
}
