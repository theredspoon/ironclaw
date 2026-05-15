//! WebUI service facade for native Reborn WebChat v2 (issue #3611).
//!
//! Browser-facing route handlers depend only on this facade. They must not
//! reach the dispatcher, run-state store, runtime-lane adapters, or raw turn
//! coordinator — those live behind [`WebUiService`].
//!
//! This is the Path A (native host surface) seam described in
//! `docs/reborn/how-to-port-channel-to-reborn.md`. WebUI sessions are
//! host-trusted, so this facade does **not** fabricate `ExternalActorRef`,
//! `ProtocolAuthEvidence`, declared egress, or `OutboundDeliverySink`.

use async_trait::async_trait;
use ironclaw_event_projections::{
    EventProjectionService, MAX_PROJECTION_PAGE_LIMIT, ProjectionCursor, ProjectionError,
    ProjectionRequest, ProjectionScope, RunStatusProjection, TimelineEntry,
};
use ironclaw_events::{EventStreamKey, ReadScope};
use ironclaw_host_api::ThreadId;
use ironclaw_threads::{
    EnsureThreadRequest, MessageContent, SessionThreadError, SessionThreadService, ThreadScope,
};
use ironclaw_turns::{
    AcceptedMessageRef, CancelRunRequest, GateRef, IdempotencyKey, ReplyTargetBindingRef,
    ResumeTurnRequest, SanitizedCancelReason, SourceBindingRef, SubmitTurnRequest,
    SubmitTurnResponse, TurnActor, TurnCoordinator, TurnError, TurnErrorCategory, TurnRunId,
    TurnScope,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::webui_inbound::{WebUiAuthenticatedCaller, WebUiGateResolution};

/// Default page size if the caller asks for `0` or omits the limit.
pub const WEBUI_TIMELINE_DEFAULT_LIMIT: usize = 100;

// ---------------------------------------------------------------------------
// Public facade trait
// ---------------------------------------------------------------------------

/// Browser-facing WebUI command surface.
///
/// Route handlers consume only this trait. Implementations route each command
/// to the appropriate Reborn host service (thread service, turn coordinator,
/// future gate-resolve port) without exposing those services to handlers.
#[async_trait]
pub trait WebUiService: Send + Sync {
    /// Create or ensure a thread for the authenticated caller.
    async fn create_thread(
        &self,
        command: WebUiCreateThreadCommand,
    ) -> Result<WebUiThreadCreated, WebUiServiceError>;

    /// Accept a user message and submit a turn (or defer it if the thread is busy).
    async fn send_message(
        &self,
        command: WebUiSendMessageCommand,
    ) -> Result<WebUiMessageAccepted, WebUiServiceError>;

    /// Request cancellation of an in-flight run.
    async fn cancel_run(
        &self,
        command: WebUiCancelRunCommand,
    ) -> Result<WebUiRunCancelled, WebUiServiceError>;

    /// Resolve an approval/auth/resource gate that an active run is parked on.
    async fn resolve_gate(
        &self,
        command: WebUiResolveGateCommand,
    ) -> Result<WebUiGateResolved, WebUiServiceError>;

    /// Initial timeline snapshot for a thread (used to bootstrap the chat view).
    async fn get_timeline_snapshot(
        &self,
        command: WebUiGetTimelineCommand,
    ) -> Result<WebUiTimelineSnapshot, WebUiServiceError>;

    /// Single batch of timeline entries that arrived after the supplied cursor.
    ///
    /// The browser-facing SSE handler builds the actual server-sent-events
    /// loop on top of this method; this trait only exposes one batch read so
    /// the facade stays transport-agnostic.
    async fn get_timeline_updates(
        &self,
        command: WebUiGetTimelineCommand,
    ) -> Result<WebUiTimelineReplay, WebUiServiceError>;
}

// ---------------------------------------------------------------------------
// Per-command input structs
// ---------------------------------------------------------------------------

/// Input for [`WebUiService::create_thread`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiCreateThreadCommand {
    pub caller: WebUiAuthenticatedCaller,
    pub client_action_id: IdempotencyKey,
    pub requested_thread_id: Option<ThreadId>,
}

/// Input for [`WebUiService::send_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiSendMessageCommand {
    pub scope: TurnScope,
    pub actor: TurnActor,
    pub client_action_id: IdempotencyKey,
    pub content: String,
}

/// Input for [`WebUiService::cancel_run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiCancelRunCommand {
    pub scope: TurnScope,
    pub actor: TurnActor,
    pub run_id: TurnRunId,
    pub reason: SanitizedCancelReason,
    pub client_action_id: IdempotencyKey,
}

/// Input for [`WebUiService::resolve_gate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiResolveGateCommand {
    pub scope: TurnScope,
    pub actor: TurnActor,
    pub run_id: TurnRunId,
    pub gate_ref: GateRef,
    pub client_action_id: IdempotencyKey,
    pub resolution: WebUiGateResolution,
}

/// Input for the timeline read methods.
///
/// `after` is opaque to handlers — pass the [`WebUiTimelineSnapshot::next_cursor`]
/// or [`WebUiTimelineReplay::next_cursor`] from the previous batch unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiGetTimelineCommand {
    pub caller: WebUiAuthenticatedCaller,
    pub thread_id: ThreadId,
    pub after: Option<WebUiTimelineCursor>,
    pub limit: usize,
}

/// Opaque cursor that the browser passes back into subsequent timeline reads.
///
/// Handlers may serialize the wrapped JSON to the browser but must not
/// reach into the inner projection cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebUiTimelineCursor(ProjectionCursor);

impl WebUiTimelineCursor {
    pub(crate) fn from_projection(cursor: ProjectionCursor) -> Self {
        Self(cursor)
    }

    pub(crate) fn into_projection(self) -> ProjectionCursor {
        self.0
    }

    pub(crate) fn as_projection(&self) -> &ProjectionCursor {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Per-command outcome types
// ---------------------------------------------------------------------------

/// Successful outcome of [`WebUiService::create_thread`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiThreadCreated {
    pub thread_id: ThreadId,
}

/// Successful outcome of [`WebUiService::send_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiMessageAccepted {
    pub thread_id: ThreadId,
    pub accepted_message_ref: AcceptedMessageRef,
    pub run: WebUiMessageRunOutcome,
}

/// Whether the submitted message produced a new run or was deferred behind an
/// active run on the same thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebUiMessageRunOutcome {
    /// A new run was admitted by the turn coordinator.
    Submitted { run_id: TurnRunId },
    /// The thread already had an active run; this message is queued behind it.
    DeferredBusy { active_run_id: TurnRunId },
}

/// Successful outcome of [`WebUiService::cancel_run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiRunCancelled {
    pub run_id: TurnRunId,
    pub already_terminal: bool,
}

/// Successful outcome of [`WebUiService::resolve_gate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebUiGateResolved {
    /// Gate approved (or a credential was supplied) — run resumed.
    Resumed { run_id: TurnRunId },
    /// Gate denied or cancelled by the user — run cancellation requested.
    Cancelled {
        run_id: TurnRunId,
        already_terminal: bool,
    },
}

/// Initial snapshot result returned by [`WebUiService::get_timeline_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiTimelineSnapshot {
    pub entries: Vec<TimelineEntry>,
    pub runs: Vec<RunStatusProjection>,
    pub next_cursor: WebUiTimelineCursor,
    pub truncated: bool,
}

/// Update batch result returned by [`WebUiService::get_timeline_updates`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiTimelineReplay {
    pub entries: Vec<TimelineEntry>,
    pub runs: Vec<RunStatusProjection>,
    pub next_cursor: WebUiTimelineCursor,
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// Error vocabulary
// ---------------------------------------------------------------------------

/// Redacted error surface for WebUI handlers.
///
/// All internal reasons (provider details, host paths, raw store errors) are
/// summarized into stable variants so callers can map them to HTTP status
/// codes without leaking provider/internal detail.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WebUiServiceError {
    /// Caller lacks an agent binding required for the requested operation.
    #[error("caller is missing required agent context")]
    MissingAgentContext,

    /// The thread store is temporarily unavailable.
    #[error("thread service unavailable")]
    ThreadServiceUnavailable,

    /// The turn coordinator rejected the request with a typed category.
    #[error("turn coordinator rejected request")]
    TurnRejected {
        category: TurnErrorCategory,
        status_code: u16,
    },

    /// A transient downstream failure; safe to retry.
    #[error("transient downstream failure")]
    Transient,

    /// Input failed shape validation inside the facade (e.g. ref construction).
    #[error("invalid input")]
    InvalidInput,

    /// The supplied timeline cursor is older than the durable log can replay
    /// from. The browser must drop the cursor and call
    /// [`WebUiService::get_timeline_snapshot`] again to rebase. The opaque
    /// cursor returned here is the earliest available replay point.
    ///
    /// Boxed so the `Result` size on the happy path stays small — every
    /// facade method returns this error type.
    #[error("timeline cursor is too old; re-snapshot required")]
    TimelineRebaseRequired {
        earliest_cursor: Box<WebUiTimelineCursor>,
    },
}

impl WebUiServiceError {
    /// HTTP status code suggested for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::MissingAgentContext => 400,
            Self::ThreadServiceUnavailable => 503,
            Self::TurnRejected { status_code, .. } => *status_code,
            Self::Transient => 503,
            Self::InvalidInput => 400,
            // 409 Conflict: the browser's view diverged from the durable log;
            // it must re-snapshot before further timeline reads succeed.
            Self::TimelineRebaseRequired { .. } => 409,
        }
    }

    /// Whether this error is safe to retry from the browser.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Transient | Self::ThreadServiceUnavailable)
            || matches!(
                self,
                Self::TurnRejected {
                    status_code: 429 | 503,
                    ..
                }
            )
    }
}

impl From<ProjectionError> for WebUiServiceError {
    fn from(value: ProjectionError) -> Self {
        match value {
            ProjectionError::InvalidRequest { .. } => Self::InvalidInput,
            ProjectionError::Source { .. } => Self::Transient,
            ProjectionError::RebaseRequired { earliest, .. } => Self::TimelineRebaseRequired {
                earliest_cursor: Box::new(WebUiTimelineCursor::from_projection(*earliest)),
            },
        }
    }
}

impl From<SessionThreadError> for WebUiServiceError {
    fn from(_value: SessionThreadError) -> Self {
        Self::ThreadServiceUnavailable
    }
}

impl From<TurnError> for WebUiServiceError {
    fn from(value: TurnError) -> Self {
        let category = value.category();
        let status_code = value.adapter_status_code();
        Self::TurnRejected {
            category,
            status_code,
        }
    }
}

// ---------------------------------------------------------------------------
// Default implementation
// ---------------------------------------------------------------------------

/// Default `WebUiService` that composes a [`SessionThreadService`], a
/// [`TurnCoordinator`], and an [`EventProjectionService`].
pub struct DefaultWebUiService {
    thread_service: std::sync::Arc<dyn SessionThreadService>,
    turn_coordinator: std::sync::Arc<dyn TurnCoordinator>,
    projection_service: std::sync::Arc<dyn EventProjectionService>,
}

impl DefaultWebUiService {
    pub fn new(
        thread_service: std::sync::Arc<dyn SessionThreadService>,
        turn_coordinator: std::sync::Arc<dyn TurnCoordinator>,
        projection_service: std::sync::Arc<dyn EventProjectionService>,
    ) -> Self {
        Self {
            thread_service,
            turn_coordinator,
            projection_service,
        }
    }
}

#[async_trait]
impl WebUiService for DefaultWebUiService {
    async fn create_thread(
        &self,
        command: WebUiCreateThreadCommand,
    ) -> Result<WebUiThreadCreated, WebUiServiceError> {
        let WebUiCreateThreadCommand {
            caller,
            client_action_id: _,
            requested_thread_id,
        } = command;

        let thread_id = match requested_thread_id {
            Some(id) => id,
            None => generate_webui_thread_id()?,
        };
        let scope = webui_thread_scope(&caller, &thread_id)?;

        let record = self
            .thread_service
            .ensure_thread(EnsureThreadRequest {
                scope,
                thread_id: Some(thread_id.clone()),
                created_by_actor_id: caller.user_id.as_str().to_string(),
                title: None,
                metadata_json: None,
            })
            .await?;

        Ok(WebUiThreadCreated {
            thread_id: record.thread_id,
        })
    }

    async fn send_message(
        &self,
        command: WebUiSendMessageCommand,
    ) -> Result<WebUiMessageAccepted, WebUiServiceError> {
        let WebUiSendMessageCommand {
            scope,
            actor,
            client_action_id,
            content,
        } = command;

        let thread_scope = thread_scope_from_turn_scope(&scope, &actor)?;
        let thread_id = scope.thread_id.clone();

        // Idempotent thread ensure so the WebUI never wedges on a missing
        // session_threads row after a partial create.
        self.thread_service
            .ensure_thread(EnsureThreadRequest {
                scope: thread_scope.clone(),
                thread_id: Some(thread_id.clone()),
                created_by_actor_id: actor.user_id.as_str().to_string(),
                title: None,
                metadata_json: None,
            })
            .await?;

        let source_binding_id = webui_binding_id(&actor);
        let accepted = self
            .thread_service
            .accept_inbound_message(ironclaw_threads::AcceptInboundMessageRequest {
                scope: thread_scope.clone(),
                thread_id: thread_id.clone(),
                actor_id: actor.user_id.as_str().to_string(),
                source_binding_id: Some(source_binding_id.clone()),
                reply_target_binding_id: Some(source_binding_id.clone()),
                external_event_id: Some(client_action_id.as_str().to_string()),
                content: MessageContent::text(content),
            })
            .await?;

        let accepted_message_ref = accepted_message_ref(accepted.message_id)?;
        let source_binding_ref = build_source_binding_ref(&source_binding_id)?;
        let reply_target_binding_ref = build_reply_target_binding_ref(&source_binding_id)?;
        let received_at = chrono::Utc::now();

        let request = SubmitTurnRequest {
            scope: scope.clone(),
            actor,
            accepted_message_ref: accepted_message_ref.clone(),
            source_binding_ref,
            reply_target_binding_ref,
            requested_run_profile: None,
            idempotency_key: client_action_id,
            received_at,
        };

        match self.turn_coordinator.submit_turn(request).await {
            Ok(SubmitTurnResponse::Accepted {
                turn_id, run_id, ..
            }) => {
                self.thread_service
                    .mark_message_submitted(
                        &thread_scope,
                        &thread_id,
                        accepted.message_id,
                        turn_id.to_string(),
                        run_id.to_string(),
                    )
                    .await?;
                Ok(WebUiMessageAccepted {
                    thread_id,
                    accepted_message_ref,
                    run: WebUiMessageRunOutcome::Submitted { run_id },
                })
            }
            Err(TurnError::ThreadBusy(busy)) => {
                self.thread_service
                    .mark_message_deferred_busy(&thread_scope, &thread_id, accepted.message_id)
                    .await?;
                Ok(WebUiMessageAccepted {
                    thread_id,
                    accepted_message_ref,
                    run: WebUiMessageRunOutcome::DeferredBusy {
                        active_run_id: busy.active_run_id,
                    },
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn cancel_run(
        &self,
        command: WebUiCancelRunCommand,
    ) -> Result<WebUiRunCancelled, WebUiServiceError> {
        let WebUiCancelRunCommand {
            scope,
            actor,
            run_id,
            reason,
            client_action_id,
        } = command;

        let response = self
            .turn_coordinator
            .cancel_run(CancelRunRequest {
                scope,
                actor,
                run_id,
                reason,
                idempotency_key: client_action_id,
            })
            .await?;

        Ok(WebUiRunCancelled {
            run_id: response.run_id,
            already_terminal: response.already_terminal,
        })
    }

    async fn resolve_gate(
        &self,
        command: WebUiResolveGateCommand,
    ) -> Result<WebUiGateResolved, WebUiServiceError> {
        let WebUiResolveGateCommand {
            scope,
            actor,
            run_id,
            gate_ref,
            client_action_id,
            resolution,
        } = command;

        match resolution {
            WebUiGateResolution::Approved { .. }
            | WebUiGateResolution::CredentialProvided { .. } => {
                let source_binding_id = webui_binding_id(&actor);
                let source_binding_ref = build_source_binding_ref(&source_binding_id)?;
                let reply_target_binding_ref = build_reply_target_binding_ref(&source_binding_id)?;
                let response = self
                    .turn_coordinator
                    .resume_turn(ResumeTurnRequest {
                        scope,
                        actor,
                        run_id,
                        gate_resolution_ref: gate_ref,
                        source_binding_ref,
                        reply_target_binding_ref,
                        idempotency_key: client_action_id,
                    })
                    .await?;
                Ok(WebUiGateResolved::Resumed {
                    run_id: response.run_id,
                })
            }
            WebUiGateResolution::Denied | WebUiGateResolution::Cancelled => {
                let response = self
                    .turn_coordinator
                    .cancel_run(CancelRunRequest {
                        scope,
                        actor,
                        run_id,
                        reason: SanitizedCancelReason::UserRequested,
                        idempotency_key: client_action_id,
                    })
                    .await?;
                Ok(WebUiGateResolved::Cancelled {
                    run_id: response.run_id,
                    already_terminal: response.already_terminal,
                })
            }
        }
    }

    async fn get_timeline_snapshot(
        &self,
        command: WebUiGetTimelineCommand,
    ) -> Result<WebUiTimelineSnapshot, WebUiServiceError> {
        let request = build_projection_request(&command)?;
        let snapshot = self.projection_service.snapshot(request).await?;
        Ok(WebUiTimelineSnapshot {
            entries: snapshot.timeline.entries,
            runs: snapshot.runs,
            next_cursor: WebUiTimelineCursor::from_projection(snapshot.next_cursor),
            truncated: snapshot.truncated,
        })
    }

    async fn get_timeline_updates(
        &self,
        command: WebUiGetTimelineCommand,
    ) -> Result<WebUiTimelineReplay, WebUiServiceError> {
        let request = build_projection_request(&command)?;
        let replay = self.projection_service.updates(request).await?;
        Ok(WebUiTimelineReplay {
            entries: replay.updates,
            runs: replay.runs,
            next_cursor: WebUiTimelineCursor::from_projection(replay.next_cursor),
            truncated: replay.truncated,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_webui_thread_id() -> Result<ThreadId, WebUiServiceError> {
    ThreadId::new(format!("thread:webui:{}", Uuid::new_v4()))
        .map_err(|_| WebUiServiceError::InvalidInput)
}

fn webui_thread_scope(
    caller: &WebUiAuthenticatedCaller,
    _thread_id: &ThreadId,
) -> Result<ThreadScope, WebUiServiceError> {
    let Some(agent_id) = caller.agent_id.clone() else {
        return Err(WebUiServiceError::MissingAgentContext);
    };
    Ok(ThreadScope {
        tenant_id: caller.tenant_id.clone(),
        agent_id,
        project_id: caller.project_id.clone(),
        owner_user_id: Some(caller.user_id.clone()),
        mission_id: None,
    })
}

fn thread_scope_from_turn_scope(
    scope: &TurnScope,
    actor: &TurnActor,
) -> Result<ThreadScope, WebUiServiceError> {
    let Some(agent_id) = scope.agent_id.clone() else {
        return Err(WebUiServiceError::MissingAgentContext);
    };
    Ok(ThreadScope {
        tenant_id: scope.tenant_id.clone(),
        agent_id,
        project_id: scope.project_id.clone(),
        owner_user_id: Some(actor.user_id.clone()),
        mission_id: None,
    })
}

fn webui_binding_id(actor: &TurnActor) -> String {
    format!("webui:{}", actor.user_id.as_str())
}

fn accepted_message_ref(
    message_id: ironclaw_threads::ThreadMessageId,
) -> Result<AcceptedMessageRef, WebUiServiceError> {
    AcceptedMessageRef::new(format!("msg:{message_id}"))
        .map_err(|_| WebUiServiceError::InvalidInput)
}

fn build_source_binding_ref(value: &str) -> Result<SourceBindingRef, WebUiServiceError> {
    bounded_binding_ref(value)
        .and_then(|v| SourceBindingRef::new(v).map_err(|_| WebUiServiceError::InvalidInput))
}

fn build_reply_target_binding_ref(value: &str) -> Result<ReplyTargetBindingRef, WebUiServiceError> {
    bounded_binding_ref(value)
        .and_then(|v| ReplyTargetBindingRef::new(v).map_err(|_| WebUiServiceError::InvalidInput))
}

/// Bound a binding-ref string to a length the typed ref accepts. Long values
/// hash to a deterministic UUIDv5 so the ref is still stable per caller.
fn bounded_binding_ref(value: &str) -> Result<String, WebUiServiceError> {
    if value.len() <= 240 && !value.chars().any(|c| c == '\0' || c.is_control()) {
        Ok(value.to_string())
    } else {
        Ok(format!(
            "webui:{}",
            Uuid::new_v5(&Uuid::NAMESPACE_OID, value.as_bytes())
        ))
    }
}

fn build_projection_request(
    command: &WebUiGetTimelineCommand,
) -> Result<ProjectionRequest, WebUiServiceError> {
    let Some(agent_id) = command.caller.agent_id.clone() else {
        return Err(WebUiServiceError::MissingAgentContext);
    };
    let stream = EventStreamKey::new(
        command.caller.tenant_id.clone(),
        command.caller.user_id.clone(),
        Some(agent_id),
    );
    let read_scope = ReadScope {
        project_id: command.caller.project_id.clone(),
        mission_id: None,
        thread_id: Some(command.thread_id.clone()),
        process_id: None,
    };
    let scope = ProjectionScope { stream, read_scope };

    if let Some(cursor) = &command.after {
        // Defense in depth: the cursor must match the caller's scope.
        // The projection service also re-checks this, but rejecting early
        // keeps the error surface to typed `InvalidInput` rather than the
        // projection's stringly-typed rebase-required.
        if cursor.as_projection().scope != scope {
            return Err(WebUiServiceError::InvalidInput);
        }
    }

    let limit = clamp_timeline_limit(command.limit);
    Ok(ProjectionRequest {
        scope,
        after: command
            .after
            .clone()
            .map(WebUiTimelineCursor::into_projection),
        limit,
    })
}

/// Clamp the caller-supplied limit into `[1, MAX_PROJECTION_PAGE_LIMIT]`, using
/// [`WEBUI_TIMELINE_DEFAULT_LIMIT`] when the caller passes `0`.
fn clamp_timeline_limit(requested: usize) -> usize {
    let normalized = if requested == 0 {
        WEBUI_TIMELINE_DEFAULT_LIMIT
    } else {
        requested
    };
    normalized.min(MAX_PROJECTION_PAGE_LIMIT)
}
