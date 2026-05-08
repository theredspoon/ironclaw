//! Loop support services for IronClaw Reborn.
//!
//! This crate adapts durable Reborn support boundaries (threads/transcripts plus
//! host-managed model gateways) into the narrow `AgentLoopHost` ports. It does
//! not own provider clients, tool dispatchers, secrets, or runtime handles.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use ironclaw_threads::{
    AppendAssistantDraftRequest, ContextMessage, LoadContextWindowRequest, MessageContent,
    MessageKind, SessionThreadError, SessionThreadService, ThreadMessageId, ThreadScope,
    UpdateAssistantDraftRequest,
};
use ironclaw_turns::{
    LoopMessageRef,
    run_profile::ModelProfileId,
    run_profile::{
        AgentLoopHostError, AgentLoopHostErrorKind, AssistantReply, BeginAssistantDraft,
        CapabilityBatchInvocation, CapabilityBatchOutcome, CapabilityDenied, CapabilityInvocation,
        CapabilityOutcome, CapabilitySurfaceVersion, FinalizeAssistantMessage, LoopContextBundle,
        LoopContextMessage, LoopContextPort, LoopContextRequest, LoopModelMessage, LoopModelPort,
        LoopModelRequest, LoopModelResponse, LoopRunContext, LoopRunInfoPort, LoopTranscriptPort,
        ModelStreamChunk, ParentLoopOutput, UpdateAssistantDraft, VisibleCapabilityRequest,
        VisibleCapabilitySurface,
    },
};
use serde::{Deserialize, Serialize};

const EMPTY_SURFACE_VERSION: &str = "empty:v1";

/// Thread-backed context adapter for text-only Reborn loops.
#[derive(Clone)]
pub struct ThreadBackedLoopContextPort<S>
where
    S: SessionThreadService + ?Sized,
{
    thread_service: Arc<S>,
    thread_scope: ThreadScope,
    run_context: LoopRunContext,
    max_messages: usize,
}

impl<S> ThreadBackedLoopContextPort<S>
where
    S: SessionThreadService + ?Sized,
{
    pub fn new(
        thread_service: Arc<S>,
        thread_scope: ThreadScope,
        run_context: LoopRunContext,
        max_messages: usize,
    ) -> Self {
        Self {
            thread_service,
            thread_scope,
            run_context,
            max_messages,
        }
    }
}

impl<S> LoopRunInfoPort for ThreadBackedLoopContextPort<S>
where
    S: SessionThreadService + ?Sized + Send + Sync,
{
    fn run_context(&self) -> &LoopRunContext {
        &self.run_context
    }
}

#[async_trait]
impl<S> LoopContextPort for ThreadBackedLoopContextPort<S>
where
    S: SessionThreadService + ?Sized + Send + Sync,
{
    async fn load_loop_context(
        &self,
        request: LoopContextRequest,
    ) -> Result<LoopContextBundle, AgentLoopHostError> {
        validate_thread_scope_for_run(&self.thread_scope, &self.run_context)?;
        let max_messages = bounded_limit(request.limit, self.max_messages);
        let context = self
            .thread_service
            .load_context_window(LoadContextWindowRequest {
                scope: self.thread_scope.clone(),
                thread_id: self.run_context.thread_id.clone(),
                max_messages,
            })
            .await
            .map_err(context_read_error)?;

        Ok(LoopContextBundle {
            messages: context
                .messages
                .into_iter()
                .filter_map(context_message_to_loop_message)
                .collect(),
            instruction_snippets: Vec::new(),
            memory_snippets: Vec::new(),
        })
    }
}

/// Thread-backed transcript adapter for text-only assistant replies.
#[derive(Clone)]
pub struct ThreadBackedLoopTranscriptPort<S>
where
    S: SessionThreadService + ?Sized,
{
    thread_service: Arc<S>,
    thread_scope: ThreadScope,
    run_context: LoopRunContext,
}

impl<S> ThreadBackedLoopTranscriptPort<S>
where
    S: SessionThreadService + ?Sized,
{
    pub fn new(
        thread_service: Arc<S>,
        thread_scope: ThreadScope,
        run_context: LoopRunContext,
    ) -> Self {
        Self {
            thread_service,
            thread_scope,
            run_context,
        }
    }
}

impl<S> LoopRunInfoPort for ThreadBackedLoopTranscriptPort<S>
where
    S: SessionThreadService + ?Sized + Send + Sync,
{
    fn run_context(&self) -> &LoopRunContext {
        &self.run_context
    }
}

#[async_trait]
impl<S> LoopTranscriptPort for ThreadBackedLoopTranscriptPort<S>
where
    S: SessionThreadService + ?Sized + Send + Sync,
{
    async fn begin_assistant_draft(
        &self,
        request: BeginAssistantDraft,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        validate_thread_scope_for_run(&self.thread_scope, &self.run_context)?;
        let draft = self
            .thread_service
            .append_assistant_draft(AppendAssistantDraftRequest {
                scope: self.thread_scope.clone(),
                thread_id: self.run_context.thread_id.clone(),
                turn_run_id: self.run_context.run_id.to_string(),
                content: MessageContent::text(request.reply.content),
            })
            .await
            .map_err(transcript_write_error)?;
        message_ref(draft.message_id)
    }

    async fn update_assistant_draft(
        &self,
        request: UpdateAssistantDraft,
    ) -> Result<(), AgentLoopHostError> {
        validate_thread_scope_for_run(&self.thread_scope, &self.run_context)?;
        let message_id = message_id_from_ref(&request.message_ref)?;
        self.thread_service
            .update_assistant_draft(UpdateAssistantDraftRequest {
                scope: self.thread_scope.clone(),
                thread_id: self.run_context.thread_id.clone(),
                message_id,
                content: MessageContent::text(request.reply.content),
            })
            .await
            .map_err(transcript_write_error)?;
        Ok(())
    }

    async fn finalize_assistant_message(
        &self,
        request: FinalizeAssistantMessage,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        validate_thread_scope_for_run(&self.thread_scope, &self.run_context)?;
        let draft = self
            .thread_service
            .append_assistant_draft(AppendAssistantDraftRequest {
                scope: self.thread_scope.clone(),
                thread_id: self.run_context.thread_id.clone(),
                turn_run_id: self.run_context.run_id.to_string(),
                content: MessageContent::text(request.reply.content.clone()),
            })
            .await
            .map_err(transcript_write_error)?;
        let finalized = self
            .thread_service
            .finalize_assistant_message(
                &self.thread_scope,
                &self.run_context.thread_id,
                draft.message_id,
                MessageContent::text(request.reply.content),
            )
            .await
            .map_err(transcript_write_error)?;
        message_ref(finalized.message_id)
    }
}

/// Empty capability surface for the text-only loop-support MVP.
#[derive(Debug, Clone, Default)]
pub struct EmptyLoopCapabilityPort;

#[async_trait]
impl ironclaw_turns::run_profile::LoopCapabilityPort for EmptyLoopCapabilityPort {
    async fn visible_capabilities(
        &self,
        _request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, AgentLoopHostError> {
        Ok(VisibleCapabilitySurface {
            version: empty_surface_version()?,
            descriptors: Vec::new(),
        })
    }

    async fn invoke_capability(
        &self,
        request: CapabilityInvocation,
    ) -> Result<CapabilityOutcome, AgentLoopHostError> {
        let empty_surface_version = empty_surface_version()?;
        if request.surface_version != empty_surface_version {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::StaleSurface,
                "capability surface is stale or unknown",
            ));
        }
        Err(empty_capability_error())
    }

    async fn invoke_capability_batch(
        &self,
        request: CapabilityBatchInvocation,
    ) -> Result<CapabilityBatchOutcome, AgentLoopHostError> {
        let empty_surface_version = empty_surface_version()?;
        if request
            .invocations
            .iter()
            .any(|invocation| invocation.surface_version != empty_surface_version)
        {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::StaleSurface,
                "capability surface is stale or unknown",
            ));
        }
        let outcomes = request
            .invocations
            .into_iter()
            .map(|_| {
                CapabilityOutcome::Denied(CapabilityDenied {
                    reason_kind: "empty_surface".to_string(),
                    safe_summary: "no capabilities are available to this loop".to_string(),
                })
            })
            .collect();
        Ok(CapabilityBatchOutcome {
            outcomes,
            stopped_on_suspension: false,
        })
    }
}

/// Thread-backed model adapter that resolves loop message references before
/// delegating completion to a host-managed gateway.
#[derive(Clone)]
pub struct ThreadBackedLoopModelPort<S, G>
where
    S: SessionThreadService + ?Sized,
    G: HostManagedModelGateway + ?Sized,
{
    thread_service: Arc<S>,
    thread_scope: ThreadScope,
    run_context: LoopRunContext,
    gateway: Arc<G>,
    max_messages: usize,
}

impl<S, G> ThreadBackedLoopModelPort<S, G>
where
    S: SessionThreadService + ?Sized,
    G: HostManagedModelGateway + ?Sized,
{
    pub fn new(
        thread_service: Arc<S>,
        thread_scope: ThreadScope,
        run_context: LoopRunContext,
        gateway: Arc<G>,
        max_messages: usize,
    ) -> Self {
        Self {
            thread_service,
            thread_scope,
            run_context,
            gateway,
            max_messages,
        }
    }
}

impl<S, G> LoopRunInfoPort for ThreadBackedLoopModelPort<S, G>
where
    S: SessionThreadService + ?Sized + Send + Sync,
    G: HostManagedModelGateway + ?Sized + Send + Sync,
{
    fn run_context(&self) -> &LoopRunContext {
        &self.run_context
    }
}

#[async_trait]
impl<S, G> LoopModelPort for ThreadBackedLoopModelPort<S, G>
where
    S: SessionThreadService + ?Sized + Send + Sync,
    G: HostManagedModelGateway + ?Sized + Send + Sync,
{
    async fn stream_model(
        &self,
        request: LoopModelRequest,
    ) -> Result<LoopModelResponse, AgentLoopHostError> {
        validate_thread_scope_for_run(&self.thread_scope, &self.run_context)?;
        let model_profile_id = request.model_preference.clone().unwrap_or_else(|| {
            self.run_context
                .resolved_run_profile
                .model_profile_id
                .clone()
        });
        let resolved_messages = self.resolve_model_messages(request.messages).await?;
        let gateway_response = self
            .gateway
            .stream_model(HostManagedModelRequest {
                model_profile_id: model_profile_id.clone(),
                messages: resolved_messages,
                surface_version: request.surface_version,
                run_id: self.run_context.run_id.to_string(),
                turn_id: self.run_context.turn_id.to_string(),
            })
            .await
            .map_err(model_gateway_error)?;

        Ok(LoopModelResponse {
            chunks: gateway_response
                .safe_text_deltas
                .into_iter()
                .map(|safe_text_delta| ModelStreamChunk { safe_text_delta })
                .collect(),
            output: gateway_response.output,
            effective_model_profile_id: model_profile_id,
        })
    }
}

impl<S, G> ThreadBackedLoopModelPort<S, G>
where
    S: SessionThreadService + ?Sized + Send + Sync,
    G: HostManagedModelGateway + ?Sized + Send + Sync,
{
    async fn resolve_model_messages(
        &self,
        requested_messages: Vec<LoopModelMessage>,
    ) -> Result<Vec<HostManagedModelMessage>, AgentLoopHostError> {
        let context = self
            .thread_service
            .load_context_window(LoadContextWindowRequest {
                scope: self.thread_scope.clone(),
                thread_id: self.run_context.thread_id.clone(),
                max_messages: self.max_messages,
            })
            .await
            .map_err(context_read_error)?;

        if requested_messages.is_empty() {
            let messages = context
                .messages
                .into_iter()
                .filter_map(|message| {
                    let content_ref = message_ref_from_context(&message)?;
                    Some(HostManagedModelMessage {
                        role: model_role_for_kind(message.kind),
                        content: message.content,
                        content_ref,
                    })
                })
                .collect();
            return Ok(messages);
        }

        let messages_by_ref = context_messages_by_ref(context.messages);
        let mut resolved = Vec::with_capacity(requested_messages.len());
        for message in requested_messages {
            let context_message = messages_by_ref
                .get(message.content_ref.as_str())
                .ok_or_else(|| {
                    AgentLoopHostError::new(
                        AgentLoopHostErrorKind::InvalidInvocation,
                        "model message reference is unavailable",
                    )
                })?;
            resolved.push(HostManagedModelMessage {
                role: HostManagedModelMessageRole::from_loop_role(&message.role)?,
                content: context_message.content.clone(),
                content_ref: message.content_ref,
            });
        }
        Ok(resolved)
    }
}

/// Host-managed text-only model gateway. Implementations own provider selection,
/// profile policy, retry/circuit behavior, and sanitization.
#[async_trait]
pub trait HostManagedModelGateway: Send + Sync {
    async fn stream_model(
        &self,
        request: HostManagedModelRequest,
    ) -> Result<HostManagedModelResponse, HostManagedModelError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostManagedModelRequest {
    pub model_profile_id: ModelProfileId,
    pub messages: Vec<HostManagedModelMessage>,
    pub surface_version: Option<CapabilitySurfaceVersion>,
    pub run_id: String,
    pub turn_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostManagedModelMessage {
    pub role: HostManagedModelMessageRole,
    pub content: String,
    pub content_ref: LoopMessageRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostManagedModelMessageRole {
    System,
    User,
    Assistant,
}

impl HostManagedModelMessageRole {
    fn from_loop_role(role: &str) -> Result<Self, AgentLoopHostError> {
        match role {
            "system" => Ok(Self::System),
            "user" => Ok(Self::User),
            "assistant" => Ok(Self::Assistant),
            _ => Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::InvalidInvocation,
                "model message role is unsupported",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostManagedModelResponse {
    pub safe_text_deltas: Vec<String>,
    pub output: ParentLoopOutput,
}

impl HostManagedModelResponse {
    pub fn assistant_reply(content: impl Into<String>) -> Self {
        let content = content.into();
        Self {
            safe_text_deltas: vec![content.clone()],
            output: ParentLoopOutput::AssistantReply(AssistantReply { content }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostManagedModelErrorKind {
    InvalidRequest,
    PolicyDenied,
    BudgetExceeded,
    Unavailable,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("host-managed model {kind:?}: {safe_summary}")]
pub struct HostManagedModelError {
    pub kind: HostManagedModelErrorKind,
    pub safe_summary: String,
}

impl HostManagedModelError {
    pub fn new(kind: HostManagedModelErrorKind, _raw_detail: impl Into<String>) -> Self {
        Self {
            kind,
            safe_summary: safe_model_summary(kind).to_string(),
        }
    }

    pub fn safe(kind: HostManagedModelErrorKind, safe_summary: impl Into<String>) -> Self {
        Self {
            kind,
            safe_summary: safe_summary.into(),
        }
    }
}

fn validate_thread_scope_for_run(
    thread_scope: &ThreadScope,
    run_context: &LoopRunContext,
) -> Result<(), AgentLoopHostError> {
    if thread_scope.tenant_id != run_context.scope.tenant_id
        || Some(thread_scope.agent_id.clone()) != run_context.scope.agent_id
        || thread_scope.project_id != run_context.scope.project_id
    {
        return Err(AgentLoopHostError::new(
            AgentLoopHostErrorKind::ScopeMismatch,
            "thread scope does not match loop run scope",
        ));
    }
    Ok(())
}

fn bounded_limit(requested: usize, configured: usize) -> usize {
    let configured = configured.max(1);
    if requested == 0 {
        configured
    } else {
        requested.min(configured)
    }
}

fn context_messages_by_ref(messages: Vec<ContextMessage>) -> HashMap<String, ContextMessage> {
    messages
        .into_iter()
        .filter_map(|message| {
            message_ref_from_context(&message)
                .map(|message_ref| (message_ref.as_str().to_string(), message))
        })
        .collect()
}

fn context_message_to_loop_message(message: ContextMessage) -> Option<LoopContextMessage> {
    let message_ref = message_ref_from_context(&message)?;
    Some(LoopContextMessage {
        message_ref,
        role: role_for_kind(message.kind).to_string(),
        safe_summary: message.content,
    })
}

fn message_ref_from_context(message: &ContextMessage) -> Option<LoopMessageRef> {
    if let Some(message_id) = message.message_id {
        return message_ref(message_id).ok();
    }
    message.summary_id.and_then(|summary_id| {
        LoopMessageRef::new(format!("msg:summary-{summary_id}"))
            .map_err(|_| ())
            .ok()
    })
}

fn message_ref(message_id: ThreadMessageId) -> Result<LoopMessageRef, AgentLoopHostError> {
    LoopMessageRef::new(format!("msg:{message_id}")).map_err(|_| {
        AgentLoopHostError::new(
            AgentLoopHostErrorKind::Internal,
            "thread message reference could not be represented",
        )
    })
}

fn message_id_from_ref(
    message_ref: &LoopMessageRef,
) -> Result<ThreadMessageId, AgentLoopHostError> {
    let raw = message_ref.as_str().strip_prefix("msg:").ok_or_else(|| {
        AgentLoopHostError::new(
            AgentLoopHostErrorKind::InvalidInvocation,
            "transcript message reference is invalid",
        )
    })?;
    ThreadMessageId::parse(raw).map_err(|_| {
        AgentLoopHostError::new(
            AgentLoopHostErrorKind::InvalidInvocation,
            "transcript message reference is invalid",
        )
    })
}

fn role_for_kind(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::User => "user",
        MessageKind::Assistant => "assistant",
        MessageKind::System | MessageKind::Summary | MessageKind::CheckpointReference => "system",
        MessageKind::ToolResultReference => "tool_result_reference",
    }
}

fn model_role_for_kind(kind: MessageKind) -> HostManagedModelMessageRole {
    match kind {
        MessageKind::User => HostManagedModelMessageRole::User,
        MessageKind::Assistant => HostManagedModelMessageRole::Assistant,
        MessageKind::System
        | MessageKind::Summary
        | MessageKind::CheckpointReference
        | MessageKind::ToolResultReference => HostManagedModelMessageRole::System,
    }
}

fn empty_surface_version() -> Result<CapabilitySurfaceVersion, AgentLoopHostError> {
    CapabilitySurfaceVersion::new(EMPTY_SURFACE_VERSION).map_err(|_| {
        AgentLoopHostError::new(
            AgentLoopHostErrorKind::Internal,
            "empty capability surface version is invalid",
        )
    })
}

fn empty_capability_error() -> AgentLoopHostError {
    AgentLoopHostError::new(
        AgentLoopHostErrorKind::InvalidInvocation,
        "no capabilities are available to this loop",
    )
}

fn context_read_error(_error: SessionThreadError) -> AgentLoopHostError {
    AgentLoopHostError::new(
        AgentLoopHostErrorKind::Unavailable,
        "thread context is unavailable",
    )
}

fn transcript_write_error(_error: SessionThreadError) -> AgentLoopHostError {
    AgentLoopHostError::new(
        AgentLoopHostErrorKind::TranscriptWriteFailed,
        "assistant transcript write failed",
    )
}

fn model_gateway_error(error: HostManagedModelError) -> AgentLoopHostError {
    AgentLoopHostError::new(model_error_kind(error.kind), error.safe_summary)
}

fn model_error_kind(kind: HostManagedModelErrorKind) -> AgentLoopHostErrorKind {
    match kind {
        HostManagedModelErrorKind::InvalidRequest => AgentLoopHostErrorKind::InvalidInvocation,
        HostManagedModelErrorKind::PolicyDenied => AgentLoopHostErrorKind::PolicyDenied,
        HostManagedModelErrorKind::BudgetExceeded => AgentLoopHostErrorKind::BudgetExceeded,
        HostManagedModelErrorKind::Unavailable => AgentLoopHostErrorKind::Unavailable,
        HostManagedModelErrorKind::Cancelled => AgentLoopHostErrorKind::Cancelled,
    }
}

fn safe_model_summary(kind: HostManagedModelErrorKind) -> &'static str {
    match kind {
        HostManagedModelErrorKind::InvalidRequest => "model request is invalid",
        HostManagedModelErrorKind::PolicyDenied => "model profile is not permitted",
        HostManagedModelErrorKind::BudgetExceeded => "model request exceeded its budget",
        HostManagedModelErrorKind::Unavailable => "model service is unavailable",
        HostManagedModelErrorKind::Cancelled => "model request was cancelled",
    }
}
