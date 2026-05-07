use async_trait::async_trait;
use ironclaw_host_api::{CapabilityId, ExtensionId, ProcessId, RuntimeKind, ThreadId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    LoopDiagnosticRef, LoopGateRef, LoopMessageRef, LoopResultRef, RunProfileVersion,
    TurnCheckpointId, TurnId, TurnRunId, TurnScope, events::EventCursor,
};

use super::{
    refs::{CheckpointSchemaId, LoopDriverId, ModelProfileId},
    snapshot::ResolvedRunProfile,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopRunContext {
    pub scope: TurnScope,
    pub thread_id: ThreadId,
    pub turn_id: TurnId,
    pub run_id: TurnRunId,
    pub resolved_run_profile: ResolvedRunProfile,
    pub loop_driver_id: LoopDriverId,
    pub loop_driver_version: RunProfileVersion,
    pub checkpoint_schema_id: CheckpointSchemaId,
    pub checkpoint_schema_version: RunProfileVersion,
}

impl LoopRunContext {
    pub fn new(
        scope: TurnScope,
        turn_id: TurnId,
        run_id: TurnRunId,
        resolved_run_profile: ResolvedRunProfile,
    ) -> Self {
        let thread_id = scope.thread_id.clone();
        Self {
            scope,
            thread_id,
            turn_id,
            run_id,
            loop_driver_id: resolved_run_profile.loop_driver.id.clone(),
            loop_driver_version: resolved_run_profile.loop_driver.version,
            checkpoint_schema_id: resolved_run_profile.checkpoint_schema_id.clone(),
            checkpoint_schema_version: resolved_run_profile.checkpoint_schema_version,
            resolved_run_profile,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLoopHostErrorKind {
    Unauthorized,
    ScopeMismatch,
    StaleSurface,
    InvalidInvocation,
    PolicyDenied,
    BudgetExceeded,
    Unavailable,
    Cancelled,
    CheckpointRejected,
    TranscriptWriteFailed,
    Internal,
}

impl AgentLoopHostErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::ScopeMismatch => "scope_mismatch",
            Self::StaleSurface => "stale_surface",
            Self::InvalidInvocation => "invalid_invocation",
            Self::PolicyDenied => "policy_denied",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::CheckpointRejected => "checkpoint_rejected",
            Self::TranscriptWriteFailed => "transcript_write_failed",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("agent loop host {kind:?}: {safe_summary}")]
pub struct AgentLoopHostError {
    pub kind: AgentLoopHostErrorKind,
    pub safe_summary: String,
    pub diagnostic_ref: Option<LoopDiagnosticRef>,
}

impl AgentLoopHostError {
    pub fn new(kind: AgentLoopHostErrorKind, safe_summary: impl Into<String>) -> Self {
        Self {
            kind,
            safe_summary: safe_summary.into(),
            diagnostic_ref: None,
        }
    }

    pub fn with_diagnostic_ref(mut self, diagnostic_ref: LoopDiagnosticRef) -> Self {
        self.diagnostic_ref = Some(diagnostic_ref);
        self
    }
}

pub trait LoopRunInfoPort: Send + Sync {
    fn run_context(&self) -> &LoopRunContext;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopContextRequest {
    pub after: Option<LoopInputCursor>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopContextBundle {
    pub messages: Vec<LoopContextMessage>,
    pub instruction_snippets: Vec<LoopContextSnippet>,
    pub memory_snippets: Vec<LoopContextSnippet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopContextMessage {
    pub message_ref: LoopMessageRef,
    pub role: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopContextSnippet {
    pub snippet_ref: String,
    pub safe_summary: String,
}

#[async_trait]
pub trait LoopContextPort: Send + Sync {
    async fn load_loop_context(
        &self,
        request: LoopContextRequest,
    ) -> Result<LoopContextBundle, AgentLoopHostError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct LoopInputCursor(EventCursor);

impl LoopInputCursor {
    pub fn from_event_cursor(cursor: EventCursor) -> Self {
        Self(cursor)
    }

    pub fn as_event_cursor(self) -> EventCursor {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopInputBatch {
    pub inputs: Vec<LoopInput>,
    pub next_cursor: LoopInputCursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopInput {
    UserMessage { message_ref: LoopMessageRef },
    FollowUp { message_ref: LoopMessageRef },
    Steering { message_ref: LoopMessageRef },
    Interrupt { kind: LoopInterruptKind },
    Cancel { reason_kind: LoopCancelReasonKind },
    GateResolved { gate_ref: LoopGateRef },
    CapabilitySurfaceChanged { version: CapabilitySurfaceVersion },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopInterruptKind {
    UserInterrupt,
    HostShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopCancelReasonKind {
    UserRequested,
    Superseded,
    Policy,
}

#[async_trait]
pub trait LoopInputPort: Send + Sync {
    async fn poll_inputs(
        &self,
        after: LoopInputCursor,
        limit: usize,
    ) -> Result<LoopInputBatch, AgentLoopHostError>;

    async fn ack_inputs(&self, cursor: LoopInputCursor) -> Result<(), AgentLoopHostError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySurfaceVersion(u64);

impl CapabilitySurfaceVersion {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopModelRequest {
    pub messages: Vec<LoopModelMessage>,
    pub surface_version: Option<CapabilitySurfaceVersion>,
    pub model_preference: Option<ModelProfileId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopModelMessage {
    pub role: String,
    pub content_ref: LoopMessageRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopModelResponse {
    pub chunks: Vec<ModelStreamChunk>,
    pub output: ParentLoopOutput,
    pub effective_model_profile_id: ModelProfileId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStreamChunk {
    pub safe_text_delta: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentLoopOutput {
    AssistantReply(AssistantReply),
    CapabilityCalls(Vec<CapabilityCallCandidate>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistantReply {
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCallCandidate {
    pub surface_version: CapabilitySurfaceVersion,
    pub capability_id: CapabilityId,
    pub arguments: Value,
}

#[async_trait]
pub trait LoopModelPort: Send + Sync {
    async fn stream_model(
        &self,
        request: LoopModelRequest,
    ) -> Result<LoopModelResponse, AgentLoopHostError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VisibleCapabilityRequest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleCapabilitySurface {
    pub version: CapabilitySurfaceVersion,
    pub descriptors: Vec<CapabilityDescriptorView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDescriptorView {
    pub capability_id: CapabilityId,
    pub provider: Option<ExtensionId>,
    pub runtime: RuntimeKind,
    pub safe_name: String,
    pub safe_description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInvocation {
    pub surface_version: CapabilitySurfaceVersion,
    pub capability_id: CapabilityId,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityBatchInvocation {
    pub invocations: Vec<CapabilityInvocation>,
    pub stop_on_first_suspension: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityBatchOutcome {
    pub outcomes: Vec<CapabilityOutcome>,
    pub stopped_on_suspension: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOutcome {
    Completed(CapabilityResultMessage),
    ApprovalRequired {
        gate_ref: LoopGateRef,
        safe_summary: String,
    },
    AuthRequired {
        gate_ref: LoopGateRef,
        safe_summary: String,
    },
    ResourceBlocked {
        gate_ref: LoopGateRef,
        safe_summary: String,
    },
    SpawnedProcess(ProcessHandleSummary),
    Denied(CapabilityDenied),
    Failed(CapabilityFailure),
}

impl CapabilityOutcome {
    pub fn is_suspension(&self) -> bool {
        matches!(
            self,
            Self::ApprovalRequired { .. }
                | Self::AuthRequired { .. }
                | Self::ResourceBlocked { .. }
                | Self::SpawnedProcess(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityResultMessage {
    pub result_ref: LoopResultRef,
    pub safe_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessHandleSummary {
    pub process_id: ProcessId,
    pub safe_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDenied {
    pub reason_kind: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFailure {
    pub error_kind: String,
    pub safe_summary: String,
}

#[async_trait]
pub trait LoopCapabilityPort: Send + Sync {
    async fn visible_capabilities(
        &self,
        request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, AgentLoopHostError>;

    async fn invoke_capability(
        &self,
        request: CapabilityInvocation,
    ) -> Result<CapabilityOutcome, AgentLoopHostError>;

    async fn invoke_capability_batch(
        &self,
        request: CapabilityBatchInvocation,
    ) -> Result<CapabilityBatchOutcome, AgentLoopHostError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginAssistantDraft {
    pub reply: AssistantReply,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAssistantDraft {
    pub message_ref: LoopMessageRef,
    pub reply: AssistantReply,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeAssistantMessage {
    pub reply: AssistantReply,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendCapabilityResultRef {
    pub result_ref: LoopResultRef,
    pub safe_summary: String,
}

#[async_trait]
pub trait LoopTranscriptPort: Send + Sync {
    async fn begin_assistant_draft(
        &self,
        _request: BeginAssistantDraft,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        Err(unsupported_host_method("begin_assistant_draft"))
    }

    async fn update_assistant_draft(
        &self,
        _request: UpdateAssistantDraft,
    ) -> Result<(), AgentLoopHostError> {
        Err(unsupported_host_method("update_assistant_draft"))
    }

    async fn finalize_assistant_message(
        &self,
        request: FinalizeAssistantMessage,
    ) -> Result<LoopMessageRef, AgentLoopHostError>;

    async fn append_capability_result_ref(
        &self,
        _request: AppendCapabilityResultRef,
    ) -> Result<LoopMessageRef, AgentLoopHostError> {
        Err(unsupported_host_method("append_capability_result_ref"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopCheckpointRequest {
    pub kind: LoopCheckpointKind,
    pub state_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopCheckpointKind {
    BeforeModel,
    BeforeSideEffect,
    BeforeBlock,
    Final,
}

impl LoopCheckpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeModel => "before_model",
            Self::BeforeSideEffect => "before_side_effect",
            Self::BeforeBlock => "before_block",
            Self::Final => "final",
        }
    }
}

#[async_trait]
pub trait LoopCheckpointPort: Send + Sync {
    async fn checkpoint(
        &self,
        request: LoopCheckpointRequest,
    ) -> Result<TurnCheckpointId, AgentLoopHostError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopProgressEvent {
    ModelStarted,
    ModelCompleted,
    CapabilityInvoked {
        capability_id: CapabilityId,
    },
    CheckpointCreated {
        checkpoint_id: TurnCheckpointId,
    },
    TranscriptFinalized {
        message_ref: LoopMessageRef,
    },
    Blocked {
        gate_ref: LoopGateRef,
        checkpoint_id: TurnCheckpointId,
    },
    Completed,
    Failed {
        reason_kind: String,
    },
    DriverNote {
        kind: LoopDriverNoteKind,
        safe_summary: String,
    },
}

impl LoopProgressEvent {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ModelStarted => "model_started",
            Self::ModelCompleted => "model_completed",
            Self::CapabilityInvoked { .. } => "capability_invoked",
            Self::CheckpointCreated { .. } => "checkpoint_created",
            Self::TranscriptFinalized { .. } => "transcript_finalized",
            Self::Blocked { .. } => "blocked",
            Self::Completed => "completed",
            Self::Failed { .. } => "failed",
            Self::DriverNote { .. } => "driver_note",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopDriverNoteKind {
    Planning,
    Waiting,
    Retrying,
}

#[async_trait]
pub trait LoopProgressPort: Send + Sync {
    async fn emit_loop_progress(&self, event: LoopProgressEvent) -> Result<(), AgentLoopHostError>;
}

pub trait AgentLoopDriverHost:
    LoopRunInfoPort
    + LoopContextPort
    + LoopInputPort
    + LoopModelPort
    + LoopCapabilityPort
    + LoopTranscriptPort
    + LoopCheckpointPort
    + LoopProgressPort
    + Send
    + Sync
{
}

impl<T> AgentLoopDriverHost for T where
    T: LoopRunInfoPort
        + LoopContextPort
        + LoopInputPort
        + LoopModelPort
        + LoopCapabilityPort
        + LoopTranscriptPort
        + LoopCheckpointPort
        + LoopProgressPort
        + Send
        + Sync
{
}

pub trait AgentLoopHost: AgentLoopDriverHost {}

impl<T> AgentLoopHost for T where T: AgentLoopDriverHost + ?Sized {}

fn unsupported_host_method(method: &'static str) -> AgentLoopHostError {
    AgentLoopHostError::new(
        AgentLoopHostErrorKind::Unavailable,
        format!("agent loop host method {method} is unavailable"),
    )
}
