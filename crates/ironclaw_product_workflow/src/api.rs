//! Public API re-exports for `ironclaw_product_workflow`.
//!
//! Keep this file as the crate-facing export map. Implementation and ownership
//! rules live in the module files themselves.

pub use crate::action::{
    ActionDispatchKind, ActionFingerprintKey, ActionPhase, AuthRequestRef, LinkedThreadActionId,
    ProductActionId, ProductCommandName, ProductInboundAction, SourceBindingKey,
};
pub use crate::binding::{ConversationBindingService, ResolveBindingRequest, ResolvedBinding};
pub use crate::error::ProductWorkflowError;
#[cfg(any(test, feature = "test-support"))]
pub use crate::fakes::{
    FakeConversationBindingService, FakeIdempotencyLedger, FakeInboundTurnService,
};
pub use crate::inbound_turn::{DefaultInboundTurnService, InboundTurnOutcome, InboundTurnService};
pub use crate::ledger::{IdempotencyDecision, IdempotencyLedger};
pub use crate::reborn_services::{
    RebornCancelRunResponse, RebornCreateThreadResponse, RebornResolveGateResponse,
    RebornResumeGateResponse, RebornServices, RebornServicesApi, RebornServicesError,
    RebornServicesErrorCode, RebornStreamEventsRequest, RebornStreamEventsResponse,
    RebornSubmitTurnResponse, RebornTimelineRequest, RebornTimelineResponse,
};
pub use crate::webui_inbound::{
    WebUiAuthenticatedCaller, WebUiCancelReason, WebUiCancelRunRequest, WebUiCreateThreadRequest,
    WebUiGateResolution, WebUiInboundCommand, WebUiInboundValidationCode,
    WebUiInboundValidationError, WebUiResolveGateRequest, WebUiSendMessageRequest,
};
pub use crate::workflow::DefaultProductWorkflow;
