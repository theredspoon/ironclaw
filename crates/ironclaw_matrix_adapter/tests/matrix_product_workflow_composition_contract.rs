use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

// Source-owner verification for ICWM-R002D Group 0:
// - ProductAdapter boundary: ironclaw_matrix_adapter::MatrixProductAdapter
//   implements ironclaw_product_adapters::ProductAdapter.
// - ProductWorkflow outbound composition: ironclaw_product_workflow owns
//   prepare_and_render_product_outbound, ProductOutboundTargetResolver, and
//   the ProductOutboundDeliveryOutcome contract.
// - Outbound target resolution and attempt/status metadata: ironclaw_outbound
//   owns OutboundPolicyService, ReplyTargetBindingValidator,
//   InMemoryOutboundStateStore, and OutboundDeliveryStatus.
// - Matrix transport and R003A terminal delivery evidence are intentionally not
//   modeled here; ProductRenderOutcome::Deferred is the required handoff shape.

use async_trait::async_trait;
use chrono::Utc;
use ironclaw_host_api::{AgentId, ProjectId, TenantId, ThreadId, UserId};
use ironclaw_matrix_adapter::{
    MatrixParsePolicy, MatrixProductAdapter, MatrixProductAdapterConfig,
};
use ironclaw_outbound::{
    CommunicationDeliveryIntent, CommunicationDeliveryResolutionRequest, CommunicationModality,
    CommunicationPreferenceKey, CommunicationPreferenceRecord, CommunicationPreferenceRepository,
    CommunicationPreferenceVersion, DeliveryDefaultScope, InMemoryOutboundStateStore,
    OutboundError, OutboundPolicyService, OutboundStateStore, ReplyTargetBindingClaim,
    ReplyTargetBindingValidator, RequestedOutboundContext, RequestedOutboundKind,
    ThreadProjectionAccessClaim, ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
    VersionedCommunicationPreferenceRecord, WriteCommunicationPreferenceRequest,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, ExternalConversationRef, FakeOutboundDeliverySink,
    FakeProtocolHttpEgress, FinalReplyView, ProductAdapterId, ProductOutboundPayload,
    ProductRenderOutcome, ProjectionCursor,
};
use ironclaw_product_workflow::{
    ProductOutboundDeliveryOutcome, ProductOutboundDeliveryRequest, ProductOutboundTargetResolver,
    ProductWorkflowError, VerifiedProductOutboundTargetMetadata,
    prepare_and_render_product_outbound,
};
use ironclaw_turns::{ReplyTargetBindingRef, TurnActor, TurnRunId, TurnScope};

#[derive(Default)]
struct AllowAllProjectionAccessPolicy;

#[async_trait]
impl ThreadProjectionAccessPolicy for AllowAllProjectionAccessPolicy {
    async fn authorize_projection_access(
        &self,
        request: ThreadProjectionAccessRequest,
    ) -> Result<ThreadProjectionAccessClaim, OutboundError> {
        Ok(ThreadProjectionAccessClaim {
            actor: request.actor,
            scope: request.scope,
            thread_id: request.thread_id,
        })
    }
}

#[derive(Default)]
struct RecordingReplyTargetBindingValidator {
    allowed_targets: Mutex<HashSet<ReplyTargetBindingRef>>,
    calls: Mutex<Vec<ReplyTargetBindingRef>>,
}

impl RecordingReplyTargetBindingValidator {
    fn allow(&self, target: ReplyTargetBindingRef) {
        self.allowed_targets
            .lock()
            .expect("validator lock")
            .insert(target);
    }

    fn calls(&self) -> Vec<ReplyTargetBindingRef> {
        self.calls.lock().expect("validator lock").clone()
    }
}

#[async_trait]
impl ReplyTargetBindingValidator for RecordingReplyTargetBindingValidator {
    async fn validate_reply_target(
        &self,
        request: ironclaw_outbound::ReplyTargetValidationRequest,
    ) -> Result<ReplyTargetBindingClaim, OutboundError> {
        self.calls
            .lock()
            .expect("validator lock")
            .push(request.candidate.target.clone());
        if self
            .allowed_targets
            .lock()
            .expect("validator lock")
            .contains(&request.candidate.target)
        {
            Ok(ReplyTargetBindingClaim::new(request.candidate.target))
        } else {
            Err(OutboundError::AccessDenied)
        }
    }
}

#[derive(Default)]
struct RecordingPreferenceRepository {
    records: Mutex<HashMap<CommunicationPreferenceKey, VersionedCommunicationPreferenceRecord>>,
    load_calls: Mutex<usize>,
}

impl RecordingPreferenceRepository {
    fn seed(&self, record: CommunicationPreferenceRecord) {
        self.records.lock().expect("preference lock").insert(
            record.key(),
            VersionedCommunicationPreferenceRecord {
                record,
                version: CommunicationPreferenceVersion::from_raw(1),
            },
        );
    }

    fn load_calls(&self) -> usize {
        *self.load_calls.lock().expect("preference lock")
    }
}

#[async_trait]
impl CommunicationPreferenceRepository for RecordingPreferenceRepository {
    async fn put_communication_preference(
        &self,
        record: CommunicationPreferenceRecord,
    ) -> Result<(), OutboundError> {
        self.seed(record);
        Ok(())
    }

    async fn load_communication_preference(
        &self,
        key: CommunicationPreferenceKey,
    ) -> Result<Option<VersionedCommunicationPreferenceRecord>, OutboundError> {
        *self.load_calls.lock().expect("preference lock") += 1;
        Ok(self
            .records
            .lock()
            .expect("preference lock")
            .get(&key)
            .cloned())
    }

    async fn write_communication_preference(
        &self,
        request: WriteCommunicationPreferenceRequest,
    ) -> Result<VersionedCommunicationPreferenceRecord, OutboundError> {
        let record = VersionedCommunicationPreferenceRecord {
            record: request.record,
            version: CommunicationPreferenceVersion::from_raw(1),
        };
        self.records
            .lock()
            .expect("preference lock")
            .insert(record.record.key(), record.clone());
        Ok(record)
    }
}

#[derive(Default)]
struct RecordingProductOutboundTargetResolver {
    calls: Mutex<Vec<ReplyTargetBindingRef>>,
}

impl RecordingProductOutboundTargetResolver {
    fn calls(&self) -> Vec<ReplyTargetBindingRef> {
        self.calls.lock().expect("target resolver lock").clone()
    }
}

#[async_trait]
impl ProductOutboundTargetResolver for RecordingProductOutboundTargetResolver {
    async fn resolve_product_outbound_target_metadata(
        &self,
        target: &ironclaw_outbound::ValidatedReplyTargetBinding,
        _require_direct_message: bool,
    ) -> Result<VerifiedProductOutboundTargetMetadata, ProductWorkflowError> {
        self.calls
            .lock()
            .expect("target resolver lock")
            .push(target.target().clone());
        Ok(VerifiedProductOutboundTargetMetadata {
            external_conversation_ref: ExternalConversationRef::new(
                None,
                "!room:example.org",
                Some("$root:example.org"),
                Some("$reply:example.org"),
            )
            .expect("valid Matrix conversation ref"),
            external_actor_ref: None,
        })
    }
}

#[tokio::test]
async fn matrix_final_reply_uses_shared_outbound_and_leaves_attempt_pending_for_r003a() {
    let scope = scope();
    let store = InMemoryOutboundStateStore::default();
    let validator = RecordingReplyTargetBindingValidator::default();
    validator.allow(reply_target());
    let preferences = RecordingPreferenceRepository::default();
    preferences.seed(preference_record(&scope));
    let resolver = RecordingProductOutboundTargetResolver::default();
    let access_policy = AllowAllProjectionAccessPolicy;
    let outbound_policy = OutboundPolicyService::new(&store, &access_policy, &validator);
    let adapter = matrix_adapter();
    let egress = FakeProtocolHttpEgress::new(Vec::<String>::new());
    let delivery_sink = FakeOutboundDeliverySink::new();

    let outcome = prepare_and_render_product_outbound(
        &outbound_policy,
        &preferences,
        &resolver,
        ProductOutboundDeliveryRequest {
            delivery: requested_matrix_delivery(scope.clone()),
            payload: matrix_final_reply_payload(),
            projection_cursor: ProjectionCursor::new("cursor:matrix:final-reply")
                .expect("valid projection cursor"),
            adapter: &adapter,
            egress: &egress,
            delivery_sink: &delivery_sink,
            require_direct_message_target: false,
        },
    )
    .await
    .expect("Matrix composition should render through shared ProductWorkflow outbound");

    let ProductOutboundDeliveryOutcome::Rendered {
        attempt,
        render_outcome,
    } = outcome
    else {
        panic!("expected Matrix outbound to reach shared render path");
    };
    assert!(
        matches!(render_outcome, ProductRenderOutcome::Deferred),
        "Matrix command JSON or SynchronousResponse is not delivery evidence"
    );
    assert_eq!(validator.calls(), vec![reply_target()]);
    assert_eq!(preferences.load_calls(), 0);
    assert_eq!(resolver.calls(), vec![reply_target()]);
    assert!(egress.calls().is_empty());
    assert!(delivery_sink.statuses().is_empty());

    let attempts = store
        .list_delivery_attempts(scope)
        .await
        .expect("list attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].delivery_id, attempt.delivery_id);
    assert_eq!(
        attempts[0].status,
        ironclaw_outbound::OutboundDeliveryStatus::Pending
    );
}

fn matrix_adapter() -> MatrixProductAdapter {
    MatrixProductAdapter::new(MatrixProductAdapterConfig {
        adapter_id: ProductAdapterId::new("matrix").expect("valid adapter id"),
        installation_id: AdapterInstallationId::new("inst_matrix").expect("valid installation id"),
        parse_policy: MatrixParsePolicy {
            allowed_rooms: vec!["!room:example.org".to_string()],
            allowed_senders: vec!["@alice:example.org".to_string()],
        },
        auth_requirement: AuthRequirement::SharedSecretHeader {
            header_name: "x-matrix-webhook-secret".to_string(),
        },
    })
    .expect("explicit Matrix policy")
}

fn scope() -> TurnScope {
    TurnScope::new_with_owner(
        TenantId::new("tenant-matrix").expect("valid tenant"),
        Some(AgentId::new("agent-matrix").expect("valid agent")),
        Some(ProjectId::new("project-matrix").expect("valid project")),
        ThreadId::new("thread-matrix").expect("valid thread"),
        Some(UserId::new("user-matrix").expect("valid user")),
    )
}

fn actor() -> TurnActor {
    TurnActor::new(UserId::new("user-matrix").expect("valid user"))
}

fn reply_target() -> ReplyTargetBindingRef {
    ReplyTargetBindingRef::new("matrix:!room:example.org").expect("valid reply target")
}

fn requested_matrix_delivery(
    scope: TurnScope,
) -> ironclaw_outbound::PrepareCommunicationDeliveryRequest {
    ironclaw_outbound::PrepareCommunicationDeliveryRequest {
        resolution_request: CommunicationDeliveryResolutionRequest {
            scope,
            actor: actor(),
            modality: CommunicationModality::Text,
            intent: CommunicationDeliveryIntent::RequestedOutbound(RequestedOutboundContext {
                requested_target: reply_target(),
                requested_kind: RequestedOutboundKind::ProductMessage,
            }),
        },
        turn_run_id: Some(TurnRunId::new()),
        projection_ref: ironclaw_outbound::ProjectionUpdateRef::new("projection:matrix:final")
            .expect("valid projection ref"),
        attempted_at: Utc::now(),
    }
}

fn preference_record(scope: &TurnScope) -> CommunicationPreferenceRecord {
    CommunicationPreferenceRecord {
        scope: DeliveryDefaultScope::personal(scope.tenant_id.clone(), actor().user_id.clone()),
        final_reply_target: Some(reply_target()),
        progress_target: None,
        approval_prompt_target: None,
        auth_prompt_target: None,
        default_modality: Some(CommunicationModality::Text),
        updated_at: Utc::now(),
        updated_by: UserId::new("pref-updater").expect("valid updater"),
    }
}

fn matrix_final_reply_payload() -> ProductOutboundPayload {
    ProductOutboundPayload::FinalReply(FinalReplyView {
        turn_run_id: TurnRunId::new(),
        text: "hello Matrix through ProductWorkflow".to_string(),
        generated_at: Utc::now(),
    })
}
