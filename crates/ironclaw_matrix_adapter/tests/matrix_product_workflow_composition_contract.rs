use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

// Source-owner verification for Matrix ProductWorkflow composition:
// - ProductAdapter boundary: ironclaw_matrix_adapter::MatrixProductAdapter
//   implements ironclaw_product_adapters::ProductAdapter.
// - ProductWorkflow outbound composition: ironclaw_product_workflow owns
//   prepare_and_render_product_outbound, ProductOutboundTargetResolver, and
//   the ProductOutboundDeliveryOutcome contract.
// - Outbound target resolution and attempt/status metadata: ironclaw_outbound
//   owns OutboundPolicyService, ReplyTargetBindingValidator,
//   FilesystemOutboundStateStore over an in-memory backend, and
//   OutboundDeliveryStatus.
// - Matrix transport and terminal delivery evidence are intentionally not
//   modeled here; ProductRenderOutcome::Deferred is the required handoff shape.

use async_trait::async_trait;
use chrono::Utc;
use ironclaw_host_api::{AgentId, ProjectId, TenantId, ThreadId, UserId};
use ironclaw_matrix_adapter::installation_policy::{
    ArtifactSha256, ComponentArtifactBinding, ComponentArtifactId, EgressTargetIndex,
    InstallationAuditMetadata, MatrixActivationState, MatrixHomeserverOrigin,
    MatrixInstallationPolicy, MatrixProductAdapterInstallation, MatrixRoomId, MatrixUserId,
    PolicyRevision, StaticManifestBinding, WitPackageName, WitWorldName,
};
use ironclaw_matrix_adapter::{
    MatrixOutboundCommand, MatrixParsePolicy, MatrixProductAdapter, MatrixProductAdapterConfig,
};
use ironclaw_outbound::test_support::in_memory_backed_outbound_state_store;
use ironclaw_outbound::{
    CommunicationDeliveryIntent, CommunicationDeliveryResolutionRequest, CommunicationModality,
    CommunicationPreferenceKey, CommunicationPreferenceRecord, CommunicationPreferenceRepository,
    CommunicationPreferenceVersion, DeliveryDefaultScope, OutboundError, OutboundPolicyService,
    OutboundStateStore, ReplyTargetBindingClaim, ReplyTargetBindingValidator,
    RequestedOutboundContext, RequestedOutboundKind, ThreadProjectionAccessClaim,
    ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
    VersionedCommunicationPreferenceRecord, WriteCommunicationPreferenceRequest,
};
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, ExternalConversationRef, FakeOutboundDeliverySink,
    FakeProtocolHttpEgress, FinalReplyView, ProductAdapter, ProductAdapterError, ProductAdapterId,
    ProductInboundAck, ProductOutboundPayload, ProductRenderOutcome, ProjectionCursor,
    ProtocolAuthEvidence, ProtocolAuthFailure,
};
use ironclaw_product_workflow::{
    ConversationBindingService, DefaultInboundTurnService, DefaultProductWorkflow,
    InMemoryIdempotencyLedger, ProductOutboundDeliveryOutcome, ProductOutboundDeliveryRequest,
    ProductOutboundTargetResolver, ProductWorkflowError, ResolveBindingRequest, ResolvedBinding,
    VerifiedProductOutboundTargetMetadata, prepare_and_render_product_outbound,
};
use ironclaw_threads::InMemorySessionThreadService;
use ironclaw_turns::{
    CancelRunRequest, CancelRunResponse, EventCursor, GetRunStateRequest, ReplyTargetBindingRef,
    ResumeTurnRequest, ResumeTurnResponse, RetryTurnRequest, RetryTurnResponse, RunProfileId,
    RunProfileVersion, SubmitTurnRequest, SubmitTurnResponse, TurnActor, TurnCoordinator,
    TurnError, TurnId, TurnRunId, TurnRunState, TurnScope, TurnStatus,
};
use serde_json::json;

type StageTimeline = Arc<Mutex<Vec<&'static str>>>;

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

#[derive(Default)]
struct RecordingConversationBindingService {
    requests: Mutex<Vec<ResolveBindingRequest>>,
    timeline: StageTimeline,
}

impl RecordingConversationBindingService {
    fn requests(&self) -> Vec<ResolveBindingRequest> {
        self.requests.lock().expect("binding lock").clone()
    }
}

#[async_trait]
impl ConversationBindingService for RecordingConversationBindingService {
    async fn resolve_binding(
        &self,
        request: ResolveBindingRequest,
    ) -> Result<ResolvedBinding, ProductWorkflowError> {
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("workflow.resolve_binding");
        self.requests.lock().expect("binding lock").push(request);
        Ok(resolved_binding())
    }

    async fn lookup_binding(
        &self,
        request: ResolveBindingRequest,
    ) -> Result<ResolvedBinding, ProductWorkflowError> {
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("workflow.lookup_binding");
        self.requests.lock().expect("binding lock").push(request);
        Ok(resolved_binding())
    }
}

#[derive(Default)]
struct RecordingTurnCoordinator {
    submitted: Mutex<Vec<SubmitTurnRequest>>,
    timeline: StageTimeline,
}

impl RecordingTurnCoordinator {
    fn submitted(&self) -> Vec<SubmitTurnRequest> {
        self.submitted.lock().expect("turn lock").clone()
    }
}

#[async_trait]
impl TurnCoordinator for RecordingTurnCoordinator {
    async fn prepare_turn(&self, _scope: TurnScope) -> Result<TurnRunId, TurnError> {
        Ok(TurnRunId::new())
    }

    async fn submit_turn(
        &self,
        request: SubmitTurnRequest,
    ) -> Result<SubmitTurnResponse, TurnError> {
        self.timeline
            .lock()
            .expect("timeline lock")
            .push("turn.submit");
        self.submitted
            .lock()
            .expect("turn lock")
            .push(request.clone());
        Ok(SubmitTurnResponse::Accepted {
            turn_id: TurnId::new(),
            run_id: TurnRunId::new(),
            status: TurnStatus::Queued,
            resolved_run_profile_id: RunProfileId::default_profile(),
            resolved_run_profile_version: RunProfileVersion::new(1),
            event_cursor: EventCursor::default(),
            accepted_message_ref: request.accepted_message_ref,
            reply_target_binding_ref: request.reply_target_binding_ref,
        })
    }

    async fn resume_turn(
        &self,
        _request: ResumeTurnRequest,
    ) -> Result<ResumeTurnResponse, TurnError> {
        Err(TurnError::Unavailable {
            reason: "resume not used by Matrix composition contract".to_string(),
        })
    }

    async fn retry_turn(&self, _request: RetryTurnRequest) -> Result<RetryTurnResponse, TurnError> {
        Err(TurnError::Unavailable {
            reason: "retry not used by Matrix composition contract".to_string(),
        })
    }

    async fn cancel_run(&self, _request: CancelRunRequest) -> Result<CancelRunResponse, TurnError> {
        Err(TurnError::Unavailable {
            reason: "cancel not used by Matrix composition contract".to_string(),
        })
    }

    async fn get_run_state(&self, _request: GetRunStateRequest) -> Result<TurnRunState, TurnError> {
        Err(TurnError::Unavailable {
            reason: "get_run_state not used by Matrix composition contract".to_string(),
        })
    }
}

struct WorkflowFixture {
    workflow: DefaultProductWorkflow,
    binding_service: Arc<RecordingConversationBindingService>,
    turn_coordinator: Arc<RecordingTurnCoordinator>,
    timeline: StageTimeline,
}

fn workflow_fixture() -> WorkflowFixture {
    let timeline = StageTimeline::default();
    let binding_service = Arc::new(RecordingConversationBindingService {
        requests: Mutex::default(),
        timeline: timeline.clone(),
    });
    let turn_coordinator = Arc::new(RecordingTurnCoordinator {
        submitted: Mutex::default(),
        timeline: timeline.clone(),
    });
    let inbound_turn_service = Arc::new(DefaultInboundTurnService::new(
        binding_service.clone(),
        InMemorySessionThreadService::default(),
        turn_coordinator.clone(),
    ));
    WorkflowFixture {
        workflow: DefaultProductWorkflow::new(
            inbound_turn_service,
            Arc::new(InMemoryIdempotencyLedger::default()),
            binding_service.clone(),
        ),
        binding_service,
        turn_coordinator,
        timeline,
    }
}

#[tokio::test]
async fn matrix_final_reply_uses_shared_outbound_and_leaves_attempt_pending_for_bridge() {
    let scope = scope();
    let store = in_memory_backed_outbound_state_store();
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
    let stored_intent = adapter.pending_matrix_intent(attempt.delivery_id.as_uuid());
    let Some(MatrixOutboundCommand::SendMessage {
        ref room_id,
        ref txn_id,
        ref body,
    }) = stored_intent
    else {
        panic!(
            "ProductWorkflow must preserve exact Matrix send intent for the shared outbound bridge"
        );
    };
    assert_eq!(room_id, "!room:example.org");
    assert_eq!(
        txn_id.as_str(),
        format!("ironclaw-{}", attempt.delivery_id.as_uuid())
    );
    assert_eq!(body["msgtype"], "m.text");
    assert_eq!(body["body"], "hello Matrix through ProductWorkflow");
    assert_eq!(body["m.relates_to"]["rel_type"], "m.thread");
    assert_eq!(body["m.relates_to"]["event_id"], "$root:example.org");
    assert_eq!(
        body["m.relates_to"]["m.in_reply_to"]["event_id"],
        "$reply:example.org"
    );
    assert_eq!(
        adapter.pending_matrix_intent(attempt.delivery_id.as_uuid()),
        None,
        "shared outbound bridge must consume the Matrix intent exactly once"
    );
    let stored_intent_json = serde_json::to_string(&stored_intent).expect("intent json");
    assert!(!stored_intent_json.contains("credential"));
    assert!(!stored_intent_json.contains("token"));
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

#[tokio::test]
async fn matrix_verified_inbound_enters_product_workflow_idempotency_and_binding() {
    let adapter = matrix_adapter();
    let fixture = workflow_fixture();
    let auth_evidence =
        ProtocolAuthEvidence::test_verified(adapter.auth_requirement().clone(), "matrix-webhook");

    let ack = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &[matrix_installation(MatrixActivationState::Enabled)],
            matrix_homeserver(),
            raw_matrix_message().to_string().as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect("verified Matrix inbound should enter ProductWorkflow");

    assert!(
        matches!(ack, ProductInboundAck::Accepted { .. }),
        "Matrix adapter should return the ProductWorkflow acknowledgement"
    );
    let binding_requests = fixture.binding_service.requests();
    assert_eq!(binding_requests.len(), 1);
    let binding_request = &binding_requests[0];
    assert_eq!(binding_request.adapter_id, adapter.adapter_id().clone());
    assert_eq!(
        binding_request.installation_id,
        adapter.installation_id().clone()
    );
    assert_eq!(
        binding_request.external_event_id.as_str(),
        "matrix:inst_matrix:room:!room:example.org:event:$event:example.org"
    );
    assert_eq!(
        binding_request.external_conversation_ref.conversation_id(),
        "!room:example.org"
    );
    assert_eq!(
        binding_request.external_actor_ref.id(),
        "@alice:example.org"
    );
    assert_eq!(
        fixture.timeline.lock().expect("timeline lock").as_slice(),
        ["workflow.resolve_binding", "turn.submit"],
        "Matrix inbound must enter ProductWorkflow binding before turn submission"
    );
    let submitted = fixture.turn_coordinator.submitted();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].actor.user_id.as_str(), "user-matrix");
    assert_eq!(submitted[0].scope.thread_id.as_str(), "thread-matrix");
    assert!(
        submitted[0]
            .accepted_message_ref
            .as_str()
            .starts_with("msg:")
    );

    let duplicate_ack = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &[matrix_installation(MatrixActivationState::Enabled)],
            matrix_homeserver(),
            raw_matrix_message().to_string().as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect("duplicate Matrix inbound should replay ProductWorkflow outcome");
    assert!(
        matches!(duplicate_ack, ProductInboundAck::Duplicate { .. }),
        "ProductWorkflow should own duplicate detection for Matrix inbound"
    );
    assert_eq!(
        fixture.binding_service.requests().len(),
        1,
        "duplicate Matrix event must not resolve binding twice"
    );
    assert_eq!(
        fixture.turn_coordinator.submitted().len(),
        1,
        "duplicate Matrix event must not submit a second turn"
    );
    assert_eq!(
        fixture.timeline.lock().expect("timeline lock").as_slice(),
        ["workflow.resolve_binding", "turn.submit"],
        "duplicate Matrix event must replay idempotency before binding/turn side effects"
    );
}

#[tokio::test]
async fn matrix_inbound_same_event_id_in_different_room_does_not_collide() {
    let adapter = matrix_adapter();
    let fixture = workflow_fixture();
    let auth_evidence =
        ProtocolAuthEvidence::test_verified(adapter.auth_requirement().clone(), "matrix-webhook");
    let installations = [matrix_installation_with_rooms(
        MatrixActivationState::Enabled,
        &["!room:example.org", "!other:example.org"],
    )];

    let first_ack = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &installations,
            matrix_homeserver(),
            raw_matrix_message_in_room("!room:example.org")
                .to_string()
                .as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect("first Matrix event should be accepted");
    let second_ack = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &installations,
            matrix_homeserver(),
            raw_matrix_message_in_room("!other:example.org")
                .to_string()
                .as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect("same Matrix event id in another room should be accepted");

    assert!(matches!(first_ack, ProductInboundAck::Accepted { .. }));
    assert!(
        matches!(second_ack, ProductInboundAck::Accepted { .. }),
        "same Matrix event id in a different room must not replay as duplicate"
    );
    let binding_requests = fixture.binding_service.requests();
    assert_eq!(binding_requests.len(), 2);
    assert_eq!(
        binding_requests[0].external_event_id.as_str(),
        "matrix:inst_matrix:room:!room:example.org:event:$event:example.org"
    );
    assert_eq!(
        binding_requests[1].external_event_id.as_str(),
        "matrix:inst_matrix:room:!other:example.org:event:$event:example.org"
    );
    assert_eq!(fixture.turn_coordinator.submitted().len(), 2);
    assert_eq!(
        fixture.timeline.lock().expect("timeline lock").as_slice(),
        [
            "workflow.resolve_binding",
            "turn.submit",
            "workflow.resolve_binding",
            "turn.submit"
        ],
        "same event id in another room must run a separate binding/turn sequence"
    );
}

#[tokio::test]
async fn matrix_unverified_inbound_fails_before_product_workflow() {
    let adapter = matrix_adapter();
    let fixture = workflow_fixture();

    let error = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &[matrix_installation(MatrixActivationState::Enabled)],
            matrix_homeserver(),
            raw_matrix_message().to_string().as_bytes(),
            &ProtocolAuthEvidence::failed(ProtocolAuthFailure::Missing),
            Utc::now(),
        )
        .await
        .expect_err("unverified Matrix inbound should fail closed");

    assert!(matches!(
        error,
        ProductAdapterError::Authentication(ProtocolAuthFailure::Missing)
    ));
    assert!(
        fixture.binding_service.requests().is_empty(),
        "unverified Matrix inbound must not reach ProductWorkflow"
    );
    assert!(fixture.turn_coordinator.submitted().is_empty());
    assert!(fixture.timeline.lock().expect("timeline lock").is_empty());
}

#[tokio::test]
async fn matrix_disabled_installation_fails_before_product_workflow_and_guest_parse() {
    let adapter = matrix_adapter();
    let fixture = workflow_fixture();
    let auth_evidence =
        ProtocolAuthEvidence::test_verified(adapter.auth_requirement().clone(), "matrix-webhook");

    let error = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &[matrix_installation(MatrixActivationState::Disabled)],
            matrix_homeserver(),
            raw_unsupported_matrix_message("!room:example.org")
                .to_string()
                .as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect_err("disabled Matrix installation should fail before parse/workflow");

    assert!(
        matches!(
            error,
            ProductAdapterError::WorkflowRejected {
                kind: ironclaw_product_adapters::ProductWorkflowRejectionKind::Unauthorized,
                status_code: 403,
                retryable: false,
                ..
            }
        ),
        "disabled lifecycle rejection must win over unsupported guest parse"
    );
    assert!(
        fixture.binding_service.requests().is_empty(),
        "disabled Matrix installation must not reach ProductWorkflow"
    );
    assert!(fixture.turn_coordinator.submitted().is_empty());
    assert!(fixture.timeline.lock().expect("timeline lock").is_empty());
}

#[tokio::test]
async fn matrix_policy_denial_fails_before_product_workflow_and_guest_parse() {
    let adapter = matrix_adapter();
    let fixture = workflow_fixture();
    let auth_evidence =
        ProtocolAuthEvidence::test_verified(adapter.auth_requirement().clone(), "matrix-webhook");

    let error = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &[matrix_installation(MatrixActivationState::Enabled)],
            matrix_homeserver(),
            raw_unsupported_matrix_message("!other:example.org")
                .to_string()
                .as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect_err("policy-denied Matrix room should fail before parse/workflow");

    assert!(
        matches!(
            error,
            ProductAdapterError::WorkflowRejected {
                kind: ironclaw_product_adapters::ProductWorkflowRejectionKind::Unauthorized,
                status_code: 403,
                retryable: false,
                ..
            }
        ),
        "policy denial must win over unsupported guest parse"
    );
    assert!(
        fixture.binding_service.requests().is_empty(),
        "policy-denied Matrix event must not reach ProductWorkflow"
    );
    assert!(fixture.turn_coordinator.submitted().is_empty());
    assert!(fixture.timeline.lock().expect("timeline lock").is_empty());
}

#[tokio::test]
async fn matrix_overlong_routing_ids_fail_before_policy_parse_or_workflow() {
    let adapter = matrix_adapter();
    let fixture = workflow_fixture();
    let auth_evidence =
        ProtocolAuthEvidence::test_verified(adapter.auth_requirement().clone(), "matrix-webhook");
    let overlong_room = format!("!{}:example.org", "r".repeat(600));

    let error = adapter
        .submit_verified_inbound(
            &fixture.workflow,
            &[matrix_installation(MatrixActivationState::Enabled)],
            matrix_homeserver(),
            raw_unsupported_matrix_message(&overlong_room)
                .to_string()
                .as_bytes(),
            &auth_evidence,
            Utc::now(),
        )
        .await
        .expect_err("overlong Matrix routing ids should fail before policy/workflow");

    assert!(
        matches!(
            error,
            ProductAdapterError::WorkflowRejected {
                kind: ironclaw_product_adapters::ProductWorkflowRejectionKind::InvalidRequest,
                status_code: 400,
                retryable: false,
                ..
            }
        ),
        "overlong routing ids should be malformed input, not policy denial"
    );
    assert!(fixture.binding_service.requests().is_empty());
    assert!(fixture.turn_coordinator.submitted().is_empty());
    assert!(fixture.timeline.lock().expect("timeline lock").is_empty());
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

fn matrix_installation(activation: MatrixActivationState) -> MatrixProductAdapterInstallation {
    matrix_installation_with_rooms(activation, &["!room:example.org"])
}

fn matrix_installation_with_rooms(
    activation: MatrixActivationState,
    rooms: &[&str],
) -> MatrixProductAdapterInstallation {
    MatrixProductAdapterInstallation::new(
        ProductAdapterId::new("matrix").expect("valid adapter id"),
        AdapterInstallationId::new("inst_matrix").expect("valid installation id"),
        matrix_component_artifact(),
        matrix_installation_policy_with_rooms(rooms),
        activation,
        PolicyRevision::new(7).expect("valid policy revision"),
        InstallationAuditMetadata::new("matrix-admin", 1_710_000_000_001).expect("audit"),
    )
    .expect("valid Matrix installation")
}

fn matrix_installation_policy_with_rooms(rooms: &[&str]) -> MatrixInstallationPolicy {
    MatrixInstallationPolicy::new(
        matrix_homeserver(),
        rooms
            .iter()
            .map(|room| MatrixRoomId::new(*room).expect("room"))
            .collect(),
        BTreeSet::from([MatrixUserId::new("@alice:example.org").expect("sender")]),
        EgressTargetIndex::new(0),
        ironclaw_product_adapters::EgressCredentialHandle::new("matrix-access-token")
            .expect("credential handle"),
    )
    .expect("valid Matrix policy")
}

fn matrix_component_artifact() -> ComponentArtifactBinding {
    ComponentArtifactBinding {
        artifact_id: ComponentArtifactId::new("matrix-component").expect("artifact id"),
        artifact_sha256: ArtifactSha256::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("sha"),
        wit_package: WitPackageName::new("near:product-adapter@0.1.0").expect("wit package"),
        wit_world: WitWorldName::new("product-adapter-component").expect("wit world"),
        manifest: StaticManifestBinding::new("manifest-hash-alpha").expect("manifest"),
        declared_egress_targets: vec![ironclaw_product_adapters::DeclaredEgressTarget::new(
            ironclaw_product_adapters::DeclaredEgressHost::new("matrix.example.org")
                .expect("declared host"),
            Some(
                ironclaw_product_adapters::EgressCredentialHandle::new("matrix-access-token")
                    .expect("credential handle"),
            ),
        )],
    }
}

fn matrix_homeserver() -> MatrixHomeserverOrigin {
    MatrixHomeserverOrigin::parse("https://matrix.example.org").expect("homeserver")
}

fn raw_matrix_message() -> serde_json::Value {
    raw_matrix_message_in_room("!room:example.org")
}

fn raw_matrix_message_in_room(room_id: &str) -> serde_json::Value {
    json!({
        "type": "m.room.message",
        "event_id": "$event:example.org",
        "room_id": room_id,
        "sender": "@alice:example.org",
        "content": {
            "msgtype": "m.text",
            "body": "hello Matrix through ProductWorkflow"
        }
    })
}

fn raw_unsupported_matrix_message(room_id: &str) -> serde_json::Value {
    json!({
        "type": "m.unsupported",
        "event_id": "$event:example.org",
        "room_id": room_id,
        "sender": "@alice:example.org",
        "content": {}
    })
}

fn resolved_binding() -> ResolvedBinding {
    ResolvedBinding {
        tenant_id: TenantId::new("tenant-matrix").expect("valid tenant"),
        actor_user_id: UserId::new("user-matrix").expect("valid user"),
        subject_user_id: Some(UserId::new("user-matrix").expect("valid user")),
        thread_id: ThreadId::new("thread-matrix").expect("valid thread"),
        agent_id: Some(AgentId::new("agent-matrix").expect("valid agent")),
        project_id: Some(ProjectId::new("project-matrix").expect("valid project")),
    }
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
