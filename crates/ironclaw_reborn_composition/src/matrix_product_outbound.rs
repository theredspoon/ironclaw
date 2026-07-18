use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ironclaw_extensions::ExtensionInstallationStore;
use ironclaw_filesystem::{RootFilesystem, ScopedFilesystem};
use ironclaw_host_api::{ResourceScope, ScopedPath};
use ironclaw_matrix_adapter::installation_policy::{
    MatrixActivationState, MatrixInstallationPolicyRejection, MatrixInstallationProjectionCache,
    MatrixOutboundPolicyCheck, MatrixPolicySnapshot, MatrixRoomId, authorize_matrix_outbound,
    ensure_matrix_extension_lifecycle_enabled,
};
use ironclaw_product_adapters::redaction::RedactedString;
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressTarget, OutboundDeliverySink,
    ParsedProductInbound, ProductAdapter, ProductAdapterCapabilities, ProductAdapterError,
    ProductAdapterHealth, ProductAdapterId, ProductOutboundEnvelope, ProductOutboundPayload,
    ProductRenderOutcome, ProductSurfaceKind, ProductWorkflowRejectionKind, ProtocolAuthEvidence,
    ProtocolHttpEgress,
};
use ironclaw_product_workflow::{
    ProductOutboundDeliveryError, ProductOutboundDeliveryOutcome, ProductOutboundDeliveryRequest,
    ProductOutboundStatusUpdateFailure, ProductOutboundTargetResolver,
    ProductWorkflowError as ProductOutboundWorkflowError, prepare_and_render_product_outbound,
};

pub const MATRIX_POLICY_PROJECTION_CACHE_PATH: &str =
    "/outbound/matrix/policy/installation-projection-cache.json";

pub trait MatrixOutboundPolicyAuthorizer: Send + Sync {
    fn authorize_matrix_outbound(
        &self,
        snapshot: &MatrixPolicySnapshot,
        check: &MatrixOutboundPolicyCheck,
    ) -> Result<(), MatrixInstallationPolicyRejection>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultMatrixOutboundPolicyAuthorizer;

impl MatrixOutboundPolicyAuthorizer for DefaultMatrixOutboundPolicyAuthorizer {
    /// Validates a source-verified R002C policy snapshot. Production callers must
    /// pass a current snapshot from the policy owner; this type does not rehydrate
    /// policy state on its own.
    fn authorize_matrix_outbound(
        &self,
        snapshot: &MatrixPolicySnapshot,
        check: &MatrixOutboundPolicyCheck,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        authorize_matrix_outbound(snapshot, check)
    }
}

#[async_trait]
pub trait MatrixPolicySnapshotSource: Send + Sync {
    async fn resolve_matrix_policy_snapshot(
        &self,
        adapter_id: &ProductAdapterId,
        installation_id: &AdapterInstallationId,
    ) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection>;
}

#[derive(Clone)]
pub struct FilesystemMatrixPolicySnapshotSource<F: ?Sized> {
    filesystem: Arc<ScopedFilesystem<F>>,
    scope: ResourceScope,
    cache_path: ScopedPath,
}

impl<F> FilesystemMatrixPolicySnapshotSource<F>
where
    F: RootFilesystem + ?Sized,
{
    pub fn new(
        filesystem: Arc<ScopedFilesystem<F>>,
        scope: ResourceScope,
        cache_path: ScopedPath,
    ) -> Self {
        Self {
            filesystem,
            scope,
            cache_path,
        }
    }
}

#[async_trait]
impl<F> MatrixPolicySnapshotSource for FilesystemMatrixPolicySnapshotSource<F>
where
    F: RootFilesystem + Send + Sync + ?Sized,
{
    async fn resolve_matrix_policy_snapshot(
        &self,
        adapter_id: &ProductAdapterId,
        installation_id: &AdapterInstallationId,
    ) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection> {
        let entry = self
            .filesystem
            .get(&self.scope, &self.cache_path)
            .await
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        let cache = MatrixInstallationProjectionCache::from_json_bytes(&entry.entry.body)
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
        let installation = cache
            .installation(installation_id)
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        if &installation.adapter_id != adapter_id {
            return Err(MatrixInstallationPolicyRejection::AdapterMismatch);
        }
        match installation.activation {
            MatrixActivationState::Enabled => {}
            MatrixActivationState::Disabled => {
                return Err(MatrixInstallationPolicyRejection::InstallationDisabled);
            }
            MatrixActivationState::Deleting => {
                return Err(MatrixInstallationPolicyRejection::InstallationDeleting);
            }
        }
        Ok(MatrixPolicySnapshot {
            adapter_id: installation.adapter_id.clone(),
            installation_id: installation.installation_id.clone(),
            homeserver: installation.policy.homeserver.clone(),
            allowed_rooms: installation.policy.allowed_rooms.clone(),
            allowed_senders: installation.policy.allowed_senders.clone(),
            egress_target_index: installation.policy.egress_target_index,
            credential_handle: installation.policy.credential_handle.clone(),
            policy_revision: installation.policy_revision,
        })
    }
}

pub struct MatrixProductOutboundEntrypoint<'a> {
    pub extension_installation_store: &'a dyn ExtensionInstallationStore,
    pub snapshot_source: &'a dyn MatrixPolicySnapshotSource,
    pub policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    pub outbound_policy: &'a ironclaw_outbound::OutboundPolicyService<'a>,
    pub communication_preferences: &'a dyn ironclaw_outbound::CommunicationPreferenceRepository,
    pub target_resolver: &'a dyn ProductOutboundTargetResolver,
    pub adapter: &'a dyn ProductAdapter,
    pub egress: &'a dyn ProtocolHttpEgress,
    pub delivery_sink: &'a dyn OutboundDeliverySink,
}

pub struct MatrixProductOutboundDeliveryInput {
    pub delivery: ironclaw_outbound::PrepareCommunicationDeliveryRequest,
    pub payload: ProductOutboundPayload,
    pub projection_cursor: ironclaw_product_adapters::ProjectionCursor,
    pub require_direct_message_target: bool,
}

impl MatrixProductOutboundEntrypoint<'_> {
    pub async fn prepare_and_render(
        &self,
        input: MatrixProductOutboundDeliveryInput,
    ) -> Result<ProductOutboundDeliveryOutcome, MatrixProductOutboundDeliveryError> {
        prepare_and_render_matrix_product_outbound(MatrixProductOutboundDeliveryRequest {
            extension_installation_store: self.extension_installation_store,
            snapshot_source: self.snapshot_source,
            resolved_snapshot: None,
            policy_authorizer: self.policy_authorizer,
            outbound_policy: self.outbound_policy,
            communication_preferences: self.communication_preferences,
            target_resolver: self.target_resolver,
            delivery: input.delivery,
            payload: input.payload,
            projection_cursor: input.projection_cursor,
            adapter: self.adapter,
            egress: self.egress,
            delivery_sink: self.delivery_sink,
            require_direct_message_target: input.require_direct_message_target,
        })
        .await
    }

    pub async fn prepare_and_render_with_snapshot(
        &self,
        input: MatrixProductOutboundDeliveryInput,
        snapshot: MatrixPolicySnapshot,
    ) -> Result<ProductOutboundDeliveryOutcome, MatrixProductOutboundDeliveryError> {
        prepare_and_render_matrix_product_outbound(MatrixProductOutboundDeliveryRequest {
            extension_installation_store: self.extension_installation_store,
            snapshot_source: self.snapshot_source,
            resolved_snapshot: Some(snapshot),
            policy_authorizer: self.policy_authorizer,
            outbound_policy: self.outbound_policy,
            communication_preferences: self.communication_preferences,
            target_resolver: self.target_resolver,
            delivery: input.delivery,
            payload: input.payload,
            projection_cursor: input.projection_cursor,
            adapter: self.adapter,
            egress: self.egress,
            delivery_sink: self.delivery_sink,
            require_direct_message_target: input.require_direct_message_target,
        })
        .await
    }
}

struct MatrixProductOutboundDeliveryRequest<'a> {
    extension_installation_store: &'a dyn ExtensionInstallationStore,
    snapshot_source: &'a dyn MatrixPolicySnapshotSource,
    resolved_snapshot: Option<MatrixPolicySnapshot>,
    policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    outbound_policy: &'a ironclaw_outbound::OutboundPolicyService<'a>,
    communication_preferences: &'a dyn ironclaw_outbound::CommunicationPreferenceRepository,
    target_resolver: &'a dyn ProductOutboundTargetResolver,
    delivery: ironclaw_outbound::PrepareCommunicationDeliveryRequest,
    payload: ProductOutboundPayload,
    projection_cursor: ironclaw_product_adapters::ProjectionCursor,
    adapter: &'a dyn ProductAdapter,
    egress: &'a dyn ProtocolHttpEgress,
    delivery_sink: &'a dyn OutboundDeliverySink,
    require_direct_message_target: bool,
}

#[derive(Debug)]
pub enum MatrixProductOutboundDeliveryError {
    Unavailable {
        reason: String,
    },
    Lifecycle(MatrixInstallationPolicyRejection),
    TargetResolution {
        source: ProductOutboundWorkflowError,
        status_update_error: Option<ProductOutboundStatusUpdateFailure>,
    },
    Policy {
        rejection: MatrixInstallationPolicyRejection,
        status_update_error: Option<ProductOutboundStatusUpdateFailure>,
    },
    Delivery(ProductOutboundDeliveryError),
}

async fn prepare_and_render_matrix_product_outbound(
    request: MatrixProductOutboundDeliveryRequest<'_>,
) -> Result<ProductOutboundDeliveryOutcome, MatrixProductOutboundDeliveryError> {
    let snapshot = match request.resolved_snapshot {
        Some(snapshot) => snapshot,
        None => request
            .snapshot_source
            .resolve_matrix_policy_snapshot(
                request.adapter.adapter_id(),
                request.adapter.installation_id(),
            )
            .await
            .map_err(|rejection| {
                record_matrix_product_outbound_policy_failure("snapshot", &rejection);
                MatrixProductOutboundDeliveryError::Policy {
                    rejection,
                    status_update_error: None,
                }
            })?,
    };

    ensure_matrix_extension_lifecycle_enabled(
        request.extension_installation_store,
        &snapshot.installation_id,
    )
    .await
    .map_err(|rejection| {
        record_matrix_product_outbound_policy_failure("lifecycle", &rejection);
        MatrixProductOutboundDeliveryError::Lifecycle(rejection)
    })?;

    let policy_failure = Arc::new(Mutex::new(None));
    let gated_adapter = MatrixPolicyGatedProductAdapter {
        inner: request.adapter,
        snapshot,
        policy_authorizer: request.policy_authorizer,
        policy_failure: Arc::clone(&policy_failure),
    };

    let outcome = prepare_and_render_product_outbound(
        request.outbound_policy,
        request.communication_preferences,
        request.target_resolver,
        ProductOutboundDeliveryRequest {
            delivery: request.delivery,
            payload: request.payload,
            projection_cursor: request.projection_cursor,
            adapter: &gated_adapter,
            egress: request.egress,
            delivery_sink: request.delivery_sink,
            require_direct_message_target: request.require_direct_message_target,
        },
    )
    .await
    .map_err(|error| map_matrix_product_outbound_delivery_error(error, &policy_failure))?;
    Ok(outcome)
}

fn map_matrix_product_outbound_delivery_error(
    error: ProductOutboundDeliveryError,
    policy_failure: &Arc<Mutex<Option<MatrixInstallationPolicyRejection>>>,
) -> MatrixProductOutboundDeliveryError {
    match error {
        ProductOutboundDeliveryError::Workflow {
            source,
            status_update_error,
        } => {
            record_matrix_product_outbound_workflow_failure("target_resolution", &source);
            MatrixProductOutboundDeliveryError::TargetResolution {
                source,
                status_update_error,
            }
        }
        ProductOutboundDeliveryError::Adapter {
            source,
            status_update_error,
        } => {
            if let Some(rejection) = policy_failure
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                record_matrix_product_outbound_policy_failure("policy", &rejection);
                MatrixProductOutboundDeliveryError::Policy {
                    rejection,
                    status_update_error,
                }
            } else {
                MatrixProductOutboundDeliveryError::Delivery(
                    ProductOutboundDeliveryError::Adapter {
                        source,
                        status_update_error,
                    },
                )
            }
        }
        other => MatrixProductOutboundDeliveryError::Delivery(other),
    }
}

struct MatrixPolicyGatedProductAdapter<'a> {
    inner: &'a dyn ProductAdapter,
    snapshot: MatrixPolicySnapshot,
    policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    policy_failure: Arc<Mutex<Option<MatrixInstallationPolicyRejection>>>,
}

#[async_trait]
impl ProductAdapter for MatrixPolicyGatedProductAdapter<'_> {
    fn adapter_id(&self) -> &ProductAdapterId {
        self.inner.adapter_id()
    }

    fn installation_id(&self) -> &AdapterInstallationId {
        self.inner.installation_id()
    }

    fn surface_kind(&self) -> ProductSurfaceKind {
        self.inner.surface_kind()
    }

    fn capabilities(&self) -> &ProductAdapterCapabilities {
        self.inner.capabilities()
    }

    fn auth_requirement(&self) -> &AuthRequirement {
        self.inner.auth_requirement()
    }

    fn declared_egress(&self) -> &[DeclaredEgressTarget] {
        self.inner.declared_egress()
    }

    fn parse_inbound(
        &self,
        raw_payload: &[u8],
        auth_evidence: &ProtocolAuthEvidence,
    ) -> Result<ParsedProductInbound, ProductAdapterError> {
        self.inner.parse_inbound(raw_payload, auth_evidence)
    }

    async fn render_outbound(
        &self,
        envelope: ProductOutboundEnvelope,
        egress: &dyn ProtocolHttpEgress,
        delivery_sink: &dyn OutboundDeliverySink,
    ) -> Result<ProductRenderOutcome, ProductAdapterError> {
        let check = match matrix_outbound_policy_check_from_envelope(&self.snapshot, &envelope) {
            Ok(check) => check,
            Err(error) => {
                *self
                    .policy_failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                return Err(map_matrix_policy_rejection_to_adapter_error(error));
            }
        };
        if let Err(rejection) = self
            .policy_authorizer
            .authorize_matrix_outbound(&self.snapshot, &check)
        {
            *self
                .policy_failure
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(rejection);
            return Err(map_matrix_policy_rejection_to_adapter_error(rejection));
        }
        self.inner
            .render_outbound(envelope, egress, delivery_sink)
            .await
    }

    fn health(&self) -> ProductAdapterHealth {
        self.inner.health()
    }
}

fn matrix_outbound_policy_check_from_envelope(
    snapshot: &MatrixPolicySnapshot,
    envelope: &ProductOutboundEnvelope,
) -> Result<MatrixOutboundPolicyCheck, MatrixInstallationPolicyRejection> {
    let room_id = MatrixRoomId::new(
        envelope
            .target
            .external_conversation_ref
            .conversation_id()
            .to_string(),
    )?;
    let transaction_id = format!("ironclaw-{}", envelope.delivery_attempt_id);
    let path = crate::matrix_outbound::matrix_send_policy_path(room_id.as_str(), &transaction_id);
    Ok(MatrixOutboundPolicyCheck {
        adapter_id: envelope.adapter_id.clone(),
        installation_id: envelope.installation_id.clone(),
        homeserver: snapshot.homeserver.clone(),
        room_id,
        egress_target_index: snapshot.egress_target_index,
        credential_handle: snapshot.credential_handle.clone(),
        path,
        guest_authorization_header_present: false,
        policy_revision: snapshot.policy_revision,
    })
}

fn map_matrix_policy_rejection_to_adapter_error(
    rejection: MatrixInstallationPolicyRejection,
) -> ProductAdapterError {
    let (kind, status_code) = match rejection {
        MatrixInstallationPolicyRejection::InstallationDisabled
        | MatrixInstallationPolicyRejection::InstallationDeleting
        | MatrixInstallationPolicyRejection::InstallationNotFound
        | MatrixInstallationPolicyRejection::AdapterMismatch
        | MatrixInstallationPolicyRejection::InstallationMismatch
        | MatrixInstallationPolicyRejection::RoomNotAllowed
        | MatrixInstallationPolicyRejection::SenderNotAllowed
        | MatrixInstallationPolicyRejection::HomeserverMismatch
        | MatrixInstallationPolicyRejection::CredentialHandleMismatch
        | MatrixInstallationPolicyRejection::GuestCredentialMaterialRejected
        | MatrixInstallationPolicyRejection::PolicyRevisionMismatch => {
            (ProductWorkflowRejectionKind::Unauthorized, 403)
        }
        _ => (ProductWorkflowRejectionKind::InvalidRequest, 400),
    };
    ProductAdapterError::WorkflowRejected {
        kind,
        status_code,
        retryable: false,
        reason: RedactedString::new(format!("matrix outbound policy rejected: {rejection:?}")),
    }
}

fn record_matrix_product_outbound_policy_failure(
    stage: &'static str,
    rejection: &MatrixInstallationPolicyRejection,
) {
    tracing::debug!(
        target = "ironclaw::reborn::matrix_product_outbound",
        stage,
        reason_code = ?rejection,
        "matrix product outbound policy gate failed"
    );
}

fn record_matrix_product_outbound_workflow_failure(
    stage: &'static str,
    source: &ProductOutboundWorkflowError,
) {
    tracing::debug!(
        target = "ironclaw::reborn::matrix_product_outbound",
        stage,
        reason = %source,
        "matrix product outbound shared workflow stage failed"
    );
}
