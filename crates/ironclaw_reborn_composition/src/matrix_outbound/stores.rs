use super::*;
use ironclaw_host_api::{AgentId, ProjectId, TenantId};

#[async_trait]
pub trait MatrixOutboundMetadataStore: Send + Sync {
    async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError>;

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError>;

    async fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        evidence: ValidatedMatrixDeliveryEvidence,
    ) -> Result<(), MatrixOutboundContractError>;

    async fn record_retry_scheduled(
        &self,
        schedule: MatrixRetrySchedule,
        context: MatrixRetryExecutionContext,
    ) -> Result<(), MatrixOutboundContractError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRetrySchedule {
    pub delivery_id: OutboundDeliveryId,
    pub scope: TurnScope,
    pub attempt_number: u32,
    pub retry_after: Duration,
    pub reason: DeliveryReasonCode,
    pub recorded_at: DateTime<Utc>,
}

const MATRIX_METADATA_SCHEMA_VERSION: u32 = 1;
pub(crate) const MATRIX_PENDING_INTENT_SCHEMA_VERSION: u32 = 1;
pub(crate) const MATRIX_RETRY_CLAIM_LEASE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredMatrixOutboundMetadataV1 {
    schema_version: u32,
    delivery_id: OutboundDeliveryId,
    scope: TurnScope,
    evidence: Option<MatrixDeliveryEvidenceV1>,
    status: Option<StoredMatrixDeliveryStatusV1>,
    retry_schedule: Option<StoredMatrixRetryScheduleV1>,
    #[serde(default)]
    retry_execution_context: Option<StoredMatrixRetryExecutionContextV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixDeliveryStatusV1 {
    status: OutboundDeliveryStatus,
    updated_at: DateTime<Utc>,
    failure_kind: Option<DeliveryFailureKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRetryScheduleV1 {
    attempt_number: u32,
    retry_after_millis: u64,
    reason: DeliveryReasonCode,
    recorded_at: DateTime<Utc>,
    #[serde(default)]
    claim_started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    claim_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRetryExecutionContextV1 {
    route: StoredFrozenProductDeliveryRouteV1,
    grant: StoredSealedDeliveryGrantV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRetryScopeIndexEntryV1 {
    schema_version: u32,
    scope: TurnScope,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredFrozenProductDeliveryRouteV1 {
    delivery_id: OutboundDeliveryId,
    scope: TurnScope,
    installation_id: String,
    adapter_id: String,
    metadata: StoredMatrixRouteMetadataV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixRouteMetadataV1 {
    policy_revision: String,
    homeserver_origin_fingerprint: String,
    room_fingerprint: String,
    egress_target_index: u32,
    credential_handle_fingerprint: String,
    reply_target_binding_ref: ReplyTargetBindingRef,
    allowed_command_kinds: Vec<MatrixCommandKind>,
    #[serde(default)]
    policy_provider_scope: Option<StoredMatrixPolicyProviderScopeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMatrixPolicyProviderScopeV1 {
    tenant_id: TenantId,
    agent_id: AgentId,
    project_id: Option<ProjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSealedDeliveryGrantV1 {
    delivery_id: OutboundDeliveryId,
    installation_id: String,
    adapter_id: String,
    policy_revision: String,
    homeserver_origin_fingerprint: String,
    room_fingerprint: String,
    egress_target_index: u32,
    credential_handle_fingerprint: String,
    allowed_command_kinds: Vec<MatrixCommandKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredMatrixPendingIntentV1 {
    pub(crate) schema_version: u32,
    pub(crate) delivery_id: OutboundDeliveryId,
    pub(crate) scope: TurnScope,
    pub(crate) attempt_id: Uuid,
    pub(crate) command: Option<MatrixOutboundCommand>,
}

impl StoredMatrixOutboundMetadataV1 {
    fn empty(delivery_id: OutboundDeliveryId, scope: TurnScope) -> Self {
        Self {
            schema_version: MATRIX_METADATA_SCHEMA_VERSION,
            delivery_id,
            scope,
            evidence: None,
            status: None,
            retry_schedule: None,
            retry_execution_context: None,
        }
    }
}

impl StoredMatrixPendingIntentV1 {
    fn pending(
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        command: MatrixOutboundCommand,
    ) -> Self {
        Self {
            schema_version: MATRIX_PENDING_INTENT_SCHEMA_VERSION,
            delivery_id,
            scope,
            attempt_id,
            command: Some(command),
        }
    }

    fn consumed_tombstone(
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Self {
        Self {
            schema_version: MATRIX_PENDING_INTENT_SCHEMA_VERSION,
            delivery_id,
            scope,
            attempt_id,
            command: None,
        }
    }

    fn is_consumed_tombstone(&self) -> bool {
        self.command.is_none()
    }
}

impl From<&MatrixRetrySchedule> for StoredMatrixRetryScheduleV1 {
    fn from(schedule: &MatrixRetrySchedule) -> Self {
        Self {
            attempt_number: schedule.attempt_number,
            retry_after_millis: schedule.retry_after.as_millis().min(u128::from(u64::MAX)) as u64,
            reason: schedule.reason,
            recorded_at: schedule.recorded_at,
            claim_started_at: None,
            claim_expires_at: None,
        }
    }
}

impl StoredMatrixRetryScheduleV1 {
    fn into_schedule(
        self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
    ) -> MatrixRetrySchedule {
        MatrixRetrySchedule {
            delivery_id,
            scope,
            attempt_number: self.attempt_number,
            retry_after: Duration::from_millis(self.retry_after_millis),
            reason: self.reason,
            recorded_at: self.recorded_at,
        }
    }
}

impl From<&MatrixRouteMetadata> for StoredMatrixRouteMetadataV1 {
    fn from(metadata: &MatrixRouteMetadata) -> Self {
        Self {
            policy_revision: metadata.policy_revision.clone(),
            homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint.clone(),
            room_fingerprint: metadata.room_fingerprint.clone(),
            egress_target_index: metadata.egress_target_index,
            credential_handle_fingerprint: metadata.credential_handle_fingerprint.clone(),
            reply_target_binding_ref: metadata.reply_target_binding_ref.clone(),
            allowed_command_kinds: metadata.allowed_command_kinds.clone(),
            policy_provider_scope: metadata
                .policy_provider_scope
                .as_ref()
                .map(StoredMatrixPolicyProviderScopeV1::from),
        }
    }
}

impl From<StoredMatrixRouteMetadataV1> for MatrixRouteMetadata {
    fn from(metadata: StoredMatrixRouteMetadataV1) -> Self {
        Self {
            policy_revision: metadata.policy_revision,
            homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint,
            room_fingerprint: metadata.room_fingerprint,
            egress_target_index: metadata.egress_target_index,
            credential_handle_fingerprint: metadata.credential_handle_fingerprint,
            reply_target_binding_ref: metadata.reply_target_binding_ref,
            allowed_command_kinds: metadata.allowed_command_kinds,
            policy_provider_scope: metadata.policy_provider_scope.map(Into::into),
        }
    }
}

impl From<&MatrixPolicyProviderScope> for StoredMatrixPolicyProviderScopeV1 {
    fn from(scope: &MatrixPolicyProviderScope) -> Self {
        Self {
            tenant_id: scope.tenant_id.clone(),
            agent_id: scope.agent_id.clone(),
            project_id: scope.project_id.clone(),
        }
    }
}

impl From<StoredMatrixPolicyProviderScopeV1> for MatrixPolicyProviderScope {
    fn from(scope: StoredMatrixPolicyProviderScopeV1) -> Self {
        Self {
            tenant_id: scope.tenant_id,
            agent_id: scope.agent_id,
            project_id: scope.project_id,
        }
    }
}

impl From<&FrozenProductDeliveryRoute> for StoredFrozenProductDeliveryRouteV1 {
    fn from(route: &FrozenProductDeliveryRoute) -> Self {
        Self {
            delivery_id: route.delivery_id,
            scope: route.scope.clone(),
            installation_id: route.installation_id.clone(),
            adapter_id: route.adapter_id.clone(),
            metadata: StoredMatrixRouteMetadataV1::from(&route.metadata),
        }
    }
}

impl From<StoredFrozenProductDeliveryRouteV1> for FrozenProductDeliveryRoute {
    fn from(route: StoredFrozenProductDeliveryRouteV1) -> Self {
        Self {
            delivery_id: route.delivery_id,
            scope: route.scope,
            installation_id: route.installation_id,
            adapter_id: route.adapter_id,
            metadata: route.metadata.into(),
        }
    }
}

impl From<&SealedDeliveryGrant> for StoredSealedDeliveryGrantV1 {
    fn from(grant: &SealedDeliveryGrant) -> Self {
        Self {
            delivery_id: grant.delivery_id,
            installation_id: grant.installation_id.clone(),
            adapter_id: grant.adapter_id.clone(),
            policy_revision: grant.policy_revision.clone(),
            homeserver_origin_fingerprint: grant.homeserver_origin_fingerprint.clone(),
            room_fingerprint: grant.room_fingerprint.clone(),
            egress_target_index: grant.egress_target_index,
            credential_handle_fingerprint: grant.credential_handle_fingerprint.clone(),
            allowed_command_kinds: grant.allowed_command_kinds.clone(),
        }
    }
}

impl From<StoredSealedDeliveryGrantV1> for SealedDeliveryGrant {
    fn from(grant: StoredSealedDeliveryGrantV1) -> Self {
        Self {
            delivery_id: grant.delivery_id,
            installation_id: grant.installation_id,
            adapter_id: grant.adapter_id,
            policy_revision: grant.policy_revision,
            homeserver_origin_fingerprint: grant.homeserver_origin_fingerprint,
            room_fingerprint: grant.room_fingerprint,
            egress_target_index: grant.egress_target_index,
            credential_handle_fingerprint: grant.credential_handle_fingerprint,
            allowed_command_kinds: grant.allowed_command_kinds,
        }
    }
}

impl StoredMatrixRetryExecutionContextV1 {
    fn new(route: &FrozenProductDeliveryRoute, grant: &SealedDeliveryGrant) -> Self {
        Self {
            route: StoredFrozenProductDeliveryRouteV1::from(route),
            grant: StoredSealedDeliveryGrantV1::from(grant),
        }
    }

    fn into_context(self) -> Result<MatrixRetryExecutionContext, MatrixOutboundContractError> {
        let route = FrozenProductDeliveryRoute::from(self.route);
        let grant = SealedDeliveryGrant::from(self.grant);
        MatrixRetryExecutionContext::new(route, grant)
    }

    fn validate(&self) -> Result<(), MatrixOutboundContractError> {
        let matches_route = self.grant.delivery_id == self.route.delivery_id
            && self.grant.installation_id == self.route.installation_id
            && self.grant.adapter_id == self.route.adapter_id
            && self.grant.policy_revision == self.route.metadata.policy_revision
            && self.grant.homeserver_origin_fingerprint
                == self.route.metadata.homeserver_origin_fingerprint
            && self.grant.room_fingerprint == self.route.metadata.room_fingerprint
            && self.grant.egress_target_index == self.route.metadata.egress_target_index
            && self.grant.credential_handle_fingerprint
                == self.route.metadata.credential_handle_fingerprint
            && self.grant.allowed_command_kinds == self.route.metadata.allowed_command_kinds;
        if matches_route {
            Ok(())
        } else {
            Err(MatrixOutboundContractError::Backend(
                "matrix retry execution context route/grant mismatch".to_string(),
            ))
        }
    }
}

pub struct FilesystemMatrixPendingIntentStore<F>
where
    F: RootFilesystem + ?Sized + 'static,
{
    filesystem: Arc<ScopedFilesystem<F>>,
}

enum PendingRecordMutation<T> {
    Write {
        record: Box<StoredMatrixPendingIntentV1>,
        outcome: T,
    },
    NoOp {
        outcome: T,
    },
}

impl<F> FilesystemMatrixPendingIntentStore<F>
where
    F: RootFilesystem + ?Sized,
{
    pub fn new(filesystem: Arc<ScopedFilesystem<F>>) -> Self {
        Self { filesystem }
    }

    pub async fn persist_pending_command(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        command: MatrixOutboundCommand,
    ) -> Result<(), MatrixOutboundContractError> {
        let record_scope = scope.clone();
        self.mutate_pending_record(scope, delivery_id, attempt_id, |current| {
            let record = match current {
                Some(mut record) => {
                    if record.is_consumed_tombstone() {
                        return Ok(PendingRecordMutation::Write {
                            record: Box::new(record),
                            outcome: (),
                        });
                    }
                    record.command = Some(command.clone());
                    record
                }
                None => StoredMatrixPendingIntentV1::pending(
                    record_scope.clone(),
                    delivery_id,
                    attempt_id,
                    command.clone(),
                ),
            };
            Ok(PendingRecordMutation::Write {
                record: Box::new(record),
                outcome: (),
            })
        })
        .await
    }

    pub async fn load_pending_command(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Result<Option<MatrixOutboundCommand>, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_pending_intent_path(&scope, delivery_id, attempt_id)?;
        let Some(versioned) = self.filesystem.get(&resource_scope, &path).await? else {
            return Ok(None);
        };
        let record = serde_json::from_slice::<StoredMatrixPendingIntentV1>(&versioned.entry.body)?;
        validate_stored_matrix_pending_intent(&record, &scope, delivery_id, attempt_id)?;
        Ok(record.command)
    }

    pub async fn mark_pending_command_consumed(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Result<bool, MatrixOutboundContractError> {
        self.mutate_pending_record(scope, delivery_id, attempt_id, |current| {
            let Some(mut record) = current else {
                return Ok(PendingRecordMutation::NoOp { outcome: false });
            };
            let consumed = record.command.take().is_some();
            Ok(PendingRecordMutation::Write {
                record: Box::new(record),
                outcome: consumed,
            })
        })
        .await
    }

    pub async fn take_pending_command(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
    ) -> Result<Option<MatrixOutboundCommand>, MatrixOutboundContractError> {
        self.mutate_pending_record(scope, delivery_id, attempt_id, |current| {
            let Some(mut record) = current else {
                return Ok(PendingRecordMutation::NoOp { outcome: None });
            };
            let command = record.command.take();
            Ok(PendingRecordMutation::Write {
                record: Box::new(record),
                outcome: command,
            })
        })
        .await
    }

    async fn mutate_pending_record<T>(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        attempt_id: Uuid,
        mutate: impl Fn(
            Option<StoredMatrixPendingIntentV1>,
        ) -> Result<PendingRecordMutation<T>, MatrixOutboundContractError>,
    ) -> Result<T, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_pending_intent_path(&scope, delivery_id, attempt_id)?;
        cas_update(
            self.filesystem.as_ref(),
            &resource_scope,
            &path,
            |bytes: &[u8]| {
                serde_json::from_slice::<StoredMatrixPendingIntentV1>(bytes).map_err(Into::into)
            },
            |record: &StoredMatrixPendingIntentV1| {
                Ok(
                    Entry::bytes(serde_json::to_vec(record)?)
                        .with_content_type(ContentType::json()),
                )
            },
            |current: Option<StoredMatrixPendingIntentV1>| {
                let outcome = (|| {
                    if let Some(record) = &current {
                        validate_stored_matrix_pending_intent(
                            record,
                            &scope,
                            delivery_id,
                            attempt_id,
                        )?;
                    }
                    match mutate(current)? {
                        PendingRecordMutation::Write { record, outcome } => {
                            validate_stored_matrix_pending_intent(
                                record.as_ref(),
                                &scope,
                                delivery_id,
                                attempt_id,
                            )?;
                            Ok(CasApply::new(*record, outcome))
                        }
                        PendingRecordMutation::NoOp { outcome } => Ok(CasApply::no_op(
                            StoredMatrixPendingIntentV1::consumed_tombstone(
                                scope.clone(),
                                delivery_id,
                                attempt_id,
                            ),
                            outcome,
                        )),
                    }
                })();
                async move { outcome }
            },
        )
        .await
        .map_err(map_matrix_pending_intent_cas_error)
    }
}

pub struct FilesystemMatrixOutboundMetadataStore<F>
where
    F: RootFilesystem + ?Sized,
{
    filesystem: Arc<ScopedFilesystem<F>>,
    outbound_state_store: Arc<dyn OutboundStateStore>,
}

impl<F> FilesystemMatrixOutboundMetadataStore<F>
where
    F: RootFilesystem + ?Sized,
{
    pub fn new(
        filesystem: Arc<ScopedFilesystem<F>>,
        outbound_state_store: Arc<dyn OutboundStateStore>,
    ) -> Self {
        Self {
            filesystem,
            outbound_state_store,
        }
    }

    pub async fn load_evidence(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<MatrixDeliveryEvidenceV1>, MatrixOutboundContractError> {
        Ok(self
            .load_record(&scope, delivery_id)
            .await?
            .and_then(|record| record.evidence))
    }

    pub async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError> {
        Ok(self
            .load_record(&scope, delivery_id)
            .await?
            .and_then(|record| {
                record.status.map(|status| UpdateDeliveryStatusRequest {
                    delivery_id,
                    scope,
                    status: status.status,
                    updated_at: status.updated_at,
                    failure_kind: status.failure_kind,
                })
            }))
    }

    pub async fn load_retry_schedule(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<MatrixRetrySchedule>, MatrixOutboundContractError> {
        Ok(self
            .load_record(&scope, delivery_id)
            .await?
            .and_then(|record| {
                record
                    .retry_schedule
                    .map(|schedule| schedule.into_schedule(delivery_id, scope))
            }))
    }

    pub async fn list_due_retry_schedules(
        &self,
        scope: TurnScope,
        now: DateTime<Utc>,
        max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }

        let resource_scope = scope.to_resource_scope();
        let metadata_dir = matrix_metadata_dir_path()?;
        let entries = match self
            .filesystem
            .list_dir(&resource_scope, &metadata_dir)
            .await
        {
            Ok(entries) => entries,
            Err(FilesystemError::NotFound { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let terminal_delivery_ids = self
            .outbound_state_store
            .list_delivery_attempts(scope.clone())
            .await?
            .into_iter()
            .filter(|attempt| is_terminal_delivery_status(attempt.status))
            .map(|attempt| attempt.delivery_id)
            .collect::<HashSet<_>>();
        let mut schedules = Vec::new();
        for entry in entries {
            if entry.file_type != FileType::File {
                continue;
            }
            let record_path = ScopedPath::new(format!("/outbound/matrix/metadata/{}", entry.name))
                .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))?;
            let Some(record) = self
                .load_record_at_path(&resource_scope, &record_path)
                .await?
            else {
                continue;
            };
            if record.scope != scope
                || terminal_delivery_ids.contains(&record.delivery_id)
                || record
                    .status
                    .as_ref()
                    .is_some_and(|status| is_terminal_delivery_status(status.status))
            {
                continue;
            }
            let Some(schedule) = record.retry_schedule else {
                continue;
            };
            if retry_schedule_due_and_unclaimed(&schedule, now)? {
                schedules.push(schedule.into_schedule(record.delivery_id, record.scope));
                if schedules.len() == max_entries {
                    break;
                }
            }
        }
        Ok(schedules)
    }

    async fn list_live_retry_schedules(
        &self,
        scope: TurnScope,
        max_entries: usize,
    ) -> Result<Vec<MatrixRetrySchedule>, MatrixOutboundContractError> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }

        let resource_scope = scope.to_resource_scope();
        let metadata_dir = matrix_metadata_dir_path()?;
        let entries = match self
            .filesystem
            .list_dir(&resource_scope, &metadata_dir)
            .await
        {
            Ok(entries) => entries,
            Err(FilesystemError::NotFound { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let terminal_delivery_ids = self
            .outbound_state_store
            .list_delivery_attempts(scope.clone())
            .await?
            .into_iter()
            .filter(|attempt| is_terminal_delivery_status(attempt.status))
            .map(|attempt| attempt.delivery_id)
            .collect::<HashSet<_>>();
        let mut schedules = Vec::new();
        for entry in entries {
            if entry.file_type != FileType::File {
                continue;
            }
            let record_path = ScopedPath::new(format!("/outbound/matrix/metadata/{}", entry.name))
                .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))?;
            let Some(record) = self
                .load_record_at_path(&resource_scope, &record_path)
                .await?
            else {
                continue;
            };
            if record.scope != scope
                || terminal_delivery_ids.contains(&record.delivery_id)
                || record
                    .status
                    .as_ref()
                    .is_some_and(|status| is_terminal_delivery_status(status.status))
            {
                continue;
            }
            let Some(schedule) = record.retry_schedule else {
                continue;
            };
            schedules.push(schedule.into_schedule(record.delivery_id, record.scope));
            if schedules.len() == max_entries {
                break;
            }
        }
        Ok(schedules)
    }

    pub async fn list_indexed_retry_scopes(
        &self,
        discovery_roots: &[TurnScope],
    ) -> Result<Vec<TurnScope>, MatrixOutboundContractError> {
        let mut seen = HashSet::new();
        let mut scopes = Vec::new();
        for root in discovery_roots {
            let resource_scope = matrix_retry_scope_index_resource_scope(root);
            for live_scope in self
                .list_live_retry_scopes_from_metadata(root, &resource_scope)
                .await?
            {
                if seen.insert(live_scope.clone()) {
                    scopes.push(live_scope);
                }
            }
            let index_dir = matrix_retry_scope_index_dir_path()?;
            let entries = match self.filesystem.list_dir(&resource_scope, &index_dir).await {
                Ok(entries) => entries,
                Err(FilesystemError::NotFound { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                if entry.file_type != FileType::File {
                    continue;
                }
                let record_path =
                    ScopedPath::new(format!("/outbound/matrix/retry-scope-index/{}", entry.name))
                        .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))?;
                let Some(index_entry) = self
                    .load_retry_scope_index_entry_at_path(&resource_scope, &record_path)
                    .await?
                else {
                    continue;
                };
                if !same_matrix_retry_scope_index_resource_scope(
                    &matrix_retry_scope_index_resource_scope(&index_entry.scope),
                    &resource_scope,
                ) {
                    continue;
                }
                if self.has_live_retry_work(&index_entry.scope).await? {
                    if seen.insert(index_entry.scope.clone()) {
                        scopes.push(index_entry.scope);
                    }
                } else {
                    let _ = self.filesystem.delete(&resource_scope, &record_path).await;
                }
            }
        }
        Ok(scopes)
    }

    async fn list_live_retry_scopes_from_metadata(
        &self,
        discovery_root: &TurnScope,
        resource_scope: &ResourceScope,
    ) -> Result<Vec<TurnScope>, MatrixOutboundContractError> {
        let metadata_dir = matrix_metadata_dir_path()?;
        let entries = match self
            .filesystem
            .list_dir(resource_scope, &metadata_dir)
            .await
        {
            Ok(entries) => entries,
            Err(FilesystemError::NotFound { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let index_resource_scope = matrix_retry_scope_index_resource_scope(discovery_root);
        let mut terminal_delivery_ids_by_scope: HashMap<TurnScope, HashSet<OutboundDeliveryId>> =
            HashMap::new();
        let mut seen = HashSet::new();
        let mut scopes = Vec::new();
        for entry in entries {
            if entry.file_type != FileType::File {
                continue;
            }
            let record_path = ScopedPath::new(format!("/outbound/matrix/metadata/{}", entry.name))
                .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))?;
            let Some(record) = self
                .load_record_at_path(resource_scope, &record_path)
                .await?
            else {
                continue;
            };
            if record.retry_schedule.is_none()
                || !same_matrix_retry_scope_index_resource_scope(
                    &matrix_retry_scope_index_resource_scope(&record.scope),
                    &index_resource_scope,
                )
                || record
                    .status
                    .as_ref()
                    .is_some_and(|status| is_terminal_delivery_status(status.status))
            {
                continue;
            }
            if !terminal_delivery_ids_by_scope.contains_key(&record.scope) {
                let terminal_delivery_ids = self
                    .outbound_state_store
                    .list_delivery_attempts(record.scope.clone())
                    .await?
                    .into_iter()
                    .filter(|attempt| is_terminal_delivery_status(attempt.status))
                    .map(|attempt| attempt.delivery_id)
                    .collect::<HashSet<_>>();
                terminal_delivery_ids_by_scope.insert(record.scope.clone(), terminal_delivery_ids);
            }
            if terminal_delivery_ids_by_scope
                .get(&record.scope)
                .is_some_and(|terminal_delivery_ids| {
                    terminal_delivery_ids.contains(&record.delivery_id)
                })
            {
                continue;
            }
            if seen.insert(record.scope.clone()) {
                let _ = self
                    .upsert_retry_scope_index(&record.scope, Utc::now())
                    .await;
                scopes.push(record.scope);
            }
        }
        Ok(scopes)
    }

    async fn has_live_retry_work(
        &self,
        scope: &TurnScope,
    ) -> Result<bool, MatrixOutboundContractError> {
        Ok(!self
            .list_live_retry_schedules(scope.clone(), 1)
            .await?
            .is_empty())
    }

    pub async fn persist_retry_execution_context(
        &self,
        _owner: &MatrixRoutePolicyOwnerToken,
        route: &FrozenProductDeliveryRoute,
        grant: &SealedDeliveryGrant,
    ) -> Result<(), MatrixOutboundContractError> {
        validate_retry_execution_context(route, grant)?;
        self.mutate_record(route.scope().clone(), route.delivery_id, |mut record| {
            record.retry_execution_context =
                Some(StoredMatrixRetryExecutionContextV1::new(route, grant));
            record
        })
        .await
    }

    pub async fn load_retry_execution_context(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<MatrixRetryExecutionContext>, MatrixOutboundContractError> {
        let Some(record) = self.load_record(&scope, delivery_id).await? else {
            return Ok(None);
        };
        if record.retry_schedule.is_none() {
            return Ok(None);
        }
        if record
            .status
            .as_ref()
            .is_some_and(|status| is_terminal_delivery_status(status.status))
        {
            return Ok(None);
        }
        record
            .retry_execution_context
            .map(StoredMatrixRetryExecutionContextV1::into_context)
            .transpose()
    }

    pub async fn claim_due_retry_schedule(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        now: DateTime<Utc>,
        lease_duration: Duration,
    ) -> Result<Option<MatrixRetrySchedule>, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_metadata_path(&scope, delivery_id)?;
        cas_update(
            self.filesystem.as_ref(),
            &resource_scope,
            &path,
            |bytes: &[u8]| {
                serde_json::from_slice::<StoredMatrixOutboundMetadataV1>(bytes).map_err(Into::into)
            },
            |record: &StoredMatrixOutboundMetadataV1| {
                Ok(
                    Entry::bytes(serde_json::to_vec(record)?)
                        .with_content_type(ContentType::json()),
                )
            },
            |current: Option<StoredMatrixOutboundMetadataV1>| {
                let outcome = (|| {
                    let Some(mut record) = current else {
                        return Ok(CasApply::no_op(
                            StoredMatrixOutboundMetadataV1::empty(delivery_id, scope.clone()),
                            None,
                        ));
                    };
                    validate_stored_matrix_metadata(&record, &scope, delivery_id)?;

                    if record
                        .status
                        .as_ref()
                        .is_some_and(|status| is_terminal_delivery_status(status.status))
                    {
                        record.retry_schedule = None;
                        return Ok(CasApply::new(record, None));
                    }

                    let Some(schedule) = record.retry_schedule.as_mut() else {
                        return Ok(CasApply::no_op(record, None));
                    };
                    let due_at = retry_due_at(schedule.recorded_at, schedule.retry_after_millis)?;
                    if now < due_at
                        || schedule
                            .claim_expires_at
                            .is_some_and(|claim_expires_at| now < claim_expires_at)
                    {
                        return Ok(CasApply::no_op(record, None));
                    }

                    let claimed_schedule =
                        schedule.clone().into_schedule(delivery_id, scope.clone());
                    schedule.claim_started_at = Some(now);
                    schedule.claim_expires_at = Some(
                        now.checked_add_signed(chrono_duration_from_std(lease_duration)?)
                            .ok_or_else(|| {
                                MatrixOutboundContractError::Backend(
                                    "matrix retry claim lease overflow".to_string(),
                                )
                            })?,
                    );
                    Ok(CasApply::new(record, Some(claimed_schedule)))
                })();
                async move { outcome }
            },
        )
        .await
        .map_err(map_matrix_metadata_cas_error)
    }

    async fn load_record(
        &self,
        scope: &TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<StoredMatrixOutboundMetadataV1>, MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_metadata_path(scope, delivery_id)?;
        let Some(versioned) = self.filesystem.get(&resource_scope, &path).await? else {
            return Ok(None);
        };
        let record: StoredMatrixOutboundMetadataV1 = serde_json::from_slice(&versioned.entry.body)?;
        validate_stored_matrix_metadata(&record, scope, delivery_id)?;
        Ok(Some(record))
    }

    async fn load_record_at_path(
        &self,
        resource_scope: &ResourceScope,
        path: &ScopedPath,
    ) -> Result<Option<StoredMatrixOutboundMetadataV1>, MatrixOutboundContractError> {
        let Some(versioned) = self.filesystem.get(resource_scope, path).await? else {
            return Ok(None);
        };
        let record: StoredMatrixOutboundMetadataV1 = serde_json::from_slice(&versioned.entry.body)?;
        validate_stored_matrix_metadata(&record, &record.scope, record.delivery_id)?;
        Ok(Some(record))
    }

    async fn load_retry_scope_index_entry_at_path(
        &self,
        resource_scope: &ResourceScope,
        path: &ScopedPath,
    ) -> Result<Option<StoredMatrixRetryScopeIndexEntryV1>, MatrixOutboundContractError> {
        let Some(versioned) = self.filesystem.get(resource_scope, path).await? else {
            return Ok(None);
        };
        let record: StoredMatrixRetryScopeIndexEntryV1 =
            serde_json::from_slice(&versioned.entry.body)?;
        validate_stored_matrix_retry_scope_index_entry(&record)?;
        Ok(Some(record))
    }

    async fn mutate_record(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
        mutate: impl Fn(StoredMatrixOutboundMetadataV1) -> StoredMatrixOutboundMetadataV1,
    ) -> Result<(), MatrixOutboundContractError> {
        let resource_scope = scope.to_resource_scope();
        let path = matrix_metadata_path(&scope, delivery_id)?;
        cas_update(
            self.filesystem.as_ref(),
            &resource_scope,
            &path,
            |bytes: &[u8]| {
                serde_json::from_slice::<StoredMatrixOutboundMetadataV1>(bytes).map_err(Into::into)
            },
            |record: &StoredMatrixOutboundMetadataV1| {
                Ok(
                    Entry::bytes(serde_json::to_vec(record)?)
                        .with_content_type(ContentType::json()),
                )
            },
            |current: Option<StoredMatrixOutboundMetadataV1>| {
                let outcome = (|| {
                    let record = current.unwrap_or_else(|| {
                        StoredMatrixOutboundMetadataV1::empty(delivery_id, scope.clone())
                    });
                    validate_stored_matrix_metadata(&record, &scope, delivery_id)?;
                    let record = mutate(record);
                    Ok(CasApply::new(record, ()))
                })();
                async move { outcome }
            },
        )
        .await
        .map_err(map_matrix_metadata_cas_error)
    }

    async fn upsert_retry_scope_index(
        &self,
        scope: &TurnScope,
        updated_at: DateTime<Utc>,
    ) -> Result<(), MatrixOutboundContractError> {
        let resource_scope = matrix_retry_scope_index_resource_scope(scope);
        let path = matrix_retry_scope_index_path(scope)?;
        let record = StoredMatrixRetryScopeIndexEntryV1 {
            schema_version: MATRIX_METADATA_SCHEMA_VERSION,
            scope: scope.clone(),
            updated_at,
        };
        validate_stored_matrix_retry_scope_index_entry(&record)?;
        self.filesystem
            .put(
                &resource_scope,
                &path,
                Entry::bytes(serde_json::to_vec(&record)?).with_content_type(ContentType::json()),
                CasExpectation::Any,
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl<F> MatrixOutboundMetadataStore for FilesystemMatrixOutboundMetadataStore<F>
where
    F: RootFilesystem + ?Sized + 'static,
{
    async fn load_delivery_status(
        &self,
        scope: TurnScope,
        delivery_id: OutboundDeliveryId,
    ) -> Result<Option<UpdateDeliveryStatusRequest>, MatrixOutboundContractError> {
        self.load_delivery_status(scope, delivery_id).await
    }

    async fn update_delivery_status(
        &self,
        request: UpdateDeliveryStatusRequest,
    ) -> Result<(), MatrixOutboundContractError> {
        self.outbound_state_store
            .update_delivery_status(request.clone())
            .await
            .map_err(MatrixOutboundContractError::from)?;
        self.mutate_record(request.scope.clone(), request.delivery_id, |mut record| {
            record.status = Some(StoredMatrixDeliveryStatusV1 {
                status: request.status,
                updated_at: request.updated_at,
                failure_kind: request.failure_kind,
            });
            if is_terminal_delivery_status(request.status) {
                record.retry_schedule = None;
                record.retry_execution_context = None;
            }
            record
        })
        .await
    }

    async fn persist_evidence(
        &self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        evidence: ValidatedMatrixDeliveryEvidence,
    ) -> Result<(), MatrixOutboundContractError> {
        self.mutate_record(scope, delivery_id, |mut record| {
            record.evidence = Some(evidence.clone().into_inner());
            record
        })
        .await
    }

    async fn record_retry_scheduled(
        &self,
        schedule: MatrixRetrySchedule,
        context: MatrixRetryExecutionContext,
    ) -> Result<(), MatrixOutboundContractError> {
        let delivery_id = schedule.delivery_id;
        let scope = schedule.scope.clone();
        if context.route.delivery_id != delivery_id || context.route.scope != scope {
            return Err(MatrixOutboundContractError::Backend(
                "matrix retry schedule context identity mismatch".to_string(),
            ));
        }
        self.mutate_record(scope, delivery_id, |mut record| {
            record.retry_schedule = Some(StoredMatrixRetryScheduleV1::from(&schedule));
            record.retry_execution_context = Some(StoredMatrixRetryExecutionContextV1::new(
                &context.route,
                &context.grant,
            ));
            record
        })
        .await?;
        self.upsert_retry_scope_index(&schedule.scope, schedule.recorded_at)
            .await
    }
}

fn matrix_metadata_path(
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
) -> Result<ScopedPath, MatrixOutboundContractError> {
    let scope_json = serde_json::to_vec(scope)?;
    let key = format!("{}:{}", sha256_hex(&scope_json), delivery_id);
    ScopedPath::new(format!(
        "/outbound/matrix/metadata/{}.json",
        sha256_hex(key.as_bytes())
    ))
    .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

fn matrix_metadata_dir_path() -> Result<ScopedPath, MatrixOutboundContractError> {
    ScopedPath::new("/outbound/matrix/metadata")
        .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

pub(crate) fn matrix_retry_scope_index_resource_scope(scope: &TurnScope) -> ResourceScope {
    let mut resource_scope = scope.to_resource_scope();
    resource_scope.thread_id = None;
    resource_scope
}

fn same_matrix_retry_scope_index_resource_scope(
    left: &ResourceScope,
    right: &ResourceScope,
) -> bool {
    left.tenant_id == right.tenant_id
        && left.user_id == right.user_id
        && left.agent_id == right.agent_id
        && left.project_id == right.project_id
        && left.mission_id == right.mission_id
        && left.thread_id == right.thread_id
}

pub(crate) fn matrix_retry_scope_index_path(
    scope: &TurnScope,
) -> Result<ScopedPath, MatrixOutboundContractError> {
    let scope_json = serde_json::to_vec(scope)?;
    ScopedPath::new(format!(
        "/outbound/matrix/retry-scope-index/{}.json",
        sha256_hex(&scope_json)
    ))
    .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

fn matrix_retry_scope_index_dir_path() -> Result<ScopedPath, MatrixOutboundContractError> {
    ScopedPath::new("/outbound/matrix/retry-scope-index")
        .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

pub(crate) fn matrix_pending_intent_path(
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
    attempt_id: Uuid,
) -> Result<ScopedPath, MatrixOutboundContractError> {
    let scope_json = serde_json::to_vec(scope)?;
    let key = format!("{}:{}:{}", sha256_hex(&scope_json), delivery_id, attempt_id);
    ScopedPath::new(format!(
        "/outbound/matrix/pending-intents/{}.json",
        sha256_hex(key.as_bytes())
    ))
    .map_err(|error| MatrixOutboundContractError::Backend(error.to_string()))
}

pub(crate) fn chrono_duration_from_std(
    duration: Duration,
) -> Result<chrono::Duration, MatrixOutboundContractError> {
    chrono::Duration::from_std(duration).map_err(|_| {
        MatrixOutboundContractError::Backend("matrix retry duration overflow".to_string())
    })
}

fn retry_due_at(
    recorded_at: DateTime<Utc>,
    retry_after_millis: u64,
) -> Result<DateTime<Utc>, MatrixOutboundContractError> {
    recorded_at
        .checked_add_signed(chrono_duration_from_std(Duration::from_millis(
            retry_after_millis,
        ))?)
        .ok_or_else(|| {
            MatrixOutboundContractError::Backend("matrix retry due timestamp overflow".to_string())
        })
}

fn retry_schedule_due_and_unclaimed(
    schedule: &StoredMatrixRetryScheduleV1,
    now: DateTime<Utc>,
) -> Result<bool, MatrixOutboundContractError> {
    Ok(
        now >= retry_due_at(schedule.recorded_at, schedule.retry_after_millis)?
            && schedule
                .claim_expires_at
                .is_none_or(|claim_expires_at| now >= claim_expires_at),
    )
}

fn validate_stored_matrix_metadata(
    record: &StoredMatrixOutboundMetadataV1,
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
) -> Result<(), MatrixOutboundContractError> {
    if record.schema_version != MATRIX_METADATA_SCHEMA_VERSION
        || record.delivery_id != delivery_id
        || record.scope != *scope
    {
        return Err(MatrixOutboundContractError::Backend(
            "matrix metadata identity mismatch".to_string(),
        ));
    }
    if let Some(evidence) = &record.evidence {
        evidence.validate_redacted()?;
    }
    if let Some(context) = &record.retry_execution_context {
        if context.route.delivery_id != record.delivery_id || context.route.scope != record.scope {
            return Err(MatrixOutboundContractError::Backend(
                "matrix retry execution context identity mismatch".to_string(),
            ));
        }
        context.validate()?;
    }
    Ok(())
}

fn validate_stored_matrix_retry_scope_index_entry(
    record: &StoredMatrixRetryScopeIndexEntryV1,
) -> Result<(), MatrixOutboundContractError> {
    if record.schema_version != MATRIX_METADATA_SCHEMA_VERSION {
        return Err(MatrixOutboundContractError::Backend(
            "matrix retry scope index schema mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_stored_matrix_pending_intent(
    record: &StoredMatrixPendingIntentV1,
    scope: &TurnScope,
    delivery_id: OutboundDeliveryId,
    attempt_id: Uuid,
) -> Result<(), MatrixOutboundContractError> {
    if record.schema_version != MATRIX_PENDING_INTENT_SCHEMA_VERSION
        || record.delivery_id != delivery_id
        || record.scope != *scope
        || record.attempt_id != attempt_id
    {
        return Err(MatrixOutboundContractError::Backend(
            "matrix pending intent identity mismatch".to_string(),
        ));
    }
    if let Some(command) = &record.command {
        validate_stored_matrix_pending_command(command)?;
    }
    Ok(())
}

fn validate_stored_matrix_pending_command(
    command: &MatrixOutboundCommand,
) -> Result<(), MatrixOutboundContractError> {
    MatrixTransactionId::new(command.transaction_id.as_str().to_owned())?;
    MatrixRoomId::new(command.room_id.as_str().to_owned())?;
    MatrixMessageBody::new(command.body.as_json().clone())?;
    Ok(())
}

fn map_matrix_metadata_cas_error(
    error: CasUpdateError<MatrixOutboundContractError>,
) -> MatrixOutboundContractError {
    match error {
        CasUpdateError::Apply(error) => error,
        CasUpdateError::Backend(error) => error.into(),
        error @ (CasUpdateError::Timeout
        | CasUpdateError::RetriesExhausted
        | CasUpdateError::CasUnsupported) => {
            MatrixOutboundContractError::Backend(error.to_string())
        }
    }
}

fn map_matrix_pending_intent_cas_error(
    error: CasUpdateError<MatrixOutboundContractError>,
) -> MatrixOutboundContractError {
    match error {
        CasUpdateError::Apply(error) => error,
        CasUpdateError::Backend(error) => error.into(),
        error @ (CasUpdateError::Timeout
        | CasUpdateError::RetriesExhausted
        | CasUpdateError::CasUnsupported) => {
            MatrixOutboundContractError::Backend(error.to_string())
        }
    }
}
