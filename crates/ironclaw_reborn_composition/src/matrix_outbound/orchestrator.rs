use super::*;

pub struct MatrixOutboundOrchestrator<'a> {
    port: &'a dyn MatrixDeliveryPort,
    credential_resolver: &'a dyn MatrixCredentialResolver,
    metadata_store: &'a dyn MatrixOutboundMetadataStore,
    pub(crate) retry_policy: &'a dyn RetryPolicy,
}

impl<'a> MatrixOutboundOrchestrator<'a> {
    pub fn new(
        port: &'a dyn MatrixDeliveryPort,
        credential_resolver: &'a dyn MatrixCredentialResolver,
        metadata_store: &'a dyn MatrixOutboundMetadataStore,
        retry_policy: &'a dyn RetryPolicy,
    ) -> Self {
        Self {
            port,
            credential_resolver,
            metadata_store,
            retry_policy,
        }
    }

    pub async fn consume_pending_intent(
        &self,
        command: MatrixOutboundCommand,
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
        attempt: DeliveryAttemptContext,
    ) -> Result<MatrixOrchestratorOutcome, DeliveryError> {
        let route_scope = route.scope().clone();
        let validated = match validate_matrix_route_grant(&command, route, &grant) {
            Ok(validated) => validated,
            Err(error) => {
                self.persist_terminal_status(
                    attempt.delivery_id,
                    route_scope,
                    MatrixTerminalStatus::FailedUnauthorized,
                    Some(error.reason),
                )
                .await?;
                return Err(error);
            }
        };
        if attempt.delivery_id != validated.delivery_id() {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )
            .await?;
            return Err(error);
        }
        let retry_context =
            MatrixRetryExecutionContext::new(validated.route.clone(), grant.clone())
                .map_err(DeliveryError::from)?;
        let metadata = validated.matrix_metadata().clone();
        let Some(credential) = self.credential_resolver.resolve(&validated) else {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )
            .await?;
            return Err(error);
        };
        if credential.credential_handle_fingerprint != metadata.credential_handle_fingerprint {
            let error = DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget);
            self.persist_terminal_status(
                attempt.delivery_id,
                validated.route.scope().clone(),
                MatrixTerminalStatus::FailedUnauthorized,
                Some(error.reason),
            )
            .await?;
            return Err(error);
        }
        let validated_scope = validated.route.scope().clone();

        match self
            .port
            .deliver(
                ProtocolDeliveryIntent::Matrix(command.clone()),
                validated,
                credential,
                attempt.clone(),
            )
            .await
        {
            DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(evidence)) => {
                let evidence = match ValidatedMatrixDeliveryEvidence::new_for_delivery(
                    evidence, &command, &metadata, &attempt,
                ) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        return self
                            .apply_delivery_error(
                                DeliveryError::from(error),
                                &attempt,
                                validated_scope,
                                retry_context.clone(),
                            )
                            .await;
                    }
                };
                self.metadata_store
                    .persist_evidence(attempt.delivery_id, validated_scope.clone(), evidence)
                    .await?;
                self.persist_terminal_status(
                    attempt.delivery_id,
                    validated_scope,
                    MatrixTerminalStatus::Delivered,
                    None,
                )
                .await?;
                Ok(MatrixOrchestratorOutcome {
                    status: MatrixTerminalStatus::Delivered,
                    retry: None,
                })
            }
            DeliveryPortResult::Rejected(error) => {
                self.apply_delivery_error(error, &attempt, validated_scope, retry_context)
                    .await
            }
        }
    }

    async fn apply_delivery_error(
        &self,
        error: DeliveryError,
        attempt: &DeliveryAttemptContext,
        scope: TurnScope,
        retry_context: MatrixRetryExecutionContext,
    ) -> Result<MatrixOrchestratorOutcome, DeliveryError> {
        let decision = self.retry_policy.classify(&error, attempt.attempt_number);
        match decision {
            MatrixRetryDecision::RetryAfter { after, reason } => {
                self.metadata_store
                    .record_retry_scheduled(
                        MatrixRetrySchedule {
                            delivery_id: attempt.delivery_id,
                            scope,
                            attempt_number: attempt.attempt_number,
                            retry_after: after,
                            reason,
                            recorded_at: Utc::now(),
                        },
                        retry_context,
                    )
                    .await?;
                Ok(MatrixOrchestratorOutcome {
                    status: MatrixTerminalStatus::RetryScheduled,
                    retry: Some(decision),
                })
            }
            MatrixRetryDecision::DoNotRetry { terminal_status } => {
                self.persist_terminal_status(
                    attempt.delivery_id,
                    scope,
                    terminal_status,
                    Some(error.reason),
                )
                .await?;
                Err(error)
            }
        }
    }

    pub(crate) async fn persist_terminal_status(
        &self,
        delivery_id: OutboundDeliveryId,
        scope: TurnScope,
        status: MatrixTerminalStatus,
        reason: Option<DeliveryReasonCode>,
    ) -> Result<(), MatrixOutboundContractError> {
        self.metadata_store
            .update_delivery_status(UpdateDeliveryStatusRequest {
                delivery_id,
                scope,
                status: outbound_status_for_matrix_status(status),
                updated_at: Utc::now(),
                failure_kind: reason.map(delivery_failure_kind_for_reason),
            })
            .await
    }
}

fn outbound_status_for_matrix_status(status: MatrixTerminalStatus) -> OutboundDeliveryStatus {
    match status {
        MatrixTerminalStatus::Delivered => OutboundDeliveryStatus::Delivered,
        MatrixTerminalStatus::RetryScheduled => OutboundDeliveryStatus::Pending,
        MatrixTerminalStatus::FailedPermanent
        | MatrixTerminalStatus::FailedUnauthorized
        | MatrixTerminalStatus::FailedExhausted => OutboundDeliveryStatus::Failed,
    }
}

pub(crate) fn delivery_failure_kind_for_reason(reason: DeliveryReasonCode) -> DeliveryFailureKind {
    match reason {
        DeliveryReasonCode::UnauthorizedTarget => DeliveryFailureKind::AuthorizationRevoked,
        DeliveryReasonCode::MatrixRateLimited => DeliveryFailureKind::RateLimited,
        DeliveryReasonCode::MatrixTimeout
        | DeliveryReasonCode::MatrixServerError
        | DeliveryReasonCode::MatrixMalformedResponse => DeliveryFailureKind::TransportUnavailable,
        DeliveryReasonCode::MissingMatrixRoute
        | DeliveryReasonCode::UnsupportedMatrixCommand
        | DeliveryReasonCode::MatrixBadRequest
        | DeliveryReasonCode::MatrixNotFound
        | DeliveryReasonCode::MatrixMessageTooLarge
        | DeliveryReasonCode::MatrixUnsupportedRoomVersion
        | DeliveryReasonCode::MaxAttemptsExceeded => DeliveryFailureKind::Rejected,
    }
}

impl From<MatrixOutboundContractError> for DeliveryError {
    fn from(value: MatrixOutboundContractError) -> Self {
        observability::record_contract_error(&value);
        Self::new(DeliveryReasonCode::MatrixMalformedResponse)
    }
}

pub struct MatrixProductionDeliveryBridge<'a, F>
where
    F: RootFilesystem + 'static,
{
    pending_store: &'a FilesystemMatrixPendingIntentStore<F>,
    pub(crate) orchestrator: &'a MatrixOutboundOrchestrator<'a>,
}

impl<'a, F> MatrixProductionDeliveryBridge<'a, F>
where
    F: RootFilesystem + 'static,
{
    pub fn new(
        pending_store: &'a FilesystemMatrixPendingIntentStore<F>,
        orchestrator: &'a MatrixOutboundOrchestrator<'a>,
    ) -> Self {
        Self {
            pending_store,
            orchestrator,
        }
    }

    pub async fn recover_pending_command(
        &self,
        route: FrozenProductDeliveryRoute,
        grant: SealedDeliveryGrant,
        attempt: DeliveryAttemptContext,
    ) -> Result<MatrixOrchestratorOutcome, DeliveryError> {
        let attempt_id = route.delivery_id.as_uuid();
        let tombstone_scope = route.scope().clone();
        let delivery_id = route.delivery_id;
        let durable_status = self
            .orchestrator
            .metadata_store
            .load_delivery_status(tombstone_scope.clone(), delivery_id)
            .await?;
        if durable_status
            .as_ref()
            .is_some_and(|request| is_terminal_delivery_status(request.status))
        {
            self.pending_store
                .mark_pending_command_consumed(tombstone_scope, delivery_id, attempt_id)
                .await?;
            return Err(DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute));
        }
        let command = self
            .pending_store
            .load_pending_command(route.scope().clone(), route.delivery_id, attempt_id)
            .await?
            .ok_or_else(|| DeliveryError::new(DeliveryReasonCode::MissingMatrixRoute))?;
        let attempt_number = attempt.attempt_number;
        let outcome = match self
            .orchestrator
            .consume_pending_intent(command, route, grant, attempt)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                let durable_status = self
                    .orchestrator
                    .metadata_store
                    .load_delivery_status(tombstone_scope.clone(), delivery_id)
                    .await?;
                if durable_status
                    .as_ref()
                    .is_some_and(|request| is_terminal_delivery_status(request.status))
                    && matches!(
                        self.orchestrator
                            .retry_policy
                            .classify(&error, attempt_number),
                        MatrixRetryDecision::DoNotRetry { .. }
                    )
                {
                    self.pending_store
                        .mark_pending_command_consumed(
                            tombstone_scope.clone(),
                            delivery_id,
                            attempt_id,
                        )
                        .await?;
                }
                return Err(error);
            }
        };
        if outcome.status != MatrixTerminalStatus::RetryScheduled {
            self.pending_store
                .mark_pending_command_consumed(tombstone_scope, delivery_id, attempt_id)
                .await?;
        }
        Ok(outcome)
    }
}
