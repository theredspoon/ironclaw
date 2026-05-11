//! Trusted `LoopExit` applier for the Reborn turn-runner composition.
//!
//! `LoopExit` is a driver claim. The applier derives trust policy from
//! evidence ports owned by the runner/host composition, validates the claim,
//! and applies only the validated mapping through the turn transition port.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_threads::{
    MessageStatus, SessionThreadService, ThreadHistoryRequest, ThreadMessageId, ThreadScope,
};
use ironclaw_turns::{
    LoopBlocked, LoopCheckpointKind, LoopExit, LoopExitInvalidHandling, LoopExitValidationPolicy,
    LoopFailed, LoopMessageRef, LoopResultRef, ResolvedRunProfile, TurnCheckpointId, TurnError,
    TurnId, TurnRunId, TurnRunState, TurnScope,
    runner::{ApplyValidatedLoopExitRequest, ClaimedTurnRun, TurnRunTransitionPort},
};

/// Evidence request for completion refs returned by a driver.
#[derive(Debug, Clone)]
pub struct CompletionEvidenceRequest<'a> {
    pub scope: &'a TurnScope,
    pub turn_id: TurnId,
    pub run_id: TurnRunId,
    pub reply_message_refs: &'a [LoopMessageRef],
    pub result_refs: &'a [LoopResultRef],
}

/// Evidence request for a terminal final checkpoint.
#[derive(Debug, Clone)]
pub struct FinalCheckpointEvidenceRequest<'a> {
    pub scope: &'a TurnScope,
    pub turn_id: TurnId,
    pub run_id: TurnRunId,
    pub checkpoint_id: &'a TurnCheckpointId,
}

/// Evidence request for a blocked loop exit.
#[derive(Debug, Clone)]
pub struct BlockedEvidenceRequest<'a> {
    pub scope: &'a TurnScope,
    pub turn_id: TurnId,
    pub run_id: TurnRunId,
    pub blocked: &'a LoopBlocked,
}

/// Evidence request for a failed loop exit.
#[derive(Debug, Clone)]
pub struct FailureEvidenceRequest<'a> {
    pub scope: &'a TurnScope,
    pub turn_id: TurnId,
    pub run_id: TurnRunId,
    pub failed: &'a LoopFailed,
}

/// Read-only durable evidence port used to validate driver-owned claims.
#[async_trait]
pub trait LoopExitEvidencePort: Send + Sync {
    async fn verify_completion_refs(
        &self,
        request: CompletionEvidenceRequest<'_>,
    ) -> Result<bool, TurnError>;

    async fn verify_final_checkpoint(
        &self,
        request: FinalCheckpointEvidenceRequest<'_>,
    ) -> Result<bool, TurnError>;

    async fn verify_blocked_evidence(
        &self,
        request: BlockedEvidenceRequest<'_>,
    ) -> Result<bool, TurnError>;

    async fn verify_failure_evidence(
        &self,
        request: FailureEvidenceRequest<'_>,
    ) -> Result<bool, TurnError>;

    async fn is_cancellation_observed(
        &self,
        scope: &TurnScope,
        turn_id: TurnId,
        run_id: TurnRunId,
    ) -> Result<bool, TurnError>;

    async fn latest_checkpoint_kind(
        &self,
        scope: &TurnScope,
        turn_id: TurnId,
        run_id: TurnRunId,
    ) -> Result<Option<LoopCheckpointKind>, TurnError>;
}

/// Trusted loop-exit applier used by `TurnRunnerWorker`.
pub struct LoopExitApplier {
    transition_port: Arc<dyn TurnRunTransitionPort>,
    evidence_port: Arc<dyn LoopExitEvidencePort>,
}

impl LoopExitApplier {
    pub fn new(
        transition_port: Arc<dyn TurnRunTransitionPort>,
        evidence_port: Arc<dyn LoopExitEvidencePort>,
    ) -> Self {
        Self {
            transition_port,
            evidence_port,
        }
    }

    /// Derive policy from durable evidence, validate the exit, and apply the
    /// validated transition under the claimed run's lease.
    pub async fn apply(
        &self,
        claimed: &ClaimedTurnRun,
        exit: LoopExit,
    ) -> Result<TurnRunState, TurnError> {
        let policy = self.derive_policy(claimed, &exit).await?;
        let decision = exit.validate(policy);
        self.transition_port
            .apply_validated_loop_exit(ApplyValidatedLoopExitRequest {
                run_id: claimed.state.run_id,
                runner_id: claimed.runner_id,
                lease_token: claimed.lease_token,
                mapping: decision.mapping,
            })
            .await
    }

    async fn derive_policy(
        &self,
        claimed: &ClaimedTurnRun,
        exit: &LoopExit,
    ) -> Result<LoopExitValidationPolicy, TurnError> {
        let scope = &claimed.state.scope;
        let turn_id = claimed.state.turn_id;
        let run_id = claimed.state.run_id;
        let profile = &claimed.resolved_run_profile;
        let mut policy = LoopExitValidationPolicy {
            require_final_checkpoint: profile.checkpoint_policy.require_final_checkpoint,
            allow_no_reply_completion: profile.checkpoint_policy.allow_no_reply_completion,
            final_checkpoint_verified: false,
            host_cancellation_observed: false,
            invalid_handling: self.invalid_handling(scope, turn_id, run_id).await?,
            completion_refs_verified: false,
            blocked_evidence_verified: false,
            failure_evidence_verified: false,
        };

        match exit {
            LoopExit::Completed(completed) => {
                policy.completion_refs_verified = self
                    .evidence_port
                    .verify_completion_refs(CompletionEvidenceRequest {
                        scope,
                        turn_id,
                        run_id,
                        reply_message_refs: &completed.reply_message_refs,
                        result_refs: &completed.result_refs,
                    })
                    .await?;
                policy.final_checkpoint_verified = self
                    .verify_terminal_final_checkpoint(
                        scope,
                        turn_id,
                        run_id,
                        profile,
                        completed.final_checkpoint_id.as_ref(),
                    )
                    .await?;
            }
            LoopExit::Blocked(blocked) => {
                policy.blocked_evidence_verified = self
                    .evidence_port
                    .verify_blocked_evidence(BlockedEvidenceRequest {
                        scope,
                        turn_id,
                        run_id,
                        blocked,
                    })
                    .await?;
            }
            LoopExit::Cancelled(cancelled) => {
                policy.host_cancellation_observed = self
                    .evidence_port
                    .is_cancellation_observed(scope, turn_id, run_id)
                    .await?;
                policy.final_checkpoint_verified = self
                    .verify_terminal_final_checkpoint(
                        scope,
                        turn_id,
                        run_id,
                        profile,
                        cancelled.checkpoint_id.as_ref(),
                    )
                    .await?;
            }
            LoopExit::Failed(failed) => {
                policy.failure_evidence_verified = self
                    .evidence_port
                    .verify_failure_evidence(FailureEvidenceRequest {
                        scope,
                        turn_id,
                        run_id,
                        failed,
                    })
                    .await?;
                policy.final_checkpoint_verified = self
                    .verify_terminal_final_checkpoint(
                        scope,
                        turn_id,
                        run_id,
                        profile,
                        failed.checkpoint_id.as_ref(),
                    )
                    .await?;
            }
        }

        Ok(policy)
    }

    async fn verify_terminal_final_checkpoint(
        &self,
        scope: &TurnScope,
        turn_id: TurnId,
        run_id: TurnRunId,
        profile: &ResolvedRunProfile,
        checkpoint_id: Option<&TurnCheckpointId>,
    ) -> Result<bool, TurnError> {
        if !profile.checkpoint_policy.require_final_checkpoint {
            return Ok(true);
        }
        let Some(checkpoint_id) = checkpoint_id else {
            return Ok(false);
        };
        self.evidence_port
            .verify_final_checkpoint(FinalCheckpointEvidenceRequest {
                scope,
                turn_id,
                run_id,
                checkpoint_id,
            })
            .await
    }

    async fn invalid_handling(
        &self,
        scope: &TurnScope,
        turn_id: TurnId,
        run_id: TurnRunId,
    ) -> Result<LoopExitInvalidHandling, TurnError> {
        match self
            .evidence_port
            .latest_checkpoint_kind(scope, turn_id, run_id)
            .await?
        {
            Some(
                LoopCheckpointKind::BeforeSideEffect
                | LoopCheckpointKind::BeforeBlock
                | LoopCheckpointKind::Final,
            ) => Ok(LoopExitInvalidHandling::RecoveryRequired),
            Some(LoopCheckpointKind::BeforeModel) | None => {
                Ok(LoopExitInvalidHandling::FailTerminal)
            }
        }
    }
}

/// Strict test/local evidence port. Defaults to distrust everything.
#[derive(Debug, Clone)]
pub struct InMemoryLoopExitEvidencePort {
    completion_refs_verified: bool,
    final_checkpoint_verified: bool,
    blocked_evidence_verified: bool,
    failure_evidence_verified: bool,
    cancellation_observed: bool,
    latest_checkpoint_kind: Option<LoopCheckpointKind>,
}

impl InMemoryLoopExitEvidencePort {
    pub fn new() -> Self {
        Self {
            completion_refs_verified: false,
            final_checkpoint_verified: false,
            blocked_evidence_verified: false,
            failure_evidence_verified: false,
            cancellation_observed: false,
            latest_checkpoint_kind: None,
        }
    }

    pub fn all_verified() -> Self {
        Self::new()
            .with_completion_refs_verified(true)
            .with_final_checkpoint_verified(true)
            .with_blocked_evidence_verified(true)
            .with_failure_evidence_verified(true)
            .with_cancellation_observed(true)
    }

    pub fn with_completion_refs_verified(mut self, verified: bool) -> Self {
        self.completion_refs_verified = verified;
        self
    }

    pub fn with_final_checkpoint_verified(mut self, verified: bool) -> Self {
        self.final_checkpoint_verified = verified;
        self
    }

    pub fn with_blocked_evidence_verified(mut self, verified: bool) -> Self {
        self.blocked_evidence_verified = verified;
        self
    }

    pub fn with_failure_evidence_verified(mut self, verified: bool) -> Self {
        self.failure_evidence_verified = verified;
        self
    }

    pub fn with_cancellation_observed(mut self, observed: bool) -> Self {
        self.cancellation_observed = observed;
        self
    }

    pub fn with_latest_checkpoint_kind(mut self, kind: Option<LoopCheckpointKind>) -> Self {
        self.latest_checkpoint_kind = kind;
        self
    }
}

impl Default for InMemoryLoopExitEvidencePort {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LoopExitEvidencePort for InMemoryLoopExitEvidencePort {
    async fn verify_completion_refs(
        &self,
        _request: CompletionEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        Ok(self.completion_refs_verified)
    }

    async fn verify_final_checkpoint(
        &self,
        _request: FinalCheckpointEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        Ok(self.final_checkpoint_verified)
    }

    async fn verify_blocked_evidence(
        &self,
        _request: BlockedEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        Ok(self.blocked_evidence_verified)
    }

    async fn verify_failure_evidence(
        &self,
        _request: FailureEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        Ok(self.failure_evidence_verified)
    }

    async fn is_cancellation_observed(
        &self,
        _scope: &TurnScope,
        _turn_id: TurnId,
        _run_id: TurnRunId,
    ) -> Result<bool, TurnError> {
        Ok(self.cancellation_observed)
    }

    async fn latest_checkpoint_kind(
        &self,
        _scope: &TurnScope,
        _turn_id: TurnId,
        _run_id: TurnRunId,
    ) -> Result<Option<LoopCheckpointKind>, TurnError> {
        Ok(self.latest_checkpoint_kind)
    }
}

/// Durable text/checkpoint-backed evidence adapter for the current Reborn
/// text-only host. Capability-result and gate/process evidence deliberately
/// remain untrusted until dedicated durable stores are wired.
pub struct ThreadCheckpointLoopExitEvidencePort<S>
where
    S: SessionThreadService + ?Sized,
{
    thread_service: Arc<S>,
    loop_checkpoint_store: Arc<dyn ironclaw_turns::LoopCheckpointStore>,
}

impl<S> ThreadCheckpointLoopExitEvidencePort<S>
where
    S: SessionThreadService + ?Sized,
{
    pub fn new(
        thread_service: Arc<S>,
        loop_checkpoint_store: Arc<dyn ironclaw_turns::LoopCheckpointStore>,
    ) -> Self {
        Self {
            thread_service,
            loop_checkpoint_store,
        }
    }
}

#[async_trait]
impl<S> LoopExitEvidencePort for ThreadCheckpointLoopExitEvidencePort<S>
where
    S: SessionThreadService + ?Sized + Send + Sync,
{
    async fn verify_completion_refs(
        &self,
        request: CompletionEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        if !request.result_refs.is_empty() {
            return Ok(false);
        }
        if request.reply_message_refs.is_empty() {
            return Ok(true);
        }
        let thread_scope = thread_scope_from_turn_scope(request.scope)?;
        let history = self
            .thread_service
            .list_thread_history(ThreadHistoryRequest {
                scope: thread_scope,
                thread_id: request.scope.thread_id.clone(),
            })
            .await
            .map_err(|error| TurnError::Unavailable {
                reason: error.to_string(),
            })?;
        let expected_run_id = request.run_id.to_string();
        Ok(request.reply_message_refs.iter().all(|message_ref| {
            let Some(message_id) = message_id_from_ref(message_ref) else {
                return false;
            };
            history.messages.iter().any(|message| {
                message.message_id == message_id
                    && message.status == MessageStatus::Finalized
                    && message.turn_run_id.as_deref() == Some(expected_run_id.as_str())
            })
        }))
    }

    async fn verify_final_checkpoint(
        &self,
        request: FinalCheckpointEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        let checkpoint = self
            .loop_checkpoint_store
            .get_loop_checkpoint(ironclaw_turns::GetLoopCheckpointRequest {
                scope: request.scope.clone(),
                turn_id: request.turn_id,
                run_id: request.run_id,
                checkpoint_id: *request.checkpoint_id,
            })
            .await?;
        Ok(checkpoint
            .map(|record| record.kind == LoopCheckpointKind::Final)
            .unwrap_or(false))
    }

    async fn verify_blocked_evidence(
        &self,
        _request: BlockedEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        // A BeforeBlock checkpoint alone is not sufficient: #3424 requires a
        // durable pending gate/process ref. The current text-only adapter has
        // no gate/process outcome store, so it must fail closed without doing
        // unrelated checkpoint I/O.
        Ok(false)
    }

    async fn verify_failure_evidence(
        &self,
        _request: FailureEvidenceRequest<'_>,
    ) -> Result<bool, TurnError> {
        // Failure exits require durable diagnostic evidence before trusting the
        // driver-supplied failure kind. The text-only adapter does not yet own
        // that diagnostics store, so it fails closed.
        Ok(false)
    }

    async fn is_cancellation_observed(
        &self,
        _scope: &TurnScope,
        _turn_id: TurnId,
        _run_id: TurnRunId,
    ) -> Result<bool, TurnError> {
        Ok(false)
    }

    async fn latest_checkpoint_kind(
        &self,
        _scope: &TurnScope,
        _turn_id: TurnId,
        _run_id: TurnRunId,
    ) -> Result<Option<LoopCheckpointKind>, TurnError> {
        // This adapter cannot query the latest checkpoint yet. Assume side
        // effects may have happened so invalid exits recover instead of
        // terminally failing a partially-applied run.
        Ok(Some(LoopCheckpointKind::BeforeSideEffect))
    }
}

fn thread_scope_from_turn_scope(scope: &TurnScope) -> Result<ThreadScope, TurnError> {
    // `ironclaw_threads::ThreadScope` is currently agent-scoped. Reject
    // agentless Reborn turns explicitly until the thread store grows an
    // agentless scope representation.
    let Some(agent_id) = scope.agent_id.clone() else {
        return Err(TurnError::InvalidRequest {
            reason: "thread checkpoint loop-exit evidence requires agent-scoped turn scope"
                .to_string(),
        });
    };

    Ok(ThreadScope {
        tenant_id: scope.tenant_id.clone(),
        agent_id,
        project_id: scope.project_id.clone(),
        owner_user_id: None,
        mission_id: None,
    })
}

fn message_id_from_ref(message_ref: &LoopMessageRef) -> Option<ThreadMessageId> {
    let raw = message_ref.as_str().strip_prefix("msg:")?;
    ThreadMessageId::parse(raw).ok()
}

#[cfg(test)]
mod tests;
