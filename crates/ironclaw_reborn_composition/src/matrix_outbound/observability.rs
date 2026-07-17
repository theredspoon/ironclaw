use super::*;

pub(crate) fn record_contract_error(error: &MatrixOutboundContractError) {
    tracing::debug!(
        target = "ironclaw::reborn::matrix_outbound",
        error = %error,
        "matrix outbound contract error mapped to sanitized delivery error"
    );
}

pub(crate) fn record_retry_worker_task_failed(error: &tokio::task::JoinError) {
    tracing::debug!(?error, "matrix retry worker task join failed");
}

pub(crate) fn record_retry_worker_shutdown_timeout(timeout: Duration) {
    tracing::debug!(
        ?timeout,
        "matrix retry worker did not stop before shutdown timeout; aborting"
    );
}

pub(crate) fn record_retry_worker_task_panicked(error: &tokio::task::JoinError) {
    tracing::debug!(?error, "aborted matrix retry worker task panicked");
}

pub(crate) fn record_retry_worker_tick_completed(report: &MatrixRetryWorkerTickReport) {
    tracing::debug!(
        scopes_scanned = report.scopes_scanned,
        due_schedules = report.due_schedules,
        attempted = report.attempted,
        delivered = report.delivered,
        retry_scheduled = report.retry_scheduled,
        skipped = report.skipped,
        failed = report.failed,
        "matrix retry worker tick completed"
    );
}

pub(crate) fn record_retry_worker_tick_failed(error: &MatrixOutboundContractError) {
    tracing::debug!(?error, "matrix retry worker tick failed");
}

pub(crate) fn record_retry_attempt_failed(
    delivery_id: OutboundDeliveryId,
    reason: DeliveryReasonCode,
) {
    tracing::debug!(
        delivery_id = %delivery_id,
        reason = ?reason,
        "matrix retry worker attempt failed"
    );
}
