use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MatrixObservabilityEvent {
    SendAttemptStarted {
        delivery_id: OutboundDeliveryId,
        attempt_number: u32,
        command_kind: MatrixCommandKind,
        homeserver_origin_fingerprint: String,
        room_fingerprint: String,
    },
    HttpResponseClassified {
        delivery_id: OutboundDeliveryId,
        attempt_number: u32,
        http_status: u16,
        status_family: Option<HttpStatusFamily>,
        matrix_errcode: Option<MatrixErrcode>,
        reason: Option<DeliveryReasonCode>,
        latency_ms: u64,
        homeserver_origin_fingerprint: String,
        room_fingerprint: String,
    },
    DeliveryStatusUpdated {
        delivery_id: OutboundDeliveryId,
        status: MatrixTerminalStatus,
        reason: Option<DeliveryReasonCode>,
    },
}

pub(crate) fn record_send_attempt_started(
    attempt: &DeliveryAttemptContext,
    command_kind: MatrixCommandKind,
    metadata: &MatrixRouteMetadata,
) {
    let event = MatrixObservabilityEvent::SendAttemptStarted {
        delivery_id: attempt.delivery_id,
        attempt_number: attempt.attempt_number,
        command_kind,
        homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint.clone(),
        room_fingerprint: metadata.room_fingerprint.clone(),
    };
    tracing::debug!(
        delivery_id = %attempt.delivery_id,
        attempt_number = attempt.attempt_number,
        command_kind = ?command_kind,
        homeserver_origin_fingerprint = %metadata.homeserver_origin_fingerprint,
        room_fingerprint = %metadata.room_fingerprint,
        "matrix send attempt started"
    );
    record_test_event(event);
}

pub(crate) fn record_http_response_classified(
    attempt: &DeliveryAttemptContext,
    metadata: &MatrixRouteMetadata,
    http_status: u16,
    status_family: Option<HttpStatusFamily>,
    matrix_errcode: Option<MatrixErrcode>,
    reason: Option<DeliveryReasonCode>,
    latency_ms: u64,
) {
    let event = MatrixObservabilityEvent::HttpResponseClassified {
        delivery_id: attempt.delivery_id,
        attempt_number: attempt.attempt_number,
        http_status,
        status_family,
        matrix_errcode,
        reason,
        latency_ms,
        homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint.clone(),
        room_fingerprint: metadata.room_fingerprint.clone(),
    };
    tracing::debug!(
        delivery_id = %attempt.delivery_id,
        attempt_number = attempt.attempt_number,
        http_status,
        status_family = ?status_family,
        matrix_errcode = ?matrix_errcode,
        reason = ?reason,
        latency_ms,
        homeserver_origin_fingerprint = %metadata.homeserver_origin_fingerprint,
        room_fingerprint = %metadata.room_fingerprint,
        "matrix HTTP response classified"
    );
    record_test_event(event);
}

pub(crate) fn record_delivery_status_updated(
    delivery_id: OutboundDeliveryId,
    status: MatrixTerminalStatus,
    reason: Option<DeliveryReasonCode>,
) {
    let event = MatrixObservabilityEvent::DeliveryStatusUpdated {
        delivery_id,
        status,
        reason,
    };
    tracing::debug!(
        delivery_id = %delivery_id,
        status = ?status,
        reason = ?reason,
        "matrix delivery status updated"
    );
    record_test_event(event);
}

pub(crate) fn record_contract_error(error: &MatrixOutboundContractError) {
    tracing::debug!(
        target = "ironclaw::reborn::matrix_outbound",
        error = %error,
        "matrix outbound contract error mapped to sanitized delivery error"
    );
}

#[cfg(test)]
fn record_test_event(event: MatrixObservabilityEvent) {
    test_capture::record(event);
}

#[cfg(not(test))]
fn record_test_event(_event: MatrixObservabilityEvent) {}

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

#[cfg(test)]
pub(crate) mod test_capture {
    use super::MatrixObservabilityEvent;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    static NEXT_CAPTURE_ID: AtomicU64 = AtomicU64::new(1);
    static CAPTURES: OnceLock<Mutex<Vec<ActiveCapture>>> = OnceLock::new();

    #[derive(Debug)]
    struct ActiveCapture {
        id: u64,
        events: Vec<MatrixObservabilityEvent>,
    }

    #[derive(Debug)]
    pub(crate) struct MatrixObservabilityCapture {
        id: u64,
    }

    pub(crate) fn start() -> MatrixObservabilityCapture {
        let id = NEXT_CAPTURE_ID.fetch_add(1, Ordering::Relaxed);
        captures()
            .lock()
            .expect("Matrix observability capture lock")
            .push(ActiveCapture {
                id,
                events: Vec::new(),
            });
        MatrixObservabilityCapture { id }
    }

    impl MatrixObservabilityCapture {
        pub(crate) fn finish(self) -> Vec<MatrixObservabilityEvent> {
            let mut captures = captures()
                .lock()
                .expect("Matrix observability capture lock");
            let Some(index) = captures.iter().position(|capture| capture.id == self.id) else {
                return Vec::new();
            };
            captures.remove(index).events
        }
    }

    pub(super) fn record(event: MatrixObservabilityEvent) {
        let mut captures = captures()
            .lock()
            .expect("Matrix observability capture lock");
        for capture in captures.iter_mut() {
            capture.events.push(event.clone());
        }
    }

    fn captures() -> &'static Mutex<Vec<ActiveCapture>> {
        CAPTURES.get_or_init(|| Mutex::new(Vec::new()))
    }
}
