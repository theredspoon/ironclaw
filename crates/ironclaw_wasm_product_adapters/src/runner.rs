//! Native ProductAdapter runner.
//!
//! `NativeProductAdapterRunner` is the integration point that turns a single
//! webhook request into the full Reborn pipeline:
//!
//! 1. Authenticate the protocol payload with a [`WebhookAuthVerifier`].
//! 2. On success, mint a `Verified` evidence via the public `mark_*_verified`
//!    helpers in `ironclaw_product_adapters::auth`.
//! 3. Hand the verified evidence + raw payload to the adapter's
//!    [`ironclaw_product_adapters::ProductAdapter::parse_inbound`].
//! 4. Forward the resulting envelope to the [`ironclaw_product_adapters::ProductWorkflow`]
//!    facade and return the structured outcome.
//!
//! The runner is deliberately not wasmtime-bound — the v2 component-model
//! plumbing lands in a follow-up. Telegram v2 today implements
//! `ProductAdapter` natively in Rust; the runner enforces the same auth /
//! dedupe / facade-only contract a wasmtime instance would.

use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use ironclaw_product_adapters::auth::{
    mark_bearer_token_verified, mark_request_signature_verified, mark_session_verified,
    mark_shared_secret_header_verified,
};
use ironclaw_product_adapters::{
    ProductAdapter, ProductAdapterError, ProductInboundAck, ProductWorkflow, ProtocolAuthEvidence,
    ProtocolAuthFailure,
};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::auth_verifier::{
    HmacWebhookAuth, SharedSecretHeaderAuth, VerificationOutcome, WebhookAuthVerifier,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RunnerError {
    #[error("webhook authentication failed: {failure}")]
    AuthenticationFailed { failure: ProtocolAuthFailure },
    #[error("native adapter panicked while parsing inbound payload")]
    AdapterPanicked,
    #[error("product workflow panicked while accepting inbound payload")]
    WorkflowPanicked,
    #[error("product workflow timed out after {timeout:?}")]
    WorkflowTimeout { timeout: Duration },
    #[error("too many in-flight webhook requests ({max_in_flight})")]
    TooManyInFlight { max_in_flight: usize },
    #[error("product workflow task failed before producing an outcome")]
    WorkflowJoinFailed,
    #[error(transparent)]
    Adapter(#[from] ProductAdapterError),
}

impl RunnerError {
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, RunnerError::AuthenticationFailed { .. })
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            RunnerError::AuthenticationFailed { .. } | RunnerError::AdapterPanicked => false,
            RunnerError::WorkflowPanicked
            | RunnerError::WorkflowTimeout { .. }
            | RunnerError::TooManyInFlight { .. }
            | RunnerError::WorkflowJoinFailed => true,
            RunnerError::Adapter(err) => err.is_retryable(),
        }
    }
}

/// What the protocol layer should do with the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookProcessOutcome {
    /// Auth succeeded, adapter parsed an envelope, workflow accepted it.
    Acknowledged { ack: ProductInboundAck },
    /// Auth succeeded but the adapter chose to drop the message (group
    /// ambient, edited message, unsupported event kind, ...). The protocol
    /// layer should respond 200 OK no-op.
    NoOp,
}

/// Webhook auth strategy.
pub enum WebhookAuth {
    Hmac(HmacWebhookAuth),
    SharedSecretHeader(SharedSecretHeaderAuth),
}

impl WebhookAuth {
    fn verify(&self, headers: &http::HeaderMap, body: &[u8]) -> VerificationOutcome {
        match self {
            WebhookAuth::Hmac(v) => v.verify(headers, body),
            WebhookAuth::SharedSecretHeader(v) => v.verify(headers, body),
        }
    }

    fn mint_evidence(&self, subject: String) -> ProtocolAuthEvidence {
        match self {
            WebhookAuth::Hmac(v) => mark_request_signature_verified(
                v.signature_header.clone(),
                Some(v.timestamp_header.clone()),
                subject,
            ),
            WebhookAuth::SharedSecretHeader(v) => {
                mark_shared_secret_header_verified(v.header_name.clone(), subject)
            }
        }
    }
}

/// Convenience constructor for synchronous-API or CLI auth bridges.
pub fn evidence_from_session_subject(subject: impl Into<String>) -> ProtocolAuthEvidence {
    mark_session_verified("ironclaw_session", subject)
}

pub fn evidence_from_bearer_subject(subject: impl Into<String>) -> ProtocolAuthEvidence {
    mark_bearer_token_verified(subject)
}

pub const DEFAULT_WEBHOOK_WORKFLOW_TIMEOUT: Duration = Duration::from_secs(55);
pub const DEFAULT_MAX_IN_FLIGHT_WEBHOOKS: usize = 64;
const DEFAULT_MAX_IN_FLIGHT_WEBHOOKS_NONZERO: NonZeroUsize =
    match NonZeroUsize::new(DEFAULT_MAX_IN_FLIGHT_WEBHOOKS) {
        Some(value) => value,
        None => NonZeroUsize::MIN,
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeProductAdapterRunnerConfig {
    pub workflow_timeout: Duration,
    pub max_in_flight: NonZeroUsize,
}

impl NativeProductAdapterRunnerConfig {
    pub fn new(workflow_timeout: Duration, max_in_flight: NonZeroUsize) -> Self {
        Self {
            workflow_timeout,
            max_in_flight,
        }
    }

    pub fn with_workflow_timeout(mut self, workflow_timeout: Duration) -> Self {
        self.workflow_timeout = workflow_timeout;
        self
    }

    pub fn with_max_in_flight(mut self, max_in_flight: NonZeroUsize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.get()
    }
}

impl Default for NativeProductAdapterRunnerConfig {
    fn default() -> Self {
        Self {
            workflow_timeout: DEFAULT_WEBHOOK_WORKFLOW_TIMEOUT,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_WEBHOOKS_NONZERO,
        }
    }
}

pub struct NativeProductAdapterRunner {
    adapter: Arc<dyn ProductAdapter>,
    workflow: Arc<dyn ProductWorkflow>,
    auth: WebhookAuth,
    config: NativeProductAdapterRunnerConfig,
    admission: Arc<Semaphore>,
}

impl NativeProductAdapterRunner {
    pub fn new(
        adapter: Arc<dyn ProductAdapter>,
        workflow: Arc<dyn ProductWorkflow>,
        auth: WebhookAuth,
    ) -> Self {
        Self::with_config(
            adapter,
            workflow,
            auth,
            NativeProductAdapterRunnerConfig::default(),
        )
    }

    pub fn with_config(
        adapter: Arc<dyn ProductAdapter>,
        workflow: Arc<dyn ProductWorkflow>,
        auth: WebhookAuth,
        config: NativeProductAdapterRunnerConfig,
    ) -> Self {
        Self {
            adapter,
            workflow,
            auth,
            admission: Arc::new(Semaphore::new(config.max_in_flight())),
            config,
        }
    }

    pub fn config(&self) -> NativeProductAdapterRunnerConfig {
        self.config
    }

    pub async fn process_webhook(
        &self,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<WebhookProcessOutcome, RunnerError> {
        let evidence = match self.auth.verify(headers, body) {
            VerificationOutcome::Verified { subject } => self.auth.mint_evidence(subject),
            VerificationOutcome::Failed { failure } => {
                return Err(RunnerError::AuthenticationFailed { failure });
            }
        };
        let _permit = self.admission.clone().try_acquire_owned().map_err(|_| {
            RunnerError::TooManyInFlight {
                max_in_flight: self.config.max_in_flight(),
            }
        })?;
        let parse_result = catch_unwind(AssertUnwindSafe(|| {
            self.adapter.parse_inbound(body, evidence)
        }));
        let Some(envelope) = (match parse_result {
            Ok(result) => result?,
            Err(_) => return Err(RunnerError::AdapterPanicked),
        }) else {
            return Ok(WebhookProcessOutcome::NoOp);
        };
        let workflow = Arc::clone(&self.workflow);
        let mut workflow_task =
            tokio::spawn(async move { workflow.accept_inbound(envelope).await });
        let ack = match tokio::time::timeout(self.config.workflow_timeout, &mut workflow_task).await
        {
            Ok(Ok(result)) => result?,
            Ok(Err(join_error)) if join_error.is_panic() => {
                return Err(RunnerError::WorkflowPanicked);
            }
            Ok(Err(_)) => return Err(RunnerError::WorkflowJoinFailed),
            Err(_) => {
                workflow_task.abort();
                return Err(RunnerError::WorkflowTimeout {
                    timeout: self.config.workflow_timeout,
                });
            }
        };
        Ok(WebhookProcessOutcome::Acknowledged { ack })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use http::HeaderMap;
    use http::header::HeaderValue;
    use ironclaw_product_adapters::auth::VerifiedAuthClaim;
    use ironclaw_product_adapters::capabilities::ProductAdapterCapabilities;
    use ironclaw_product_adapters::external::{
        ExternalActorRef, ExternalConversationRef, ExternalEventId,
    };
    use ironclaw_product_adapters::identity::{
        AdapterInstallationId, ProductAdapterId, ProductSurfaceKind,
    };
    use ironclaw_product_adapters::{
        AuthRequirement, ProductInboundEnvelope, ProductInboundPayload, ProductOutboundEnvelope,
        ProtocolHttpEgress,
    };
    use tokio::sync::Notify;

    use super::*;

    struct StaticAdapter {
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
        capabilities: ProductAdapterCapabilities,
        envelope: ProductInboundEnvelope,
    }

    impl StaticAdapter {
        fn new(envelope: ProductInboundEnvelope) -> Self {
            Self {
                adapter_id: ProductAdapterId::new("telegram_v2").expect("valid"),
                installation_id: AdapterInstallationId::new("install_alpha").expect("valid"),
                capabilities: ProductAdapterCapabilities::empty(),
                envelope,
            }
        }
    }

    #[async_trait]
    impl ProductAdapter for StaticAdapter {
        fn adapter_id(&self) -> &ProductAdapterId {
            &self.adapter_id
        }

        fn installation_id(&self) -> &AdapterInstallationId {
            &self.installation_id
        }

        fn surface_kind(&self) -> ProductSurfaceKind {
            ProductSurfaceKind::ExternalChannel
        }

        fn capabilities(&self) -> &ProductAdapterCapabilities {
            &self.capabilities
        }

        fn parse_inbound(
            &self,
            _raw_payload: &[u8],
            _auth_evidence: ProtocolAuthEvidence,
        ) -> Result<Option<ProductInboundEnvelope>, ProductAdapterError> {
            Ok(Some(self.envelope.clone()))
        }

        async fn render_outbound(
            &self,
            _envelope: ProductOutboundEnvelope,
            _egress: &dyn ProtocolHttpEgress,
        ) -> Result<(), ProductAdapterError> {
            Ok(())
        }
    }

    struct PanicAdapter {
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
        capabilities: ProductAdapterCapabilities,
    }

    impl PanicAdapter {
        fn new() -> Self {
            Self {
                adapter_id: ProductAdapterId::new("telegram_v2").expect("valid"),
                installation_id: AdapterInstallationId::new("install_alpha").expect("valid"),
                capabilities: ProductAdapterCapabilities::empty(),
            }
        }
    }

    #[async_trait]
    impl ProductAdapter for PanicAdapter {
        fn adapter_id(&self) -> &ProductAdapterId {
            &self.adapter_id
        }

        fn installation_id(&self) -> &AdapterInstallationId {
            &self.installation_id
        }

        fn surface_kind(&self) -> ProductSurfaceKind {
            ProductSurfaceKind::ExternalChannel
        }

        fn capabilities(&self) -> &ProductAdapterCapabilities {
            &self.capabilities
        }

        fn parse_inbound(
            &self,
            _raw_payload: &[u8],
            _auth_evidence: ProtocolAuthEvidence,
        ) -> Result<Option<ProductInboundEnvelope>, ProductAdapterError> {
            panic!("adapter parse panic must be contained")
        }

        async fn render_outbound(
            &self,
            _envelope: ProductOutboundEnvelope,
            _egress: &dyn ProtocolHttpEgress,
        ) -> Result<(), ProductAdapterError> {
            Ok(())
        }
    }

    struct AckWorkflow;

    #[async_trait]
    impl ProductWorkflow for AckWorkflow {
        async fn accept_inbound(
            &self,
            _envelope: ProductInboundEnvelope,
        ) -> Result<ProductInboundAck, ProductAdapterError> {
            Ok(ProductInboundAck::NoOp)
        }
    }

    struct PendingWorkflow;

    #[async_trait]
    impl ProductWorkflow for PendingWorkflow {
        async fn accept_inbound(
            &self,
            _envelope: ProductInboundEnvelope,
        ) -> Result<ProductInboundAck, ProductAdapterError> {
            std::future::pending().await
        }
    }

    struct PanicWorkflow;

    #[async_trait]
    impl ProductWorkflow for PanicWorkflow {
        async fn accept_inbound(
            &self,
            _envelope: ProductInboundEnvelope,
        ) -> Result<ProductInboundAck, ProductAdapterError> {
            panic!("workflow panic must be contained")
        }
    }

    struct BlockingWorkflow {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ProductWorkflow for BlockingWorkflow {
        async fn accept_inbound(
            &self,
            _envelope: ProductInboundEnvelope,
        ) -> Result<ProductInboundAck, ProductAdapterError> {
            self.entered.notify_waiters();
            self.release.notified().await;
            Ok(ProductInboundAck::NoOp)
        }
    }

    fn sample_envelope() -> ProductInboundEnvelope {
        ProductInboundEnvelope {
            adapter_id: ProductAdapterId::new("telegram_v2").expect("valid"),
            installation_id: AdapterInstallationId::new("install_alpha").expect("valid"),
            external_event_id: ExternalEventId::new("update:42").expect("valid"),
            external_actor_ref: ExternalActorRef::new("telegram_user", "777", None).expect("valid"),
            external_conversation_ref: ExternalConversationRef::new(
                None,
                "12345",
                Some("topic-7"),
                Some("msg-100"),
            )
            .expect("valid"),
            auth_claim: VerifiedAuthClaim {
                requirement: AuthRequirement::SharedSecretHeader {
                    header_name: "X-Telegram-Bot-Api-Secret-Token".into(),
                },
                subject: "telegram_install_alpha".into(),
            },
            received_at: chrono::Utc::now(),
            payload: ProductInboundPayload::NoOp,
        }
    }

    fn shared_secret_auth() -> WebhookAuth {
        WebhookAuth::SharedSecretHeader(SharedSecretHeaderAuth {
            header_name: "X-Test-Secret".into(),
            expected_secret: "topsecret".into(),
            subject: "telegram_install_alpha".into(),
        })
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Test-Secret", HeaderValue::from_static("topsecret"));
        headers
    }

    fn test_config(max_in_flight: usize, timeout: Duration) -> NativeProductAdapterRunnerConfig {
        NativeProductAdapterRunnerConfig::new(
            timeout,
            std::num::NonZeroUsize::new(max_in_flight).expect("nonzero"),
        )
    }

    #[tokio::test]
    async fn process_webhook_times_out_slow_workflow() {
        let runner = NativeProductAdapterRunner::with_config(
            Arc::new(StaticAdapter::new(sample_envelope())),
            Arc::new(PendingWorkflow),
            shared_secret_auth(),
            test_config(1, Duration::from_millis(5)),
        );
        let err = runner
            .process_webhook(&auth_headers(), b"{}")
            .await
            .expect_err("slow workflow should time out");
        assert!(matches!(err, RunnerError::WorkflowTimeout { .. }));
    }

    #[tokio::test]
    async fn process_webhook_rejects_when_max_in_flight_reached() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let runner = Arc::new(NativeProductAdapterRunner::with_config(
            Arc::new(StaticAdapter::new(sample_envelope())),
            Arc::new(BlockingWorkflow {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
            shared_secret_auth(),
            test_config(1, Duration::from_secs(1)),
        ));
        let first_runner = Arc::clone(&runner);
        let first_headers = auth_headers();
        let first =
            tokio::spawn(async move { first_runner.process_webhook(&first_headers, b"{}").await });
        entered.notified().await;

        let err = runner
            .process_webhook(&auth_headers(), b"{}")
            .await
            .expect_err("second request should be rejected by admission control");
        assert_eq!(err, RunnerError::TooManyInFlight { max_in_flight: 1 });

        release.notify_waiters();
        first.await.expect("join").expect("first request succeeds");
    }

    #[tokio::test]
    async fn process_webhook_contains_adapter_panics() {
        let runner = NativeProductAdapterRunner::with_config(
            Arc::new(PanicAdapter::new()),
            Arc::new(AckWorkflow),
            shared_secret_auth(),
            test_config(1, Duration::from_secs(1)),
        );
        let err = runner
            .process_webhook(&auth_headers(), b"{}")
            .await
            .expect_err("adapter panic should become runner error");
        assert_eq!(err, RunnerError::AdapterPanicked);
    }

    #[tokio::test]
    async fn process_webhook_contains_workflow_panics() {
        let runner = NativeProductAdapterRunner::with_config(
            Arc::new(StaticAdapter::new(sample_envelope())),
            Arc::new(PanicWorkflow),
            shared_secret_auth(),
            test_config(1, Duration::from_secs(1)),
        );
        let err = runner
            .process_webhook(&auth_headers(), b"{}")
            .await
            .expect_err("workflow panic should become runner error");
        assert_eq!(err, RunnerError::WorkflowPanicked);
    }
}
