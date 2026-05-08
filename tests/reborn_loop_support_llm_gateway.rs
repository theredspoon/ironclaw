use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ironclaw::{
    llm::{
        CompletionRequest, CompletionResponse, FinishReason, LlmError, LlmProvider,
        ToolCompletionRequest, ToolCompletionResponse,
    },
    reborn_loop_support::{LlmModelProfilePolicy, LlmProviderModelGateway},
};
use ironclaw_loop_support::{
    HostManagedModelErrorKind, HostManagedModelGateway, HostManagedModelMessage,
    HostManagedModelMessageRole, HostManagedModelRequest,
};
use ironclaw_turns::{LoopMessageRef, run_profile::ModelProfileId};
use rust_decimal::Decimal;

#[tokio::test]
async fn gateway_calls_llm_provider_for_allowed_model_profile() {
    let provider = Arc::new(RecordingLlmProvider::reply("assistant response"));
    let policy = LlmModelProfilePolicy::new()
        .allow_model_profile(interactive_model(), Some("host-selected-model".to_string()));
    let gateway = LlmProviderModelGateway::new(provider.clone(), policy);

    let response = gateway
        .stream_model(model_request(interactive_model()))
        .await
        .unwrap();

    assert_eq!(
        response.safe_text_deltas,
        vec!["assistant response".to_string()]
    );
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model.as_deref(), Some("host-selected-model"));
    assert_eq!(
        requests[0]
            .metadata
            .get("model_profile_id")
            .map(String::as_str),
        Some("interactive_model")
    );
    assert_eq!(requests[0].messages.len(), 2);
    assert_eq!(requests[0].messages[0].content, "system instructions");
    assert_eq!(requests[0].messages[1].content, "hello model");
}

#[tokio::test]
async fn gateway_rejects_unknown_model_profile_without_calling_provider() {
    let provider = Arc::new(RecordingLlmProvider::reply("unused"));
    let gateway = LlmProviderModelGateway::new(
        provider.clone(),
        LlmModelProfilePolicy::new().allow_model_profile(interactive_model(), None),
    );

    let error = gateway
        .stream_model(model_request(ModelProfileId::new("unknown_model").unwrap()))
        .await
        .unwrap_err();

    assert_eq!(error.kind, HostManagedModelErrorKind::PolicyDenied);
    assert!(provider.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn gateway_sanitizes_provider_errors() {
    let provider = Arc::new(RecordingLlmProvider::fail(LlmError::RequestFailed {
        provider: "raw-provider".to_string(),
        reason: "RAW_PROVIDER_SECRET".to_string(),
    }));
    let gateway = LlmProviderModelGateway::new(
        provider,
        LlmModelProfilePolicy::new().allow_model_profile(interactive_model(), None),
    );

    let error = gateway
        .stream_model(model_request(interactive_model()))
        .await
        .unwrap_err();

    assert_eq!(error.kind, HostManagedModelErrorKind::Unavailable);
    assert!(!error.safe_summary.contains("RAW_PROVIDER_SECRET"));
    assert!(!format!("{error:?}").contains("RAW_PROVIDER_SECRET"));
}

fn interactive_model() -> ModelProfileId {
    ModelProfileId::new("interactive_model").unwrap()
}

fn model_request(model_profile_id: ModelProfileId) -> HostManagedModelRequest {
    HostManagedModelRequest {
        model_profile_id,
        messages: vec![
            HostManagedModelMessage {
                role: HostManagedModelMessageRole::System,
                content: "system instructions".to_string(),
                content_ref: LoopMessageRef::new("msg:11111111-1111-1111-1111-111111111111")
                    .unwrap(),
            },
            HostManagedModelMessage {
                role: HostManagedModelMessageRole::User,
                content: "hello model".to_string(),
                content_ref: LoopMessageRef::new("msg:22222222-2222-2222-2222-222222222222")
                    .unwrap(),
            },
        ],
        surface_version: None,
        run_id: "run-1".to_string(),
        turn_id: "turn-1".to_string(),
    }
}

struct RecordingLlmProvider {
    requests: Mutex<Vec<CompletionRequest>>,
    response: Mutex<Option<Result<CompletionResponse, LlmError>>>,
}

impl RecordingLlmProvider {
    fn reply(content: &str) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(Ok(CompletionResponse {
                content: content.to_string(),
                input_tokens: 1,
                output_tokens: 1,
                finish_reason: FinishReason::Stop,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
            }))),
        }
    }

    fn fail(error: LlmError) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(Err(error))),
        }
    }
}

#[async_trait]
impl LlmProvider for RecordingLlmProvider {
    fn model_name(&self) -> &str {
        "recording-model"
    }

    fn cost_per_token(&self) -> (Decimal, Decimal) {
        (Decimal::ZERO, Decimal::ZERO)
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        self.requests.lock().unwrap().push(request);
        self.response
            .lock()
            .unwrap()
            .take()
            .expect("test provider response is configured once")
    }

    async fn complete_with_tools(
        &self,
        _request: ToolCompletionRequest,
    ) -> Result<ToolCompletionResponse, LlmError> {
        Err(LlmError::RequestFailed {
            provider: "recording".to_string(),
            reason: "tool completion is not used by the loop support gateway".to_string(),
        })
    }
}
