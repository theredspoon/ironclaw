//! Root-level adapters for Reborn loop support services.
//!
//! Reborn crates define contracts and support adapters without owning raw root
//! runtime/provider handles. This module is the root composition boundary that
//! wraps the existing `src/llm` provider trait behind those contracts.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use ironclaw_loop_support::{
    HostManagedModelError, HostManagedModelErrorKind, HostManagedModelGateway,
    HostManagedModelMessage, HostManagedModelMessageRole, HostManagedModelRequest,
    HostManagedModelResponse,
};
use ironclaw_turns::run_profile::ModelProfileId;

use crate::llm::{ChatMessage, CompletionRequest, LlmError, LlmProvider};

/// Fail-closed routing policy from resolved Reborn model profile ids to the
/// host-selected provider/model envelope.
#[derive(Debug, Clone, Default)]
pub struct LlmModelProfilePolicy {
    routes: HashMap<ModelProfileId, LlmModelProfileRoute>,
}

impl LlmModelProfilePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_model_profile(
        mut self,
        model_profile_id: ModelProfileId,
        model_override: Option<String>,
    ) -> Self {
        self.routes
            .insert(model_profile_id, LlmModelProfileRoute { model_override });
        self
    }

    fn route_for(&self, model_profile_id: &ModelProfileId) -> Option<&LlmModelProfileRoute> {
        self.routes.get(model_profile_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LlmModelProfileRoute {
    model_override: Option<String>,
}

/// Host-managed model gateway backed by the root `LlmProvider` abstraction.
#[derive(Clone)]
pub struct LlmProviderModelGateway<P>
where
    P: LlmProvider + ?Sized,
{
    provider: Arc<P>,
    policy: LlmModelProfilePolicy,
}

impl<P> LlmProviderModelGateway<P>
where
    P: LlmProvider + ?Sized,
{
    pub fn new(provider: Arc<P>, policy: LlmModelProfilePolicy) -> Self {
        Self { provider, policy }
    }
}

#[async_trait]
impl<P> HostManagedModelGateway for LlmProviderModelGateway<P>
where
    P: LlmProvider + ?Sized + Send + Sync,
{
    async fn stream_model(
        &self,
        request: HostManagedModelRequest,
    ) -> Result<HostManagedModelResponse, HostManagedModelError> {
        let route = self
            .policy
            .route_for(&request.model_profile_id)
            .ok_or_else(|| {
                HostManagedModelError::safe(
                    HostManagedModelErrorKind::PolicyDenied,
                    "model profile is not permitted",
                )
            })?;
        let mut completion = CompletionRequest::new(convert_messages(request.messages)?);
        completion.model.clone_from(&route.model_override);
        completion.metadata.insert(
            "model_profile_id".to_string(),
            request.model_profile_id.as_str().to_string(),
        );
        completion
            .metadata
            .insert("turn_id".to_string(), request.turn_id);
        completion
            .metadata
            .insert("run_id".to_string(), request.run_id);

        let response = self
            .provider
            .complete(completion)
            .await
            .map_err(map_provider_error)?;
        Ok(HostManagedModelResponse::assistant_reply(response.content))
    }
}

fn convert_messages(
    messages: Vec<HostManagedModelMessage>,
) -> Result<Vec<ChatMessage>, HostManagedModelError> {
    messages
        .into_iter()
        .map(|message| match message.role {
            HostManagedModelMessageRole::System => Ok(ChatMessage::system(message.content)),
            HostManagedModelMessageRole::User => Ok(ChatMessage::user(message.content)),
            HostManagedModelMessageRole::Assistant => Ok(ChatMessage::assistant(message.content)),
        })
        .collect()
}

fn map_provider_error(error: LlmError) -> HostManagedModelError {
    match error {
        LlmError::ContextLengthExceeded { .. } => HostManagedModelError::safe(
            HostManagedModelErrorKind::BudgetExceeded,
            "model request exceeded its context budget",
        ),
        LlmError::ModelNotAvailable { .. } => HostManagedModelError::safe(
            HostManagedModelErrorKind::PolicyDenied,
            "requested model is not available through this profile",
        ),
        LlmError::AuthFailed { .. } | LlmError::SessionExpired { .. } => {
            HostManagedModelError::safe(
                HostManagedModelErrorKind::Unavailable,
                "model credentials are unavailable",
            )
        }
        _ => HostManagedModelError::safe(
            HostManagedModelErrorKind::Unavailable,
            "model service is unavailable",
        ),
    }
}
