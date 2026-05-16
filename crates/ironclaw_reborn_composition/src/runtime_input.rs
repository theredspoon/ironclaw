//! Input DTO for the assembled Reborn runtime (`build_reborn_runtime`).
//!
//! `RebornRuntimeInput` extends `RebornBuildInput` (which is substrate-only)
//! with the additional knobs needed to assemble a runnable agent:
//!
//! - **LLM configuration** (optional, behind the `root-llm-provider` feature).
//!   Used by the composition root to construct an `LlmProviderModelGateway`
//!   that satisfies the loop-support `HostManagedModelGateway` contract.
//! - **Turn-runner configuration** — poll/heartbeat intervals for the worker
//!   loop.
//!
//! The CLI builds this struct from env vars / config; it does not call into
//! `ironclaw_reborn` or `ironclaw_llm` directly.

use std::time::Duration;

use crate::input::RebornBuildInput;

/// Configuration for the host-managed LLM model gateway wired into the
/// composed Reborn runtime.
///
/// Only available when this crate is built with the `root-llm-provider`
/// feature. Mirrors `ironclaw_llm::RegistryProviderConfig` but stays in
/// composition-owned types so callers (the CLI) never name `ironclaw_llm`
/// directly.
#[cfg(feature = "root-llm-provider")]
pub const DEFAULT_LLM_REQUEST_TIMEOUT_SECS: u64 = 120;

pub const DEFAULT_TURN_RUNNER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_TURN_RUNNER_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(feature = "root-llm-provider")]
#[derive(Debug, Clone)]
pub struct RebornLlmConfig {
    /// Provider id (e.g. `"openai"`, `"anthropic"`, `"ollama"`).
    pub provider_id: String,
    /// Model id passed to the provider (e.g. `"gpt-4o-mini"`).
    pub model: String,
    /// Provider API base URL.
    pub base_url: String,
    /// API key, if the provider requires one. `None` for keyless providers
    /// like Ollama.
    pub api_key: Option<secrecy::SecretString>,
    /// API protocol identifier — maps onto
    /// `ironclaw_llm::ProviderProtocol`. Canonical values follow
    /// `ProviderProtocol`'s serde `snake_case` names:
    /// `"open_ai_completions"`, `"anthropic"`, `"ollama"`, `"deep_seek"`,
    /// `"gemini"`, `"open_router"`, `"github_copilot"`.
    pub protocol: String,
    /// Request timeout in seconds passed to the underlying HTTP client.
    pub request_timeout_secs: u64,
    /// Extra HTTP headers injected on every request.
    pub extra_headers: Vec<(String, String)>,
}

#[cfg(feature = "root-llm-provider")]
impl RebornLlmConfig {
    /// Convenience constructor for the common OpenAI Chat Completions case.
    pub fn openai_compat(
        provider_id: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: secrecy::SecretString,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            model: model.into(),
            base_url: base_url.into(),
            api_key: Some(api_key),
            protocol: "open_ai_completions".to_string(),
            request_timeout_secs: DEFAULT_LLM_REQUEST_TIMEOUT_SECS,
            extra_headers: Vec::new(),
        }
    }
}

/// Configuration for the turn-runner worker spawned by the runtime.
#[derive(Debug, Clone)]
pub struct TurnRunnerSettings {
    pub heartbeat_interval: Duration,
    pub poll_interval: Duration,
}

impl Default for TurnRunnerSettings {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_TURN_RUNNER_HEARTBEAT_INTERVAL,
            poll_interval: DEFAULT_TURN_RUNNER_POLL_INTERVAL,
        }
    }
}

/// Full input for `build_reborn_runtime` — substrate config plus the extras
/// needed to assemble a runnable Reborn agent.
#[derive(Default)]
pub struct RebornRuntimeInput {
    pub services: Option<RebornBuildInput>,
    #[cfg(feature = "root-llm-provider")]
    pub llm: Option<RebornLlmConfig>,
    pub runner: TurnRunnerSettings,
}

impl RebornRuntimeInput {
    /// Start from a substrate build input. The substrate input must be
    /// provided — there is no in-memory-only fallback at this layer because
    /// the substrate decisions (local-dev root, libsql handle, etc.) belong
    /// to the caller, not the assembly.
    pub fn from_services(services: RebornBuildInput) -> Self {
        Self {
            services: Some(services),
            #[cfg(feature = "root-llm-provider")]
            llm: None,
            runner: TurnRunnerSettings::default(),
        }
    }

    #[cfg(feature = "root-llm-provider")]
    pub fn with_llm(mut self, llm: RebornLlmConfig) -> Self {
        self.llm = Some(llm);
        self
    }

    pub fn with_runner_settings(mut self, runner: TurnRunnerSettings) -> Self {
        self.runner = runner;
        self
    }
}
