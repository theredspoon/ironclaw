//! Provider-catalog resolution for the assembled Reborn runtime.
//!
//! The three-layer LLM config model the operator sees:
//!
//! 1. **Catalog** — built-in `providers.json` + optional user-overlay
//!    `$IRONCLAW_REBORN_HOME/providers.json` (same JSON shape as
//!    v1's `~/.ironclaw/providers.json`). Loaded here via
//!    `ironclaw_llm::ProviderRegistry::load_from_path`.
//! 2. **Selection** — boot TOML's `[llm.<slot>]` section, parsed by
//!    `ironclaw_reborn_config::LlmSlotSelection`. "Use provider X
//!    for the `default` slot, with model Y."
//! 3. **Runtime config** — derived here. The resolved `ProviderDefinition`
//!    plus the selection's overrides becomes a `RebornLlmConfig` that
//!    `build_reborn_runtime` knows how to wire into a host-managed
//!    model gateway.
//!
//! This module is the home of step 3. Lives behind the
//! `root-llm-provider` feature so the substrate-only composition stays
//! free of `ironclaw_llm`.
//!
//! When epic
//! [#3036](https://github.com/nearai/ironclaw/issues/3036)'s blueprint
//! apply service lands, it writes the selection into the eventual
//! `ProviderRepo` instead of into a TOML file; the runtime then reads
//! from the repo. The resolution logic in this module survives that
//! transition unchanged — the only thing that changes is whether the
//! `LlmSlotSelection` input came from a TOML reader or a repo read.

#![cfg(feature = "root-llm-provider")]

use std::path::Path;

use thiserror::Error;

use ironclaw_llm::{ProviderRegistry, registry::ProviderDefinition};
use ironclaw_reborn_config::LlmSlotSelection;

use crate::runtime_input::RebornLlmConfig;

/// Errors surfaced when resolving an `LlmSlotSelection` against the
/// merged provider catalog.
#[derive(Debug, Error)]
pub enum RebornLlmCatalogError {
    /// Selection didn't name a provider. Boot TOML carried
    /// `[llm.default]` with no `provider_id` field.
    #[error(
        "llm slot selection has no `provider_id`; set `[llm.<slot>] provider_id = \"...\"` in config.toml"
    )]
    MissingProviderId,
    /// `provider_id` doesn't exist in the merged catalog.
    #[error(
        "llm provider id `{requested}` not found in the provider catalog \
         (compiled-in + $IRONCLAW_REBORN_HOME/providers.json); known ids: [{known}]"
    )]
    UnknownProvider { requested: String, known: String },
    /// Provider requires an API key but the resolved env var isn't set.
    #[error(
        "llm provider `{provider}` requires API key env var `{env}` to be set; \
         export it (e.g. `export {env}=...`) or override with `[llm.<slot>] api_key_env = ...`"
    )]
    ApiKeyEnvUnset { provider: String, env: String },
    /// Provider says it needs an API key but doesn't expose an
    /// `api_key_env` setting (and the selection didn't override it).
    /// Theoretically impossible in a sane catalog; defensive guard.
    #[error(
        "llm provider `{provider}` requires an API key but the catalog entry has no \
         `api_key_env`; add `api_key_env` to the provider catalog entry or override via \
         `[llm.<slot>] api_key_env = ...`"
    )]
    ApiKeyEnvUnconfigured { provider: String },
    /// Provider requires a base URL (e.g. generic OpenAI-compatible) but
    /// neither the catalog nor the selection supplied one.
    #[error(
        "llm provider `{provider}` requires a base_url but neither the catalog entry's \
         `default_base_url` nor the selection's `base_url` override are set"
    )]
    BaseUrlUnconfigured { provider: String },
}

/// Resolve an `LlmSlotSelection` against the merged provider catalog.
///
/// Steps:
/// 1. Build the catalog (`ProviderRegistry::load_from_path(user)`).
/// 2. Look up the requested `provider_id`.
/// 3. Determine api_key_env (selection override > catalog default).
/// 4. Read the API key value from that env var (fail-closed if absent).
/// 5. Determine base_url (selection override > catalog default).
/// 6. Determine model (selection override > catalog default).
/// 7. Build and return a `RebornLlmConfig`.
pub fn resolve_llm_selection_against_catalog(
    selection: &LlmSlotSelection,
    user_providers_path: Option<&Path>,
) -> Result<RebornLlmConfig, RebornLlmCatalogError> {
    let registry = ProviderRegistry::load_from_path(user_providers_path);
    resolve_against_registry(selection, &registry)
}

/// Resolve a selection against a pre-built registry. Useful in tests
/// where a synthetic registry can be assembled without touching the
/// filesystem.
pub fn resolve_against_registry(
    selection: &LlmSlotSelection,
    registry: &ProviderRegistry,
) -> Result<RebornLlmConfig, RebornLlmCatalogError> {
    let provider_id = selection
        .provider_id
        .as_deref()
        .ok_or(RebornLlmCatalogError::MissingProviderId)?;

    let provider = registry.find(provider_id).ok_or_else(|| {
        RebornLlmCatalogError::UnknownProvider {
            requested: provider_id.to_string(),
            known: registry
                .all()
                .iter()
                .map(|provider| provider.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        }
    })?;

    // API key resolution.
    let api_key = read_api_key(selection, provider)?;

    // Base URL resolution (selection > catalog default).
    let base_url = selection
        .base_url
        .clone()
        .or_else(|| provider.default_base_url.clone())
        .ok_or_else(|| RebornLlmCatalogError::BaseUrlUnconfigured {
            provider: provider.id.clone(),
        })?;

    // Model resolution.
    let model = selection
        .model
        .clone()
        .unwrap_or_else(|| provider.default_model.clone());

    Ok(RebornLlmConfig {
        provider_id: provider.id.clone(),
        model,
        base_url,
        api_key,
        protocol: serialize_protocol(provider.protocol),
        request_timeout_secs: 120,
        extra_headers: Vec::new(),
    })
}

fn read_api_key(
    selection: &LlmSlotSelection,
    provider: &ProviderDefinition,
) -> Result<Option<secrecy::SecretString>, RebornLlmCatalogError> {
    let env_var = selection
        .api_key_env
        .clone()
        .or_else(|| provider.api_key_env.clone());

    match (env_var, provider.api_key_required) {
        (Some(env), required) => match std::env::var(&env) {
            Ok(value) => Ok(Some(secrecy::SecretString::from(value))),
            Err(_) if required => Err(RebornLlmCatalogError::ApiKeyEnvUnset {
                provider: provider.id.clone(),
                env,
            }),
            Err(_) => Ok(None),
        },
        (None, true) => Err(RebornLlmCatalogError::ApiKeyEnvUnconfigured {
            provider: provider.id.clone(),
        }),
        (None, false) => Ok(None),
    }
}

/// Map `ironclaw_llm::ProviderProtocol` to the wire string
/// `RebornLlmConfig.protocol` accepts.
fn serialize_protocol(protocol: ironclaw_llm::ProviderProtocol) -> String {
    use ironclaw_llm::ProviderProtocol;
    match protocol {
        ProviderProtocol::OpenAiCompletions => "openai_completions",
        ProviderProtocol::Anthropic => "anthropic",
        ProviderProtocol::Ollama => "ollama",
        ProviderProtocol::GithubCopilot => "github_copilot",
        ProviderProtocol::DeepSeek => "deepseek",
        ProviderProtocol::Gemini => "gemini",
        ProviderProtocol::OpenRouter => "openrouter",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_llm::registry::{ProviderProtocol, ProviderRegistry};

    fn provider_with_required_key(id: &str, env: &str) -> ProviderDefinition {
        ProviderDefinition {
            id: id.to_string(),
            aliases: Vec::new(),
            protocol: ProviderProtocol::OpenAiCompletions,
            default_base_url: Some("https://example.test/v1".to_string()),
            base_url_env: None,
            base_url_required: false,
            api_key_env: Some(env.to_string()),
            api_key_required: true,
            model_env: "TEST_MODEL".to_string(),
            default_model: "test-model".to_string(),
            description: "test".to_string(),
            extra_headers_env: None,
            unsupported_params: Vec::new(),
            setup: None,
        }
    }

    fn provider_no_key_required(id: &str) -> ProviderDefinition {
        ProviderDefinition {
            id: id.to_string(),
            aliases: Vec::new(),
            protocol: ProviderProtocol::Ollama,
            default_base_url: Some("http://localhost:11434".to_string()),
            base_url_env: None,
            base_url_required: false,
            api_key_env: None,
            api_key_required: false,
            model_env: "TEST_MODEL".to_string(),
            default_model: "llama3".to_string(),
            description: "test (no key)".to_string(),
            extra_headers_env: None,
            unsupported_params: Vec::new(),
            setup: None,
        }
    }

    #[test]
    fn unknown_provider_lists_known_ids() {
        let registry =
            ProviderRegistry::new(vec![provider_with_required_key("alpha", "ALPHA_KEY")]);
        let selection = LlmSlotSelection {
            provider_id: Some("does-not-exist".to_string()),
            ..Default::default()
        };
        let err = resolve_against_registry(&selection, &registry).expect_err("must error");
        match err {
            RebornLlmCatalogError::UnknownProvider { requested, known } => {
                assert_eq!(requested, "does-not-exist");
                assert!(known.contains("alpha"), "known list: {known}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn missing_required_api_key_env_fails_closed() {
        // Use a uniquely-named env var that we never set; no `set_var`
        // / `remove_var` calls (forbidden under `forbid(unsafe_code)`
        // post-edition-2024). The unique suffix means even if the test
        // environment happens to pre-set similar names, this one is
        // free.
        let env_name = "REBORN_TEST_UNSET_API_KEY_DO_NOT_SET_8a3f1c2e";
        debug_assert!(
            std::env::var(env_name).is_err(),
            "test depends on `{env_name}` being unset"
        );
        let registry =
            ProviderRegistry::new(vec![provider_with_required_key("alpha", env_name)]);
        let selection = LlmSlotSelection {
            provider_id: Some("alpha".to_string()),
            ..Default::default()
        };
        let err = resolve_against_registry(&selection, &registry).expect_err("must error");
        assert!(matches!(
            err,
            RebornLlmCatalogError::ApiKeyEnvUnset { .. }
        ));
    }

    #[test]
    fn happy_path_no_key_required_uses_catalog_default_model_and_base_url() {
        let registry = ProviderRegistry::new(vec![provider_no_key_required("alpha")]);
        let selection = LlmSlotSelection {
            provider_id: Some("alpha".to_string()),
            ..Default::default()
        };

        let config = resolve_against_registry(&selection, &registry).expect("must resolve");
        assert_eq!(config.provider_id, "alpha");
        assert_eq!(config.model, "llama3"); // catalog default
        assert_eq!(config.base_url, "http://localhost:11434"); // catalog default
        assert_eq!(config.protocol, "ollama");
        assert!(config.api_key.is_none());
    }

    #[test]
    fn selection_overrides_take_precedence_over_catalog() {
        let registry = ProviderRegistry::new(vec![provider_no_key_required("alpha")]);
        let selection = LlmSlotSelection {
            provider_id: Some("alpha".to_string()),
            model: Some("custom-model".to_string()),
            base_url: Some("https://override.test/v1".to_string()),
            api_key_env: None,
        };

        let config = resolve_against_registry(&selection, &registry).expect("must resolve");
        assert_eq!(config.model, "custom-model");
        assert_eq!(config.base_url, "https://override.test/v1");
    }
}
