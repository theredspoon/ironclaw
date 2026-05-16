use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use ironclaw_reborn_composition::{
    RebornCompositionProfile, RebornRuntimeInput, TurnRunnerSettings, build_reborn_runtime,
};
use ironclaw_reborn_config::{RebornBootConfig, RebornProfile};

use crate::context::RebornCliContext;

/// Start the standalone Reborn runtime. Sends `--message` if provided
/// (single-shot mode), otherwise drops into a stdin REPL.
#[derive(Debug, Args)]
pub(crate) struct RunCommand {
    /// Send a single message, print the assistant reply, and exit.
    /// Without this flag, the CLI reads lines from stdin in a loop.
    #[arg(short = 'm', long = "message")]
    message: Option<String>,

    /// Print the substrate readiness snapshot and exit without starting
    /// the agent. Preserves the legacy `run` diagnostic shape so existing
    /// smoke tests keep passing.
    #[arg(long = "dry-run")]
    dry_run: bool,
}

impl RunCommand {
    pub(crate) fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        let _ = init_tracing();
        if self.dry_run {
            return run_dry(context);
        }

        let runtime_input = build_runtime_input(context.boot_config())?;
        let message = self.message.clone();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let runtime = build_reborn_runtime(runtime_input).await?;
            print_runtime_banner(context.boot_config());

            let conversation = runtime.new_conversation().await?;

            let outcome = if let Some(text) = message {
                send_once(&runtime, &conversation, &text).await
            } else {
                run_repl(&runtime, &conversation).await
            };

            runtime.shutdown().await?;
            outcome
        })?;
        Ok(())
    }
}

fn run_dry(context: RebornCliContext) -> anyhow::Result<()> {
    let config = context.boot_config();
    println!("IronClaw Reborn runtime shell");
    println!("binary: ironclaw-reborn");
    println!("version: {}", env!("CARGO_PKG_VERSION"));
    println!("reborn_home: {}", config.home().path().display());
    println!("home_source: {}", config.home().source_label());
    println!("profile: {}", config.profile());
    println!("v1_state: not-used");
    println!("runtime_shell: initialized (dry-run)");
    Ok(())
}

fn print_runtime_banner(config: &RebornBootConfig) {
    eprintln!("ironclaw-reborn: runtime started");
    eprintln!("  profile     : {}", config.profile());
    eprintln!("  reborn_home : {}", config.home().path().display());
    eprintln!();
}

async fn send_once(
    runtime: &ironclaw_reborn_composition::RebornRuntime,
    conversation: &ironclaw_reborn_composition::ConversationId,
    text: &str,
) -> anyhow::Result<()> {
    let reply = runtime.send_user_message(conversation, text).await?;
    print_reply(&reply);
    Ok(())
}

async fn run_repl(
    runtime: &ironclaw_reborn_composition::RebornRuntime,
    conversation: &ironclaw_reborn_composition::ConversationId,
) -> anyhow::Result<()> {
    let stdin_is_tty = std::io::stdin().is_terminal();
    if stdin_is_tty {
        eprintln!("(repl) type a message and press enter; Ctrl-D to exit");
    }
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    use tokio::io::AsyncBufReadExt;
    let mut lines = reader.lines();

    let cancel = tokio::signal::ctrl_c();
    tokio::pin!(cancel);

    loop {
        if stdin_is_tty {
            // Prompt to stderr so stdout stays clean for piping.
            eprint!("> ");
            let _ = std::io::stderr().flush();
        }
        tokio::select! {
            line = lines.next_line() => {
                match line? {
                    Some(text) if text.trim().is_empty() => continue,
                    Some(text) => {
                        match runtime.send_user_message(conversation, text.trim()).await {
                            Ok(reply) => print_reply(&reply),
                            Err(error) => eprintln!("error: {error}"),
                        }
                    }
                    None => {
                        if stdin_is_tty {
                            eprintln!();
                        }
                        return Ok(());
                    }
                }
            }
            _ = &mut cancel => {
                eprintln!();
                eprintln!("(repl) caught ctrl-c, shutting down");
                return Ok(());
            }
        }
    }
}

fn print_reply(reply: &ironclaw_reborn_composition::AssistantReply) {
    match reply.text.as_deref() {
        Some(text) => println!("{text}"),
        None => println!(
            "(no assistant text; status={:?}, run_id={})",
            reply.status, reply.run_id
        ),
    }
}

fn build_runtime_input(config: &RebornBootConfig) -> anyhow::Result<RebornRuntimeInput> {
    use ironclaw_reborn_composition::RebornBuildInput;

    // Read the operator's boot TOML if present. Missing file is OK
    // (operator may not have run `ironclaw-reborn config init` yet);
    // sparse fields are OK (each absent field falls back to the
    // CLI-shaped default baked into composition).
    let config_file = read_config_file(config)?;

    let owner_id = config_file
        .as_ref()
        .and_then(|file| file.identity.as_ref())
        .and_then(|identity| identity.default_owner.as_deref())
        .unwrap_or("reborn-cli");

    let local_dev_root: PathBuf = config.home().path().join("local-dev");

    let composition_profile = match config.profile() {
        RebornProfile::LocalDev => RebornCompositionProfile::LocalDev,
        other => {
            anyhow::bail!(
                "ironclaw-reborn run currently supports profile=local-dev; got profile={other}. \
                 Production wiring lands in a follow-up slice."
            );
        }
    };
    let _ = composition_profile;

    let services_input = RebornBuildInput::local_dev(owner_id, local_dev_root);

    #[allow(unused_mut)]
    let mut runtime_input = RebornRuntimeInput::from_services(services_input)
        .with_runner_settings(runner_settings(config_file.as_ref()));

    #[cfg(feature = "root-llm-provider")]
    {
        match resolve_llm_config(config, config_file.as_ref())? {
            LlmResolutionOutcome::Resolved(llm) => {
                runtime_input = runtime_input.with_llm(llm);
            }
            LlmResolutionOutcome::NoSelectionConfigured => {
                tracing::warn!(
                    "no LLM selection configured; set `[llm.default]` in {} or export \
                     OPENAI_API_KEY / ANTHROPIC_API_KEY / OLLAMA_BASE_URL. \
                     Runs will fail until an LLM is wired.",
                    config.home().config_file_path().display()
                );
            }
        }
    }

    Ok(runtime_input)
}

fn read_config_file(
    config: &RebornBootConfig,
) -> anyhow::Result<Option<ironclaw_reborn_config::RebornConfigFile>> {
    use ironclaw_reborn_config::RebornConfigFile;
    let path = config.home().config_file_path();
    let file = RebornConfigFile::load(&path).map_err(anyhow::Error::from)?;
    if let Some(parsed) = &file {
        tracing::debug!(
            path = %path.display(),
            api_version = ?parsed.api_version,
            "loaded boot config TOML"
        );
    }
    Ok(file)
}

fn runner_settings(
    config_file: Option<&ironclaw_reborn_config::RebornConfigFile>,
) -> TurnRunnerSettings {
    let mut settings = TurnRunnerSettings {
        heartbeat_interval: Duration::from_secs(5),
        poll_interval: Duration::from_millis(200),
    };
    if let Some(runner) = config_file.and_then(|file| file.runner.as_ref()) {
        if let Some(secs) = runner.heartbeat_interval_secs {
            settings.heartbeat_interval = Duration::from_secs(secs);
        }
        if let Some(ms) = runner.poll_interval_ms {
            settings.poll_interval = Duration::from_millis(ms);
        }
    }
    settings
}

#[cfg(feature = "root-llm-provider")]
enum LlmResolutionOutcome {
    Resolved(ironclaw_reborn_composition::RebornLlmConfig),
    NoSelectionConfigured,
}

#[cfg(feature = "root-llm-provider")]
fn resolve_llm_config(
    boot: &RebornBootConfig,
    config_file: Option<&ironclaw_reborn_config::RebornConfigFile>,
) -> anyhow::Result<LlmResolutionOutcome> {
    // Preference order:
    //   1. boot TOML [llm.default] (catalog-driven via providers.json)
    //   2. env-only fallback (legacy: OPENAI_API_KEY etc.) for ergonomics
    //   3. no LLM configured -> stub gateway, send fails at first message
    if let Some(selection) = config_file.and_then(|file| file.default_llm_slot()) {
        let providers_path = boot.home().providers_file_path();
        let providers_arg = if providers_path.exists() {
            Some(providers_path.as_path())
        } else {
            None
        };
        let llm = ironclaw_reborn_composition::resolve_llm_selection_against_catalog(
            selection,
            providers_arg,
        )?;
        tracing::info!(
            provider_id = %llm.provider_id,
            model = %llm.model,
            base_url = %llm.base_url,
            "resolved LLM selection from config.toml against provider catalog"
        );
        return Ok(LlmResolutionOutcome::Resolved(llm));
    }

    if let Some(llm) = resolve_llm_config_from_env()? {
        tracing::info!(
            provider_id = %llm.provider_id,
            model = %llm.model,
            "resolved LLM selection from environment (no [llm.default] in config.toml)"
        );
        return Ok(LlmResolutionOutcome::Resolved(llm));
    }

    Ok(LlmResolutionOutcome::NoSelectionConfigured)
}

#[cfg(feature = "root-llm-provider")]
fn resolve_llm_config_from_env()
-> anyhow::Result<Option<ironclaw_reborn_composition::RebornLlmConfig>> {
    use ironclaw_reborn_composition::RebornLlmConfig;
    use secrecy::SecretString;

    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        let model = std::env::var("IRONCLAW_REBORN_MODEL")
            .unwrap_or_else(|_| "gpt-4o-mini".to_string());
        let base_url = std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());
        return Ok(Some(RebornLlmConfig::openai_compat(
            "openai",
            base_url,
            model,
            SecretString::from(key),
        )));
    }
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        let model = std::env::var("IRONCLAW_REBORN_MODEL")
            .unwrap_or_else(|_| "claude-3-5-sonnet-latest".to_string());
        let base_url = std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com/v1".to_string());
        return Ok(Some(RebornLlmConfig {
            provider_id: "anthropic".to_string(),
            model,
            base_url,
            api_key: Some(SecretString::from(key)),
            protocol: "anthropic".to_string(),
            request_timeout_secs: 120,
            extra_headers: Vec::new(),
        }));
    }
    if let Ok(base_url) = std::env::var("OLLAMA_BASE_URL") {
        let model = std::env::var("IRONCLAW_REBORN_MODEL")
            .unwrap_or_else(|_| "llama3.2".to_string());
        return Ok(Some(RebornLlmConfig {
            provider_id: "ollama".to_string(),
            model,
            base_url,
            api_key: None,
            protocol: "ollama".to_string(),
            request_timeout_secs: 120,
            extra_headers: Vec::new(),
        }));
    }
    Ok(None)
}

fn init_tracing() -> Result<(), ()> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    let filter = EnvFilter::try_from_env("IRONCLAW_REBORN_LOG").unwrap_or_else(|_| {
        EnvFilter::new("info,ironclaw_reborn=info,ironclaw_reborn_composition=info")
    });
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|_| ())
}
