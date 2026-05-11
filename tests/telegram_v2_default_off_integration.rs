//! Caller-level test for issue #3285's default-off wiring.
//!
//! This test drives [`ironclaw::config::validate_telegram_v1_v2_exclusivity`]
//! against constructed [`ChannelsConfig`] values — the same input type the
//! host now hands to the validator after [`ChannelsConfig::resolve`]
//! invokes it. A unit test inside `channels.rs` covers the resolve path
//! end-to-end; this caller-level test exercises every observable
//! (v1-enabled, v1-telegram-listed, v2-enabled) tuple to pin the contract.

use std::collections::HashMap;
use std::path::PathBuf;

use ironclaw::config::{ChannelsConfig, CliConfig, validate_telegram_v1_v2_exclusivity};

fn channels_cfg(v1_enabled: bool, v1_telegram_listed: bool, v2_enabled: bool) -> ChannelsConfig {
    ChannelsConfig {
        cli: CliConfig { enabled: false },
        http: None,
        gateway: None,
        signal: None,
        tui: None,
        wasm_channels_dir: PathBuf::from("/tmp/channels"),
        wasm_channels_enabled: v1_enabled,
        configured_wasm_channels: if v1_telegram_listed {
            vec!["telegram".to_string()]
        } else {
            Vec::new()
        },
        wasm_channel_owner_ids: HashMap::new(),
        reborn_telegram_v2_enabled: v2_enabled,
    }
}

#[test]
fn default_off_keeps_v1_only() {
    // The default IronClaw config has REBORN_TELEGRAM_V2_ENABLED = false.
    // Even if v1 telegram is configured, the validator must allow startup.
    validate_telegram_v1_v2_exclusivity(&channels_cfg(true, true, false))
        .expect("default off is valid");
}

#[test]
fn v2_only_is_valid_when_v1_disabled() {
    validate_telegram_v1_v2_exclusivity(&channels_cfg(false, false, true))
        .expect("v2 alone is valid");
}

#[test]
fn neither_is_valid() {
    validate_telegram_v1_v2_exclusivity(&channels_cfg(false, false, false))
        .expect("neither is valid");
}

#[test]
fn v1_plus_v2_simultaneous_is_a_hard_startup_error() {
    let err = validate_telegram_v1_v2_exclusivity(&channels_cfg(true, true, true))
        .expect_err("simultaneous v1+v2 must reject");
    let rendered = err.to_string();
    assert!(rendered.contains("REBORN_TELEGRAM_V2_ENABLED"));
    assert!(rendered.contains("3285"));
}

#[test]
fn v1_enabled_without_telegram_listed_allows_v2() {
    // wasm_channels_enabled = true but the telegram channel is not in
    // configured_wasm_channels — v1 is not handling telegram, so v2 OK.
    validate_telegram_v1_v2_exclusivity(&channels_cfg(true, false, true))
        .expect("non-telegram v1 channels do not block v2");
}

#[test]
fn telegram_listed_but_wasm_channels_disabled_allows_v2() {
    // configured_wasm_channels lists "telegram" but wasm_channels_enabled
    // is false — v1 is not active for startup, so v2 is fine.
    validate_telegram_v1_v2_exclusivity(&channels_cfg(false, true, true))
        .expect("disabled v1 list does not block v2");
}

#[test]
#[cfg(feature = "libsql")]
fn config_for_testing_has_v2_disabled() {
    // The library's testing helper produces a Config with reborn_telegram_v2_enabled
    // = false. Pin that so the legacy v1 path runs unchanged in every test.
    let temp = tempfile::tempdir().expect("tempdir");
    let libsql = temp.path().join("test.db");
    let skills = temp.path().join("skills");
    let installed = temp.path().join("installed_skills");
    let config = ironclaw::config::Config::for_testing(libsql, skills, installed);
    assert!(
        !config.channels.reborn_telegram_v2_enabled,
        "test config must default Reborn Telegram v2 to off"
    );
}
