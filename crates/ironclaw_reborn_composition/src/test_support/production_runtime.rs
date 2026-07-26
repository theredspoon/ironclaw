//! Production-runtime fixture helpers.
//!
//! These helpers mirror configuration supplied by the production CLI before
//! [`crate::build_reborn_runtime`] performs its fail-closed readiness check.
//! They are available only with `test-support` and ship no production code.

use std::time::Duration;

use ironclaw_host_api::{AgentId, CapabilityId, SecretHandle, TenantId, ThreadId, UserId};
use ironclaw_turns::TurnScope;

/// Configure the Matrix retry worker required by production readiness.
///
/// This mirrors the production call site that supplies
/// [`crate::input::MatrixRetryWorkerProductionConfig`] through
/// [`crate::RebornBuildInput::with_matrix_retry_production_config`]. Integration
/// tests use this helper instead of duplicating crate-private configuration
/// details.
#[cfg(all(
    feature = "test-support",
    any(feature = "libsql", feature = "postgres")
))]
pub fn with_production_matrix_retry_worker_for_test(
    input: crate::RebornBuildInput,
    fixture_id: &str,
) -> crate::RebornBuildInput {
    let scope = TurnScope::new_with_owner(
        TenantId::new(format!("{fixture_id}-tenant")).expect("valid Matrix retry tenant"),
        Some(AgentId::new(format!("{fixture_id}-agent")).expect("valid Matrix retry agent")),
        None,
        ThreadId::new(format!("{fixture_id}-thread")).expect("valid Matrix retry thread"),
        Some(UserId::new(format!("{fixture_id}-owner")).expect("valid Matrix retry owner")),
    );

    input.with_matrix_retry_production_config(crate::input::MatrixRetryWorkerProductionConfig::new(
        crate::input::MatrixRetryWorkerProductionConfigInput {
            settings: crate::matrix_outbound::MatrixRetryWorkerSettings {
                enabled: true,
                poll_interval: Duration::from_secs(60),
                startup_jitter_max: Duration::ZERO,
                tick_jitter_max: Duration::ZERO,
                max_entries_per_scope: 1,
            },
            scopes: vec![scope],
            homeserver_origin: "https://matrix.example".to_string(),
            credential_secret: SecretHandle::new("matrix_access_token")
                .expect("valid Matrix credential secret"),
            credential_handle_fingerprint: format!(
                "sha256:{}",
                ironclaw_common::hashing::sha256_hex(b"test-matrix-credential")
            ),
            capability_id: CapabilityId::new("matrix.send").expect("valid Matrix capability id"),
        },
    ))
}
