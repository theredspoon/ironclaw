//! Reborn binary-E2E harness skeleton.
//!
//! The strict harness must wire real Reborn workflow/runtime state and only
//! mock external boundaries. The reusable external-boundary shims live in the
//! sibling modules; the full runtime composition is intentionally implemented
//! separately so it cannot silently fall back to internal fakes.
//!
//! Current blocker for strict #3702 acceptance: `ironclaw_product_workflow`
//! exposes test-support fakes for conversation binding/idempotency, but no
//! production filesystem-backed binding/idempotency service that this root
//! harness can compose. Until that exists, this module must not claim binary
//! parity by wrapping `FakeConversationBindingService` or `FakeIdempotencyLedger`.

#![allow(dead_code)]

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HarnessWaitConfig {
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for HarnessWaitConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            poll_interval: Duration::from_millis(10),
        }
    }
}
