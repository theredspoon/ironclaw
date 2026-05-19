//! Reborn binary-E2E harness skeleton.
//!
//! The strict harness must wire real Reborn workflow/runtime state and only
//! mock external boundaries. The reusable external-boundary shims live in the
//! sibling modules; the full runtime composition is intentionally implemented
//! separately so it cannot silently fall back to internal fakes.
//!
//! The product-workflow support module provides filesystem-backed
//! conversation-binding and idempotency services for strict harness composition.
//! Full runtime and approval block/resume wiring still belongs with the binary
//! harness itself; tests must not fall back to product-workflow fakes when
//! claiming #3702 parity.

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
