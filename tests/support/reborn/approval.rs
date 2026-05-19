//! Approval helpers for Reborn parity harnesses.
//!
//! This module intentionally does not replace run state, gate persistence, or
//! authorization stores. Full approval helpers are added with the runtime
//! harness that drives the real blocked/resume path.

#![allow(dead_code)]

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalWaitConfig {
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for ApprovalWaitConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            poll_interval: Duration::from_millis(10),
        }
    }
}
