//! Stub host runtime primitives for IronClaw Reborn WASM v2 product adapters.
//!
//! This crate is the trusted-host boundary for protocol authentication and
//! constrained outbound egress. The native runner and concrete adapters land in
//! later slices so this PR stays focused on the reusable auth/egress contract.

#![forbid(unsafe_code)]

pub mod auth_verifier;
pub mod egress_policy;

pub use auth_verifier::{
    HmacWebhookAuth, SharedSecretHeaderAuth, VerificationOutcome, WebhookAuthVerifier,
};
pub use egress_policy::{EgressPolicy, EgressPolicyError, EgressPolicyTarget};
