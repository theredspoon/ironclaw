//! Standalone Reborn composition and adapter wiring.
//!
//! This crate is the Reborn-side home for adapters that intentionally bridge
//! to existing root IronClaw services while keeping the normal `/src` app graph
//! free of Reborn loop-support wiring.

pub mod model_gateway;

pub use model_gateway::{LlmModelProfilePolicy, LlmProviderModelGateway};
