//! Matrix-local shared outbound handoff contracts.
//!
//! These types freeze the Matrix shared outbound boundary without changing
//! global outbound status, retry, or evidence schemas. ProductWorkflow keeps
//! Matrix command intent pending; this bridge records terminal status only
//! after a delivery port returns protocol evidence or a sanitized error.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_common::hashing::sha256_hex;
use ironclaw_filesystem::{
    CasApply, CasExpectation, CasUpdateError, ContentType, Entry, FileType, FilesystemError,
    RootFilesystem, ScopedFilesystem, cas_update,
};
use ironclaw_host_api::{
    CapabilityId, ExtensionId, NetworkMethod, NetworkPolicy, NetworkScheme, NetworkTargetPattern,
    ResourceScope, RuntimeCredentialTarget, RuntimeHttpEgressError, RuntimeHttpEgressRequest,
    RuntimeHttpEgressResponse, RuntimeKind, ScopedPath, SecretHandle, TrustClass,
};
use ironclaw_host_runtime::{
    HostRuntimeCredentialMaterial, HostRuntimeHttpEgressPort, HostRuntimeHttpEgressRequest,
};
use ironclaw_outbound::{
    DeliveryFailureKind, OutboundDeliveryId, OutboundDeliveryStatus, OutboundError,
    OutboundStateStore, UpdateDeliveryStatusRequest,
};
use ironclaw_secrets::{SecretStore, SecretStoreError};
use ironclaw_turns::{ReplyTargetBindingRef, TurnScope};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;
mod contracts;
mod evidence;
mod http_delivery;
mod observability;
mod orchestrator;
mod production_retry;
mod stores;

pub use contracts::*;
pub use evidence::*;
pub use http_delivery::*;
pub use orchestrator::*;
pub use production_retry::*;
pub use stores::*;

#[cfg(any(test, feature = "test-support"))]
pub mod fakes;

#[cfg(test)]
mod tests;
