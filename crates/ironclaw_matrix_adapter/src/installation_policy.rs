//! Host-owned Matrix ProductAdapter installation policy.
//!
//! This module deliberately stays outside the ProductAdapter WIT/runtime config.
//! It models the host-side policy snapshot required before Matrix WASM
//! parse/render or Matrix HTTP egress can run.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ironclaw_product_adapters::{AdapterInstallationId, EgressCredentialHandle, ProductAdapterId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixInstallationPolicyRejection {
    InstallationNotFound,
    AmbiguousInstallation,
    InstallationDisabled,
    InstallationDeleting,
    AdapterMismatch,
    InstallationMismatch,
    ArtifactHashMismatch,
    ManifestHashMismatch,
    WitWorldMismatch,
    ArtifactSignatureInvalid,
    UnexpectedGuestImport,
    DirectHttpEgressDenied,
    AuthMissing,
    AuthInvalid,
    AuthReplay,
    RoomNotAllowed,
    SenderNotAllowed,
    HomeserverMismatch,
    EgressTargetUndeclared,
    EgressTargetOutOfBounds,
    CredentialHandleMissing,
    CredentialHandleMismatch,
    CredentialHandleRevoked,
    GuestCredentialMaterialRejected,
    UnsafeMatrixRequestShape,
    UnsafeRedirect,
    PrivateNetworkTarget,
    PolicyRevisionMismatch,
    PolicySnapshotExpired,
    MutationUnauthorized,
    MutationRejected,
    InvalidPolicyValue,
}

impl MatrixInstallationPolicyRejection {
    pub fn external_response_shape(self) -> ExternalPolicyRejectionShape {
        match self {
            Self::MutationUnauthorized => ExternalPolicyRejectionShape {
                status: 403,
                body_code: "matrix_policy_forbidden",
            },
            _ => ExternalPolicyRejectionShape {
                status: 403,
                body_code: "matrix_policy_denied",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalPolicyRejectionShape {
    pub status: u16,
    pub body_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MatrixHomeserverOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl MatrixHomeserverOrigin {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, MatrixInstallationPolicyRejection> {
        let value = value.as_ref();
        let (scheme, rest) = value
            .split_once("://")
            .ok_or(MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "https" && scheme != "http" {
            return Err(MatrixInstallationPolicyRejection::InvalidPolicyValue);
        }
        if rest.contains('?') || rest.contains('#') || rest.contains('@') {
            return Err(MatrixInstallationPolicyRejection::InvalidPolicyValue);
        }
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains('/') {
            return Err(MatrixInstallationPolicyRejection::InvalidPolicyValue);
        }
        let (host, port) = parse_host_port(rest)?;
        reject_private_or_metadata_host(&host)?;
        Ok(Self { scheme, host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

fn parse_host_port(
    value: &str,
) -> Result<(String, Option<u16>), MatrixInstallationPolicyRejection> {
    if value.is_empty() {
        return Err(MatrixInstallationPolicyRejection::InvalidPolicyValue);
    }
    if let Some(host) = value.strip_prefix('[') {
        let (host, port) = host
            .split_once(']')
            .ok_or(MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
        let port = if port.is_empty() {
            None
        } else {
            Some(parse_port(port.strip_prefix(':').ok_or(
                MatrixInstallationPolicyRejection::InvalidPolicyValue,
            )?)?)
        };
        return Ok((host.to_ascii_lowercase(), port));
    }
    let mut parts = value.rsplitn(2, ':');
    let last = parts.next().unwrap_or_default();
    let maybe_host = parts.next();
    let (host, port) = if let Some(host) = maybe_host {
        if last.chars().all(|c| c.is_ascii_digit()) {
            (host, Some(parse_port(last)?))
        } else {
            (value, None)
        }
    } else {
        (value, None)
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(MatrixInstallationPolicyRejection::InvalidPolicyValue);
    }
    Ok((host, port))
}

fn parse_port(value: &str) -> Result<u16, MatrixInstallationPolicyRejection> {
    value
        .parse::<u16>()
        .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)
}

fn reject_private_or_metadata_host(host: &str) -> Result<(), MatrixInstallationPolicyRejection> {
    if host == "metadata.google.internal" {
        return Err(MatrixInstallationPolicyRejection::PrivateNetworkTarget);
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Ok(());
    };
    match ip {
        IpAddr::V4(ip) if is_disallowed_ipv4(ip) => {
            Err(MatrixInstallationPolicyRejection::PrivateNetworkTarget)
        }
        IpAddr::V6(ip) if is_disallowed_ipv6(ip) => {
            Err(MatrixInstallationPolicyRejection::PrivateNetworkTarget)
        }
        _ => Ok(()),
    }
}

fn is_disallowed_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.octets() == [169, 254, 169, 254]
}

fn is_disallowed_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MatrixRoomId(String);

impl MatrixRoomId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        let value = value.into();
        if value.starts_with('!')
            && value.contains(':')
            && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            Ok(Self(value))
        } else {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MatrixUserId(String);

impl MatrixUserId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        let value = value.into();
        if value.starts_with('@')
            && value.contains(':')
            && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            Ok(Self(value))
        } else {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EgressTargetIndex(u32);

impl EgressTargetIndex {
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRevision(u64);

impl PolicyRevision {
    pub fn new(value: u64) -> Result<Self, MatrixInstallationPolicyRejection> {
        if value == 0 {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentArtifactId(String);

impl ComponentArtifactId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSha256(String);

impl ArtifactSha256 {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        let value = value.into();
        if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitPackageName(String);

impl WitPackageName {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitWorldName(String);

impl WitWorldName {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticManifestBinding(String);

impl StaticManifestBinding {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

fn non_empty(value: String) -> Result<String, MatrixInstallationPolicyRejection> {
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
    } else {
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentArtifactBinding {
    pub artifact_id: ComponentArtifactId,
    pub artifact_sha256: ArtifactSha256,
    pub wit_package: WitPackageName,
    pub wit_world: WitWorldName,
    pub manifest: StaticManifestBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixActivationState {
    Disabled,
    Enabled,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationAuditMetadata {
    actor: String,
    at_ms: u64,
}

impl InstallationAuditMetadata {
    pub fn new(
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        Ok(Self {
            actor: non_empty(actor.into())?,
            at_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixInstallationPolicy {
    pub homeserver: MatrixHomeserverOrigin,
    pub allowed_rooms: BTreeSet<MatrixRoomId>,
    pub allowed_senders: BTreeSet<MatrixUserId>,
    pub egress_target_index: EgressTargetIndex,
    pub credential_handle: EgressCredentialHandle,
}

impl MatrixInstallationPolicy {
    pub fn new(
        homeserver: MatrixHomeserverOrigin,
        allowed_rooms: BTreeSet<MatrixRoomId>,
        allowed_senders: BTreeSet<MatrixUserId>,
        egress_target_index: EgressTargetIndex,
        credential_handle: EgressCredentialHandle,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        if allowed_rooms.is_empty() || allowed_senders.is_empty() {
            return Err(MatrixInstallationPolicyRejection::InvalidPolicyValue);
        }
        Ok(Self {
            homeserver,
            allowed_rooms,
            allowed_senders,
            egress_target_index,
            credential_handle,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixProductAdapterInstallation {
    pub adapter_id: ProductAdapterId,
    pub installation_id: AdapterInstallationId,
    pub component: ComponentArtifactBinding,
    pub policy: MatrixInstallationPolicy,
    pub activation: MatrixActivationState,
    pub policy_revision: PolicyRevision,
    pub audit: InstallationAuditMetadata,
}

impl MatrixProductAdapterInstallation {
    pub fn new(
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
        component: ComponentArtifactBinding,
        policy: MatrixInstallationPolicy,
        activation: MatrixActivationState,
        policy_revision: PolicyRevision,
        audit: InstallationAuditMetadata,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        Ok(Self {
            adapter_id,
            installation_id,
            component,
            policy,
            activation,
            policy_revision,
            audit,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixInboundRoutingContext {
    pub homeserver: MatrixHomeserverOrigin,
    pub room_id: MatrixRoomId,
    pub sender: MatrixUserId,
    verified: bool,
}

impl MatrixInboundRoutingContext {
    pub fn verified_for_test(
        homeserver: MatrixHomeserverOrigin,
        room_id: MatrixRoomId,
        sender: MatrixUserId,
    ) -> Self {
        Self {
            homeserver,
            room_id,
            sender,
            verified: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixPolicySnapshot {
    pub adapter_id: ProductAdapterId,
    pub installation_id: AdapterInstallationId,
    pub homeserver: MatrixHomeserverOrigin,
    pub allowed_rooms: BTreeSet<MatrixRoomId>,
    pub allowed_senders: BTreeSet<MatrixUserId>,
    pub egress_target_index: EgressTargetIndex,
    pub credential_handle: EgressCredentialHandle,
    pub policy_revision: PolicyRevision,
}

pub fn resolve_matrix_inbound_installation(
    installations: &[MatrixProductAdapterInstallation],
    ctx: &MatrixInboundRoutingContext,
) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection> {
    if !ctx.verified {
        return Err(MatrixInstallationPolicyRejection::AuthInvalid);
    }
    let mut disabled_match = false;
    let mut deleting_match = false;
    let mut allowed = Vec::new();
    let mut saw_homeserver = false;
    let mut saw_room_rejection = false;
    let mut saw_sender_rejection = false;

    for installation in installations {
        if installation.policy.homeserver != ctx.homeserver {
            continue;
        }
        saw_homeserver = true;
        match installation.activation {
            MatrixActivationState::Disabled => {
                disabled_match = true;
                continue;
            }
            MatrixActivationState::Deleting => {
                deleting_match = true;
                continue;
            }
            MatrixActivationState::Enabled => {}
        }
        if !installation.policy.allowed_rooms.contains(&ctx.room_id) {
            saw_room_rejection = true;
            continue;
        }
        if !installation.policy.allowed_senders.contains(&ctx.sender) {
            saw_sender_rejection = true;
            continue;
        }
        allowed.push(installation);
    }

    match allowed.as_slice() {
        [installation] => Ok(MatrixPolicySnapshot {
            adapter_id: installation.adapter_id.clone(),
            installation_id: installation.installation_id.clone(),
            homeserver: installation.policy.homeserver.clone(),
            allowed_rooms: installation.policy.allowed_rooms.clone(),
            allowed_senders: installation.policy.allowed_senders.clone(),
            egress_target_index: installation.policy.egress_target_index,
            credential_handle: installation.policy.credential_handle.clone(),
            policy_revision: installation.policy_revision,
        }),
        [_, ..] => Err(MatrixInstallationPolicyRejection::AmbiguousInstallation),
        [] if deleting_match => Err(MatrixInstallationPolicyRejection::InstallationDeleting),
        [] if disabled_match => Err(MatrixInstallationPolicyRejection::InstallationDisabled),
        [] if saw_room_rejection => Err(MatrixInstallationPolicyRejection::RoomNotAllowed),
        [] if saw_sender_rejection => Err(MatrixInstallationPolicyRejection::SenderNotAllowed),
        [] if saw_homeserver => Err(MatrixInstallationPolicyRejection::RoomNotAllowed),
        [] => Err(MatrixInstallationPolicyRejection::InstallationNotFound),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixOutboundPolicyCheck {
    pub adapter_id: ProductAdapterId,
    pub installation_id: AdapterInstallationId,
    pub homeserver: MatrixHomeserverOrigin,
    pub room_id: MatrixRoomId,
    pub egress_target_index: EgressTargetIndex,
    pub credential_handle: EgressCredentialHandle,
    pub path: String,
    pub guest_authorization_header_present: bool,
    pub policy_revision: PolicyRevision,
}

pub fn authorize_matrix_outbound(
    snapshot: &MatrixPolicySnapshot,
    check: &MatrixOutboundPolicyCheck,
) -> Result<(), MatrixInstallationPolicyRejection> {
    if check.adapter_id != snapshot.adapter_id {
        return Err(MatrixInstallationPolicyRejection::AdapterMismatch);
    }
    if check.installation_id != snapshot.installation_id {
        return Err(MatrixInstallationPolicyRejection::InstallationMismatch);
    }
    if check.policy_revision != snapshot.policy_revision {
        return Err(MatrixInstallationPolicyRejection::PolicyRevisionMismatch);
    }
    if check.homeserver != snapshot.homeserver {
        return Err(MatrixInstallationPolicyRejection::HomeserverMismatch);
    }
    if !snapshot.allowed_rooms.contains(&check.room_id) {
        return Err(MatrixInstallationPolicyRejection::RoomNotAllowed);
    }
    if check.egress_target_index != snapshot.egress_target_index {
        return Err(MatrixInstallationPolicyRejection::EgressTargetOutOfBounds);
    }
    if check.credential_handle != snapshot.credential_handle {
        return Err(MatrixInstallationPolicyRejection::CredentialHandleMismatch);
    }
    if check.guest_authorization_header_present {
        return Err(MatrixInstallationPolicyRejection::GuestCredentialMaterialRejected);
    }
    validate_matrix_send_path(&check.path)?;
    Ok(())
}

fn validate_matrix_send_path(path: &str) -> Result<(), MatrixInstallationPolicyRejection> {
    if path.contains("://")
        || path.contains('\\')
        || path.contains('\n')
        || path.contains('\r')
        || path.contains('\0')
        || path.contains("..")
        || path.starts_with("//")
        || path.contains("mxc://")
        || path.contains("file://")
    {
        return Err(MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape);
    }
    if path.starts_with("/_matrix/client/v3/rooms/") && path.contains("/send/m.room.message/") {
        Ok(())
    } else {
        Err(MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape)
    }
}
