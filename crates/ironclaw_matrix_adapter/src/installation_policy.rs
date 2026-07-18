//! Host-owned Matrix ProductAdapter installation policy.
//!
//! Matrix installations need host-side room, sender, homeserver, artifact, and
//! credential binding before parse/render or HTTP egress can run. The policy
//! snapshot here is per installation and per request; it is not global adapter
//! state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use ironclaw_extensions::{
    ExtensionActivationState, ExtensionInstallationError, ExtensionInstallationId,
    ExtensionInstallationStore, InstallationOwner,
};
use ironclaw_host_api::UserId;
use ironclaw_product_adapter_registry::ProductAdapterRuntimeEntry;
use ironclaw_product_adapters::{
    AdapterInstallationId, DeclaredEgressHost, DeclaredEgressTarget, EgressCredentialHandle,
    ProductAdapterId, ProtocolAuthEvidence,
};
use ironclaw_wasm_product_adapters::{EgressPolicy, EgressPolicyError, EgressPolicyTarget};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    PolicyRevisionOverflow,
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
    pub const ALL: [Self; 33] = [
        Self::InstallationNotFound,
        Self::AmbiguousInstallation,
        Self::InstallationDisabled,
        Self::InstallationDeleting,
        Self::AdapterMismatch,
        Self::InstallationMismatch,
        Self::ArtifactHashMismatch,
        Self::ManifestHashMismatch,
        Self::WitWorldMismatch,
        Self::ArtifactSignatureInvalid,
        Self::UnexpectedGuestImport,
        Self::DirectHttpEgressDenied,
        Self::AuthMissing,
        Self::AuthInvalid,
        Self::AuthReplay,
        Self::PolicyRevisionOverflow,
        Self::RoomNotAllowed,
        Self::SenderNotAllowed,
        Self::HomeserverMismatch,
        Self::EgressTargetUndeclared,
        Self::EgressTargetOutOfBounds,
        Self::CredentialHandleMissing,
        Self::CredentialHandleMismatch,
        Self::CredentialHandleRevoked,
        Self::GuestCredentialMaterialRejected,
        Self::UnsafeMatrixRequestShape,
        Self::UnsafeRedirect,
        Self::PrivateNetworkTarget,
        Self::PolicyRevisionMismatch,
        Self::PolicySnapshotExpired,
        Self::MutationUnauthorized,
        Self::MutationRejected,
        Self::InvalidPolicyValue,
    ];

    pub fn external_response_shape(self) -> ExternalPolicyRejectionShape {
        ExternalPolicyRejectionShape {
            status: 403,
            body_code: "matrix_policy_denied",
        }
    }
}

impl std::fmt::Display for MatrixInstallationPolicyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalPolicyRejectionShape {
    pub status: u16,
    pub body_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for MatrixHomeserverOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            scheme: String,
            host: String,
            port: Option<u16>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let host = if wire.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]", wire.host)
        } else {
            wire.host
        };
        let mut origin = format!("{}://{}", wire.scheme, host);
        if let Some(port) = wire.port {
            origin.push(':');
            origin.push_str(&port.to_string());
        }
        Self::parse(origin).map_err(serde::de::Error::custom)
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
        let ip = host
            .parse::<Ipv6Addr>()
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
        if is_disallowed_ipv6(ip) {
            return Err(MatrixInstallationPolicyRejection::PrivateNetworkTarget);
        }
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
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || is_ipv4_documentation(ip)
        || ip.octets() == [169, 254, 169, 254]
}

fn is_ipv4_documentation(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_disallowed_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || is_ipv6_link_local(ip)
        || ip.is_multicast()
        || is_ipv6_documentation(ip)
        || ipv6_mapped_ipv4(ip).is_some_and(is_disallowed_ipv4)
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}

fn ipv6_mapped_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MatrixRoomId(String);

impl MatrixRoomId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        let value = value.into();
        // Matrix localparts can be case-sensitive. Until a Matrix SDK-backed
        // canonicalizer owns server-name normalization, store IDs verbatim and
        // fail closed on mismatches rather than guessing.
        if value.starts_with('!')
            && value.contains(':')
            && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            Ok(Self(value))
        } else {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MatrixRoomId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MatrixUserId(String);

impl MatrixUserId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        let value = value.into();
        // See MatrixRoomId: this policy layer intentionally avoids partial
        // normalization that could rewrite a case-sensitive identifier.
        if value.starts_with('@')
            && value.contains(':')
            && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            Ok(Self(value))
        } else {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MatrixUserId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressTargetIndex(u32);

impl EgressTargetIndex {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PolicyRevision(u64);

impl PolicyRevision {
    pub fn new(value: u64) -> Result<Self, MatrixInstallationPolicyRejection> {
        if value == 0 {
            Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
        } else {
            Ok(Self(value))
        }
    }

    pub fn next(self) -> Result<Self, MatrixInstallationPolicyRejection> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(MatrixInstallationPolicyRejection::PolicyRevisionOverflow)
    }
}

impl<'de> Deserialize<'de> for PolicyRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ComponentArtifactId(String);

impl ComponentArtifactId {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

impl<'de> Deserialize<'de> for ComponentArtifactId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
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

impl<'de> Deserialize<'de> for ArtifactSha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct WitPackageName(String);

impl WitPackageName {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

impl<'de> Deserialize<'de> for WitPackageName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct WitWorldName(String);

impl WitWorldName {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

impl<'de> Deserialize<'de> for WitWorldName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Typed binding to the source-verified ProductAdapter manifest/runtime identity.
/// The Matrix policy layer stores the manifest identity, not a duplicate manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StaticManifestBinding(String);

impl StaticManifestBinding {
    pub fn new(value: impl Into<String>) -> Result<Self, MatrixInstallationPolicyRejection> {
        non_empty(value.into()).map(Self)
    }
}

impl<'de> Deserialize<'de> for StaticManifestBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn non_empty(value: String) -> Result<String, MatrixInstallationPolicyRejection> {
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
    } else {
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentArtifactBinding {
    pub artifact_id: ComponentArtifactId,
    pub artifact_sha256: ArtifactSha256,
    pub wit_package: WitPackageName,
    pub wit_world: WitWorldName,
    pub manifest: StaticManifestBinding,
    pub declared_egress_targets: Vec<DeclaredEgressTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRuntimeArtifactEvidence {
    pub artifact_id: ComponentArtifactId,
    pub artifact_sha256: ArtifactSha256,
    pub wit_package: WitPackageName,
    pub wit_world: WitWorldName,
}

pub fn project_matrix_installation_from_runtime_entry(
    entry: &ProductAdapterRuntimeEntry,
    artifact: MatrixRuntimeArtifactEvidence,
    policy: MatrixInstallationPolicy,
    audit: InstallationAuditMetadata,
) -> Result<MatrixProductAdapterInstallation, MatrixInstallationPolicyRejection> {
    let manifest_hash = entry
        .installation()
        .manifest_ref()
        .manifest_hash()
        .ok_or(MatrixInstallationPolicyRejection::ManifestHashMismatch)?;
    let component = ComponentArtifactBinding {
        artifact_id: artifact.artifact_id,
        artifact_sha256: artifact.artifact_sha256,
        wit_package: artifact.wit_package,
        wit_world: artifact.wit_world,
        manifest: StaticManifestBinding::new(manifest_hash.as_str())?,
        declared_egress_targets: entry.adapter().declared_egress().to_vec(),
    };

    validate_component_policy_binding(&component, &policy)?;
    MatrixProductAdapterInstallation::new(
        entry.adapter().adapter_id().clone(),
        AdapterInstallationId::new(entry.installation().installation_id().as_str())
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?,
        component,
        policy,
        MatrixActivationState::Enabled,
        PolicyRevision::new(1)?,
        audit,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentArtifactInspection {
    pub artifact_sha256: ArtifactSha256,
    pub wit_package: WitPackageName,
    pub wit_world: WitWorldName,
    pub manifest: StaticManifestBinding,
    pub required_exports_present: bool,
    pub unexpected_imports: Vec<String>,
    pub direct_http_egress_import: bool,
    pub signature_valid: Option<bool>,
}

pub fn validate_component_artifact(
    binding: &ComponentArtifactBinding,
    inspection: &ComponentArtifactInspection,
) -> Result<(), MatrixInstallationPolicyRejection> {
    if binding.artifact_sha256 != inspection.artifact_sha256 {
        return Err(MatrixInstallationPolicyRejection::ArtifactHashMismatch);
    }
    if binding.manifest != inspection.manifest {
        return Err(MatrixInstallationPolicyRejection::ManifestHashMismatch);
    }
    if binding.wit_package != inspection.wit_package || binding.wit_world != inspection.wit_world {
        return Err(MatrixInstallationPolicyRejection::WitWorldMismatch);
    }
    if !inspection.required_exports_present
        || !inspection.unexpected_imports.is_empty()
        || inspection.direct_http_egress_import
    {
        return Err(MatrixInstallationPolicyRejection::UnexpectedGuestImport);
    }
    if inspection.signature_valid != Some(true) {
        return Err(MatrixInstallationPolicyRejection::ArtifactSignatureInvalid);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixActivationState {
    Disabled,
    Enabled,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallationAuditMetadata {
    pub created_by: String,
    pub created_at_ms: u64,
    pub updated_by: String,
    pub updated_at_ms: u64,
    pub last_enable_actor: Option<String>,
    pub last_enable_at_ms: Option<u64>,
}

impl<'de> Deserialize<'de> for InstallationAuditMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            created_by: String,
            created_at_ms: u64,
            updated_by: String,
            updated_at_ms: u64,
            last_enable_actor: Option<String>,
            last_enable_at_ms: Option<u64>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let audit = Self {
            created_by: non_empty(wire.created_by).map_err(serde::de::Error::custom)?,
            created_at_ms: wire.created_at_ms,
            updated_by: non_empty(wire.updated_by).map_err(serde::de::Error::custom)?,
            updated_at_ms: wire.updated_at_ms,
            last_enable_actor: wire
                .last_enable_actor
                .map(non_empty)
                .transpose()
                .map_err(serde::de::Error::custom)?,
            last_enable_at_ms: wire.last_enable_at_ms,
        };
        Ok(audit)
    }
}

impl InstallationAuditMetadata {
    pub fn new(
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        let actor = non_empty(actor.into())?;
        Ok(Self {
            created_by: actor.clone(),
            created_at_ms: at_ms,
            updated_by: actor,
            updated_at_ms: at_ms,
            last_enable_actor: None,
            last_enable_at_ms: None,
        })
    }

    pub fn record_update(
        &mut self,
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        self.updated_by = non_empty(actor.into())?;
        self.updated_at_ms = at_ms;
        Ok(())
    }

    pub fn record_enable(
        &mut self,
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        let actor = non_empty(actor.into())?;
        self.updated_by = actor.clone();
        self.updated_at_ms = at_ms;
        self.last_enable_actor = Some(actor);
        self.last_enable_at_ms = Some(at_ms);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixInstallationPolicy {
    pub homeserver: MatrixHomeserverOrigin,
    pub allowed_rooms: BTreeSet<MatrixRoomId>,
    pub allowed_senders: BTreeSet<MatrixUserId>,
    pub egress_target_index: EgressTargetIndex,
    pub credential_handle: EgressCredentialHandle,
}

impl<'de> Deserialize<'de> for MatrixInstallationPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            homeserver: MatrixHomeserverOrigin,
            allowed_rooms: BTreeSet<MatrixRoomId>,
            allowed_senders: BTreeSet<MatrixUserId>,
            egress_target_index: EgressTargetIndex,
            credential_handle: EgressCredentialHandle,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.homeserver,
            wire.allowed_rooms,
            wire.allowed_senders,
            wire.egress_target_index,
            wire.credential_handle,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl MatrixInstallationPolicy {
    pub fn new(
        homeserver: MatrixHomeserverOrigin,
        allowed_rooms: BTreeSet<MatrixRoomId>,
        allowed_senders: BTreeSet<MatrixUserId>,
        egress_target_index: EgressTargetIndex,
        credential_handle: EgressCredentialHandle,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        Ok(Self {
            homeserver,
            allowed_rooms,
            allowed_senders,
            egress_target_index,
            credential_handle,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixProductAdapterInstallation {
    pub adapter_id: ProductAdapterId,
    pub installation_id: AdapterInstallationId,
    pub component: ComponentArtifactBinding,
    pub policy: MatrixInstallationPolicy,
    pub activation: MatrixActivationState,
    pub policy_revision: PolicyRevision,
    pub audit: InstallationAuditMetadata,
}

impl<'de> Deserialize<'de> for MatrixProductAdapterInstallation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            adapter_id: ProductAdapterId,
            installation_id: AdapterInstallationId,
            component: ComponentArtifactBinding,
            policy: MatrixInstallationPolicy,
            activation: MatrixActivationState,
            policy_revision: PolicyRevision,
            audit: InstallationAuditMetadata,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.adapter_id,
            wire.installation_id,
            wire.component,
            wire.policy,
            wire.activation,
            wire.policy_revision,
            wire.audit,
        )
        .map_err(serde::de::Error::custom)
    }
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
        validate_component_policy_binding(&component, &policy)?;
        if activation == MatrixActivationState::Enabled {
            validate_enabled_policy_allowlists(&policy)?;
        }
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

    pub fn create_disabled(
        adapter_id: ProductAdapterId,
        installation_id: AdapterInstallationId,
        component: ComponentArtifactBinding,
        policy: MatrixInstallationPolicy,
        audit: InstallationAuditMetadata,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        Self::new(
            adapter_id,
            installation_id,
            component,
            policy,
            MatrixActivationState::Disabled,
            PolicyRevision::new(1)?,
            audit,
        )
    }

    pub fn apply_mutation(
        &mut self,
        mutation: MatrixInstallationMutation,
        authority: &MatrixInstallationMutationAuthority,
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<MatrixInstallationAuditEvent, MatrixInstallationPolicyRejection> {
        if !authority.can_manage_installations {
            return Err(MatrixInstallationPolicyRejection::MutationUnauthorized);
        }
        let actor = non_empty(actor.into())?;
        let previous_activation = self.activation;
        let previous_revision = self.policy_revision;
        let operation = mutation.operation();
        let next_revision = self.policy_revision.next()?;

        match mutation {
            MatrixInstallationMutation::Enable {
                artifact_inspection,
            } => {
                validate_component_artifact(&self.component, &artifact_inspection)?;
                validate_component_policy_binding(&self.component, &self.policy)?;
                validate_enabled_policy_allowlists(&self.policy)?;
                self.activation = MatrixActivationState::Enabled;
                self.policy_revision = next_revision;
                self.audit.record_enable(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::Disable => {
                self.activation = MatrixActivationState::Disabled;
                self.policy_revision = next_revision;
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::Delete => {
                self.activation = MatrixActivationState::Deleting;
                self.policy_revision = next_revision;
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::UpdatePolicy { policy } => {
                validate_component_policy_binding(&self.component, &policy)?;
                if self.activation == MatrixActivationState::Enabled {
                    validate_enabled_policy_allowlists(&policy)?;
                }
                self.policy = policy;
                self.policy_revision = next_revision;
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::RebindArtifact {
                component,
                artifact_inspection,
            } => {
                validate_component_artifact(&component, &artifact_inspection)?;
                validate_component_policy_binding(&component, &self.policy)?;
                self.component = component;
                self.policy_revision = next_revision;
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::RebindCredential { credential_handle } => {
                let mut policy = self.policy.clone();
                policy.credential_handle = credential_handle;
                validate_component_policy_binding(&self.component, &policy)?;
                self.policy = policy;
                self.policy_revision = next_revision;
                self.audit.record_update(actor.clone(), at_ms)?;
            }
        }

        Ok(MatrixInstallationAuditEvent {
            actor,
            operation,
            installation_id: self.installation_id.clone(),
            previous_activation,
            next_activation: self.activation,
            previous_revision,
            next_revision: self.policy_revision,
            rejected_reason: None,
            at_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixInstallationMutationAuthority {
    pub can_manage_installations: bool,
}

impl MatrixInstallationMutationAuthority {
    pub fn tenant_operator() -> Self {
        Self {
            can_manage_installations: true,
        }
    }

    pub fn deny() -> Self {
        Self {
            can_manage_installations: false,
        }
    }

    pub fn from_installation_owner(
        owner: &InstallationOwner,
        actor: &UserId,
        tenant_operator: &UserId,
    ) -> Self {
        Self {
            can_manage_installations: if owner.is_tenant() {
                actor == tenant_operator
            } else {
                owner
                    .members()
                    .is_some_and(|members| members.contains(actor))
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixInstallationMutation {
    Enable {
        artifact_inspection: ComponentArtifactInspection,
    },
    Disable,
    Delete,
    UpdatePolicy {
        policy: MatrixInstallationPolicy,
    },
    RebindArtifact {
        component: ComponentArtifactBinding,
        artifact_inspection: ComponentArtifactInspection,
    },
    RebindCredential {
        credential_handle: EgressCredentialHandle,
    },
}

impl MatrixInstallationMutation {
    fn operation(&self) -> MatrixInstallationMutationOperation {
        match self {
            Self::Enable { .. } => MatrixInstallationMutationOperation::Enable,
            Self::Disable => MatrixInstallationMutationOperation::Disable,
            Self::Delete => MatrixInstallationMutationOperation::Delete,
            Self::UpdatePolicy { .. } => MatrixInstallationMutationOperation::UpdatePolicy,
            Self::RebindArtifact { .. } => MatrixInstallationMutationOperation::RebindArtifact,
            Self::RebindCredential { .. } => MatrixInstallationMutationOperation::RebindCredential,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixInstallationMutationOperation {
    Create,
    Enable,
    Disable,
    Delete,
    UpdatePolicy,
    RebindArtifact,
    RebindCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixExtensionLifecycleMutation {
    Enable,
    Disable,
    Delete,
}

impl MatrixExtensionLifecycleMutation {
    fn activation_state(self) -> Option<ExtensionActivationState> {
        match self {
            Self::Enable => Some(ExtensionActivationState::Enabled),
            Self::Disable => Some(ExtensionActivationState::Disabled),
            Self::Delete => None,
        }
    }
}

pub async fn apply_matrix_extension_lifecycle_mutation(
    store: &dyn ExtensionInstallationStore,
    installation_id: &AdapterInstallationId,
    mutation: MatrixExtensionLifecycleMutation,
    actor: &UserId,
    tenant_operator: &UserId,
) -> Result<(), MatrixInstallationPolicyRejection> {
    let extension_installation_id = extension_installation_id(installation_id)?;
    let installation = store
        .get_installation(&extension_installation_id)
        .await
        .map_err(matrix_rejection_from_extension_error)?
        .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
    let authority = MatrixInstallationMutationAuthority::from_installation_owner(
        installation.owner(),
        actor,
        tenant_operator,
    );
    if !authority.can_manage_installations {
        return Err(MatrixInstallationPolicyRejection::MutationUnauthorized);
    }

    if let Some(state) = mutation.activation_state() {
        store
            .set_activation_state(&extension_installation_id, state)
            .await
            .map_err(matrix_rejection_from_extension_error)
    } else {
        store
            .delete_installation(&extension_installation_id)
            .await
            .map_err(matrix_rejection_from_extension_error)
    }
}

fn extension_installation_id(
    installation_id: &AdapterInstallationId,
) -> Result<ExtensionInstallationId, MatrixInstallationPolicyRejection> {
    ExtensionInstallationId::new(installation_id.as_str())
        .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)
}

fn matrix_rejection_from_extension_error(
    error: ExtensionInstallationError,
) -> MatrixInstallationPolicyRejection {
    match error {
        ExtensionInstallationError::InstallationNotFound { .. } => {
            MatrixInstallationPolicyRejection::InstallationNotFound
        }
        ExtensionInstallationError::ManifestHashMismatch { .. }
        | ExtensionInstallationError::ConflictingManifestReference { .. } => {
            MatrixInstallationPolicyRejection::ManifestHashMismatch
        }
        ExtensionInstallationError::ManifestNotFound { .. }
        | ExtensionInstallationError::UnknownManifest { .. } => {
            MatrixInstallationPolicyRejection::InstallationNotFound
        }
        ExtensionInstallationError::DuplicateCredentialBinding { .. }
        | ExtensionInstallationError::ConflictingCredentialBinding { .. } => {
            MatrixInstallationPolicyRejection::CredentialHandleMismatch
        }
        _ => MatrixInstallationPolicyRejection::MutationRejected,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixInstallationAuditEvent {
    pub actor: String,
    pub operation: MatrixInstallationMutationOperation,
    pub installation_id: AdapterInstallationId,
    pub previous_activation: MatrixActivationState,
    pub next_activation: MatrixActivationState,
    pub previous_revision: PolicyRevision,
    pub next_revision: PolicyRevision,
    pub rejected_reason: Option<MatrixInstallationPolicyRejection>,
    pub at_ms: u64,
}

impl<'de> Deserialize<'de> for MatrixInstallationAuditEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            actor: String,
            operation: MatrixInstallationMutationOperation,
            installation_id: AdapterInstallationId,
            previous_activation: MatrixActivationState,
            next_activation: MatrixActivationState,
            previous_revision: PolicyRevision,
            next_revision: PolicyRevision,
            rejected_reason: Option<MatrixInstallationPolicyRejection>,
            at_ms: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            actor: non_empty(wire.actor).map_err(serde::de::Error::custom)?,
            operation: wire.operation,
            installation_id: wire.installation_id,
            previous_activation: wire.previous_activation,
            next_activation: wire.next_activation,
            previous_revision: wire.previous_revision,
            next_revision: wire.next_revision,
            rejected_reason: wire.rejected_reason,
            at_ms: wire.at_ms,
        })
    }
}

impl MatrixInstallationAuditEvent {
    pub fn accepted(
        installation: &MatrixProductAdapterInstallation,
        operation: MatrixInstallationMutationOperation,
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        let actor = non_empty(actor.into())?;
        Ok(Self {
            actor,
            operation,
            installation_id: installation.installation_id.clone(),
            previous_activation: installation.activation,
            next_activation: installation.activation,
            previous_revision: installation.policy_revision,
            next_revision: installation.policy_revision,
            rejected_reason: None,
            at_ms,
        })
    }

    pub fn rejected(
        installation: &MatrixProductAdapterInstallation,
        operation: MatrixInstallationMutationOperation,
        actor: impl Into<String>,
        reason: MatrixInstallationPolicyRejection,
        at_ms: u64,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        let actor = non_empty(actor.into())?;
        Ok(Self {
            actor,
            operation,
            installation_id: installation.installation_id.clone(),
            previous_activation: installation.activation,
            next_activation: installation.activation,
            previous_revision: installation.policy_revision,
            next_revision: installation.policy_revision,
            rejected_reason: Some(reason),
            at_ms,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MatrixInstallationProjectionCache {
    installations: BTreeMap<AdapterInstallationId, MatrixProductAdapterInstallation>,
    audit_events: Vec<MatrixInstallationAuditEvent>,
}

impl<'de> Deserialize<'de> for MatrixInstallationProjectionCache {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default)]
            installations: BTreeMap<AdapterInstallationId, MatrixProductAdapterInstallation>,
            #[serde(default)]
            audit_events: Vec<MatrixInstallationAuditEvent>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let cache = Self {
            installations: wire.installations,
            audit_events: wire.audit_events,
        };
        cache
            .validate_persisted_state()
            .map_err(serde::de::Error::custom)?;
        Ok(cache)
    }
}

#[derive(Debug)]
pub enum MatrixInstallationProjectionStoreError {
    Read(io::Error),
    Decode(serde_json::Error),
    Encode(serde_json::Error),
    CreateDirectory(io::Error),
    Write(io::Error),
    Commit(io::Error),
}

impl fmt::Display for MatrixInstallationProjectionStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(source) => write!(f, "failed to read Matrix policy snapshot: {source}"),
            Self::Decode(source) => {
                write!(f, "failed to decode Matrix policy snapshot: {source}")
            }
            Self::Encode(source) => {
                write!(f, "failed to encode Matrix policy snapshot: {source}")
            }
            Self::CreateDirectory(source) => {
                write!(
                    f,
                    "failed to create Matrix policy snapshot directory: {source}"
                )
            }
            Self::Write(source) => write!(f, "failed to write Matrix policy snapshot: {source}"),
            Self::Commit(source) => write!(f, "failed to commit Matrix policy snapshot: {source}"),
        }
    }
}

impl std::error::Error for MatrixInstallationProjectionStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(source)
            | Self::CreateDirectory(source)
            | Self::Write(source)
            | Self::Commit(source) => Some(source),
            Self::Decode(source) | Self::Encode(source) => Some(source),
        }
    }
}

fn durable_snapshot_tmp_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "matrix-installation-policy.json".into());
    file_name.push(".tmp");
    path.with_file_name(file_name)
}

impl MatrixInstallationProjectionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub fn from_json_str(value: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(value)
    }

    pub fn load_from_path(
        path: impl AsRef<Path>,
    ) -> Result<Self, MatrixInstallationProjectionStoreError> {
        let bytes = fs::read(path).map_err(MatrixInstallationProjectionStoreError::Read)?;
        Self::from_json_bytes(&bytes).map_err(MatrixInstallationProjectionStoreError::Decode)
    }

    pub fn save_to_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), MatrixInstallationProjectionStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(MatrixInstallationProjectionStoreError::CreateDirectory)?;
        }

        let bytes = self
            .to_json_bytes()
            .map_err(MatrixInstallationProjectionStoreError::Encode)?;
        let tmp_path = durable_snapshot_tmp_path(path);
        fs::write(&tmp_path, bytes).map_err(MatrixInstallationProjectionStoreError::Write)?;
        fs::rename(&tmp_path, path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            MatrixInstallationProjectionStoreError::Commit(source)
        })?;
        Ok(())
    }

    pub fn insert_projection(
        &mut self,
        installation: MatrixProductAdapterInstallation,
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        let actor = non_empty(actor.into())?;
        if self
            .installations
            .contains_key(&installation.installation_id)
        {
            self.audit_events
                .push(MatrixInstallationAuditEvent::rejected(
                    &installation,
                    MatrixInstallationMutationOperation::Create,
                    actor,
                    MatrixInstallationPolicyRejection::MutationRejected,
                    at_ms,
                )?);
            return Err(MatrixInstallationPolicyRejection::MutationRejected);
        }
        if let Err(reason) = self.validate_no_enabled_scope_overlap(&installation, None) {
            self.audit_events
                .push(MatrixInstallationAuditEvent::rejected(
                    &installation,
                    MatrixInstallationMutationOperation::Create,
                    actor,
                    reason,
                    at_ms,
                )?);
            return Err(reason);
        }
        self.audit_events
            .push(MatrixInstallationAuditEvent::accepted(
                &installation,
                MatrixInstallationMutationOperation::Create,
                actor,
                at_ms,
            )?);
        self.installations
            .insert(installation.installation_id.clone(), installation);
        Ok(())
    }

    pub fn apply_policy_mutation(
        &mut self,
        installation_id: &AdapterInstallationId,
        mutation: MatrixInstallationMutation,
        authority: &MatrixInstallationMutationAuthority,
        actor: impl Into<String>,
        at_ms: u64,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        let actor = non_empty(actor.into())?;
        let operation = mutation.operation();
        let installation_for_precheck = self
            .installations
            .get(installation_id)
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        if matches!(
            mutation,
            MatrixInstallationMutation::Enable { .. }
                | MatrixInstallationMutation::Disable
                | MatrixInstallationMutation::Delete
        ) {
            self.audit_events
                .push(MatrixInstallationAuditEvent::rejected(
                    installation_for_precheck,
                    operation,
                    actor,
                    MatrixInstallationPolicyRejection::MutationRejected,
                    at_ms,
                )?);
            return Err(MatrixInstallationPolicyRejection::MutationRejected);
        }
        if !authority.can_manage_installations {
            self.audit_events
                .push(MatrixInstallationAuditEvent::rejected(
                    installation_for_precheck,
                    operation,
                    actor,
                    MatrixInstallationPolicyRejection::MutationUnauthorized,
                    at_ms,
                )?);
            return Err(MatrixInstallationPolicyRejection::MutationUnauthorized);
        }
        if let MatrixInstallationMutation::UpdatePolicy { policy } = &mutation
            && installation_for_precheck.activation == MatrixActivationState::Enabled
        {
            let mut candidate = installation_for_precheck.clone();
            candidate.policy = policy.clone();
            if let Err(reason) =
                self.validate_no_enabled_scope_overlap(&candidate, Some(installation_id))
            {
                self.audit_events
                    .push(MatrixInstallationAuditEvent::rejected(
                        installation_for_precheck,
                        operation,
                        actor,
                        reason,
                        at_ms,
                    )?);
                return Err(reason);
            }
        }
        let installation = self
            .installations
            .get_mut(installation_id)
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        match installation.apply_mutation(mutation, authority, actor.clone(), at_ms) {
            Ok(event) => {
                self.audit_events.push(event);
                Ok(())
            }
            Err(reason) => {
                self.audit_events
                    .push(MatrixInstallationAuditEvent::rejected(
                        installation,
                        operation,
                        actor,
                        reason,
                        at_ms,
                    )?);
                Err(reason)
            }
        }
    }

    pub fn installation(
        &self,
        installation_id: &AdapterInstallationId,
    ) -> Option<&MatrixProductAdapterInstallation> {
        self.installations.get(installation_id)
    }

    pub fn installations(&self) -> impl Iterator<Item = &MatrixProductAdapterInstallation> {
        self.installations.values()
    }

    pub fn audit_events(&self) -> &[MatrixInstallationAuditEvent] {
        &self.audit_events
    }

    fn validate_persisted_state(&self) -> Result<(), MatrixInstallationPolicyRejection> {
        for (key, installation) in &self.installations {
            if key != &installation.installation_id {
                return Err(MatrixInstallationPolicyRejection::InstallationMismatch);
            }
            validate_persisted_installation(installation)?;
            self.validate_no_enabled_scope_overlap(installation, Some(key))?;
        }
        for event in &self.audit_events {
            non_empty(event.actor.clone())?;
        }
        Ok(())
    }

    fn validate_no_enabled_scope_overlap(
        &self,
        candidate: &MatrixProductAdapterInstallation,
        replacing: Option<&AdapterInstallationId>,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        if candidate.activation != MatrixActivationState::Enabled {
            return Ok(());
        }
        validate_enabled_policy_allowlists(&candidate.policy)?;
        for existing in self.installations.values() {
            if Some(&existing.installation_id) == replacing {
                continue;
            }
            if enabled_matrix_scopes_overlap(candidate, existing) {
                return Err(MatrixInstallationPolicyRejection::AmbiguousInstallation);
            }
        }
        Ok(())
    }
}

fn validate_persisted_installation(
    installation: &MatrixProductAdapterInstallation,
) -> Result<(), MatrixInstallationPolicyRejection> {
    validate_persisted_audit_metadata(&installation.audit)?;
    if installation.activation == MatrixActivationState::Enabled {
        validate_enabled_policy_allowlists(&installation.policy)?;
    }
    validate_component_policy_binding(&installation.component, &installation.policy)
}

fn validate_enabled_policy_allowlists(
    policy: &MatrixInstallationPolicy,
) -> Result<(), MatrixInstallationPolicyRejection> {
    if policy.allowed_rooms.is_empty() || policy.allowed_senders.is_empty() {
        Err(MatrixInstallationPolicyRejection::InvalidPolicyValue)
    } else {
        Ok(())
    }
}

fn enabled_matrix_scopes_overlap(
    left: &MatrixProductAdapterInstallation,
    right: &MatrixProductAdapterInstallation,
) -> bool {
    left.activation == MatrixActivationState::Enabled
        && right.activation == MatrixActivationState::Enabled
        && left.policy.homeserver == right.policy.homeserver
        && left
            .policy
            .allowed_rooms
            .iter()
            .any(|room| right.policy.allowed_rooms.contains(room))
        && left
            .policy
            .allowed_senders
            .iter()
            .any(|sender| right.policy.allowed_senders.contains(sender))
}

fn validate_persisted_audit_metadata(
    audit: &InstallationAuditMetadata,
) -> Result<(), MatrixInstallationPolicyRejection> {
    non_empty(audit.created_by.clone())?;
    non_empty(audit.updated_by.clone())?;
    if let Some(actor) = &audit.last_enable_actor {
        non_empty(actor.clone())?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixInboundRoutingContext {
    pub homeserver: MatrixHomeserverOrigin,
    pub room_id: MatrixRoomId,
    pub sender: MatrixUserId,
    pub auth: VerifiedMatrixAuthContext,
    pub received_at_ms: u64,
}

impl MatrixInboundRoutingContext {
    pub fn from_verified_auth(
        homeserver: MatrixHomeserverOrigin,
        room_id: MatrixRoomId,
        sender: MatrixUserId,
        auth_evidence: &ProtocolAuthEvidence,
        received_at_ms: u64,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        Ok(Self {
            homeserver,
            room_id,
            sender,
            auth: VerifiedMatrixAuthContext::from_evidence(auth_evidence)?,
            received_at_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedMatrixAuthContext {
    subject: String,
}

impl<'de> Deserialize<'de> for VerifiedMatrixAuthContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
        Err(serde::de::Error::custom(
            "VerifiedMatrixAuthContext is host-minted from protocol auth evidence",
        ))
    }
}

impl VerifiedMatrixAuthContext {
    pub fn from_evidence(
        auth_evidence: &ProtocolAuthEvidence,
    ) -> Result<Self, MatrixInstallationPolicyRejection> {
        let claim = auth_evidence
            .claim()
            .ok_or(MatrixInstallationPolicyRejection::AuthInvalid)?;
        Ok(Self {
            subject: non_empty(claim.subject().to_string())?,
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        validate_component_policy_binding(&installation.component, &installation.policy)?;
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

fn validate_component_policy_binding(
    component: &ComponentArtifactBinding,
    policy: &MatrixInstallationPolicy,
) -> Result<(), MatrixInstallationPolicyRejection> {
    let target = component
        .declared_egress_targets
        .get(policy.egress_target_index.as_usize())
        .ok_or(MatrixInstallationPolicyRejection::EgressTargetOutOfBounds)?;

    if target.host.as_str() != policy.homeserver.host() {
        return Err(MatrixInstallationPolicyRejection::HomeserverMismatch);
    }
    let egress_policy = EgressPolicy::new(component.declared_egress_targets.clone());
    let host = DeclaredEgressHost::new(target.host.as_str())
        .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
    if target.credential_handle.as_ref() != Some(&policy.credential_handle) {
        return match target.credential_handle.as_ref() {
            Some(_) => Err(MatrixInstallationPolicyRejection::CredentialHandleMismatch),
            None => Err(MatrixInstallationPolicyRejection::CredentialHandleMissing),
        };
    }
    match egress_policy.check(EgressPolicyTarget {
        host: &host,
        credential_handle: Some(&policy.credential_handle),
    }) {
        Ok(()) => Ok(()),
        Err(EgressPolicyError::UndeclaredHost { .. }) => {
            Err(MatrixInstallationPolicyRejection::EgressTargetUndeclared)
        }
        Err(EgressPolicyError::UnauthorizedCredentialHandle { .. })
        | Err(EgressPolicyError::CredentialHandleNotPairedWithHost { .. }) => {
            Err(MatrixInstallationPolicyRejection::CredentialHandleMismatch)
        }
        Err(EgressPolicyError::UnauthenticatedEgressNotDeclared { .. }) => {
            Err(MatrixInstallationPolicyRejection::CredentialHandleMissing)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    validate_matrix_send_path(&check.path, &check.room_id)?;
    Ok(())
}

pub async fn authorize_matrix_outbound_with_extension_lifecycle(
    store: &dyn ExtensionInstallationStore,
    snapshot: &MatrixPolicySnapshot,
    check: &MatrixOutboundPolicyCheck,
) -> Result<(), MatrixInstallationPolicyRejection> {
    let extension_installation_id = extension_installation_id(&snapshot.installation_id)?;
    let installation = store
        .get_installation(&extension_installation_id)
        .await
        .map_err(matrix_rejection_from_extension_error)?
        .ok_or(MatrixInstallationPolicyRejection::InstallationDeleting)?;
    match installation.activation_state() {
        ExtensionActivationState::Enabled => authorize_matrix_outbound(snapshot, check),
        ExtensionActivationState::Installed | ExtensionActivationState::Disabled => {
            Err(MatrixInstallationPolicyRejection::InstallationDisabled)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixCredentialState {
    Active,
    Missing,
    Stale,
    Revoked,
    Rotated,
    WrongHomeserver,
}

pub fn validate_matrix_credential_state(
    state: MatrixCredentialState,
) -> Result<(), MatrixInstallationPolicyRejection> {
    match state {
        MatrixCredentialState::Active => Ok(()),
        MatrixCredentialState::Missing => {
            Err(MatrixInstallationPolicyRejection::CredentialHandleMissing)
        }
        MatrixCredentialState::Stale
        | MatrixCredentialState::Revoked
        | MatrixCredentialState::Rotated => {
            Err(MatrixInstallationPolicyRejection::CredentialHandleRevoked)
        }
        MatrixCredentialState::WrongHomeserver => {
            Err(MatrixInstallationPolicyRejection::HomeserverMismatch)
        }
    }
}

fn validate_matrix_send_path(
    path: &str,
    room_id: &MatrixRoomId,
) -> Result<(), MatrixInstallationPolicyRejection> {
    if path.contains("://")
        || path.contains('\\')
        || path.contains('?')
        || path.contains('#')
        || path.contains('%')
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

    let rest = path
        .strip_prefix("/_matrix/client/v3/rooms/")
        .ok_or(MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape)?;
    let (path_room, txn) = rest
        .split_once("/send/m.room.message/")
        .ok_or(MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape)?;
    if path_room != room_id.0 || txn.is_empty() || txn.contains('/') {
        return Err(MatrixInstallationPolicyRejection::UnsafeMatrixRequestShape);
    }
    Ok(())
}
