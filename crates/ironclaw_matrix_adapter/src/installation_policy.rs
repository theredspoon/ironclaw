//! Host-owned Matrix ProductAdapter installation policy.
//!
//! Matrix installations need host-side room, sender, homeserver, artifact, and
//! credential binding before parse/render or HTTP egress can run. The policy
//! snapshot here is per installation and per request; it is not global adapter
//! state.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ironclaw_product_adapters::{
    AdapterInstallationId, DeclaredEgressTarget, EgressCredentialHandle, ProductAdapterId,
    ProtocolAuthEvidence,
};

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
    pub const ALL: [Self; 32] = [
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EgressTargetIndex(u32);

impl EgressTargetIndex {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
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

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
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
    pub declared_egress_targets: Vec<DeclaredEgressTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixActivationState {
    Disabled,
    Enabled,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationAuditMetadata {
    pub created_by: String,
    pub created_at_ms: u64,
    pub updated_by: String,
    pub updated_at_ms: u64,
    pub last_enable_actor: Option<String>,
    pub last_enable_at_ms: Option<u64>,
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

        match mutation {
            MatrixInstallationMutation::Enable {
                artifact_inspection,
            } => {
                validate_component_artifact(&self.component, &artifact_inspection)?;
                self.activation = MatrixActivationState::Enabled;
                self.policy_revision = self.policy_revision.next();
                self.audit.record_enable(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::Disable => {
                self.activation = MatrixActivationState::Disabled;
                self.policy_revision = self.policy_revision.next();
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::Delete => {
                self.activation = MatrixActivationState::Deleting;
                self.policy_revision = self.policy_revision.next();
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::UpdatePolicy { policy } => {
                self.policy = policy;
                self.policy_revision = self.policy_revision.next();
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::RebindArtifact {
                component,
                artifact_inspection,
            } => {
                validate_component_artifact(&component, &artifact_inspection)?;
                self.component = component;
                self.policy_revision = self.policy_revision.next();
                self.audit.record_update(actor.clone(), at_ms)?;
            }
            MatrixInstallationMutation::RebindCredential { credential_handle } => {
                self.policy.credential_handle = credential_handle;
                self.policy_revision = self.policy_revision.next();
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixInstallationMutationAuthority {
    pub can_manage_installations: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixInstallationMutationOperation {
    Enable,
    Disable,
    Delete,
    UpdatePolicy,
    RebindArtifact,
    RebindCredential,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMatrixAuthContext {
    subject: String,
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
    match target.credential_handle.as_ref() {
        Some(handle) if handle == &policy.credential_handle => Ok(()),
        Some(_) => Err(MatrixInstallationPolicyRejection::CredentialHandleMismatch),
        None => Err(MatrixInstallationPolicyRejection::CredentialHandleMissing),
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
    validate_matrix_send_path(&check.path, &check.room_id)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
