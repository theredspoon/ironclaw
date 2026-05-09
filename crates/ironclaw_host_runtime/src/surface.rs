use ironclaw_authorization::TrustAwareCapabilityDispatchAuthorizer;
use ironclaw_extensions::ExtensionRegistry;
use ironclaw_host_api::{
    CapabilityDescriptor, Decision, EffectKind, ResourceEstimate, RuntimeKind,
};
use ironclaw_trust::TrustDecision;
use serde_json::json;

use crate::{
    CapabilitySurfaceVersion, HostRuntimeError, VisibleCapabilityRequest, VisibleCapabilitySurface,
};

const ALL_RUNTIME_KINDS: &[RuntimeKind] = &[
    RuntimeKind::Wasm,
    RuntimeKind::Mcp,
    RuntimeKind::Script,
    RuntimeKind::FirstParty,
    RuntimeKind::System,
];

const ALL_EFFECT_KINDS: &[EffectKind] = &[
    EffectKind::ReadFilesystem,
    EffectKind::WriteFilesystem,
    EffectKind::DeleteFilesystem,
    EffectKind::Network,
    EffectKind::UseSecret,
    EffectKind::ExecuteCode,
    EffectKind::SpawnProcess,
    EffectKind::DispatchCapability,
    EffectKind::ModifyExtension,
    EffectKind::ModifyApproval,
    EffectKind::ModifyBudget,
    EffectKind::ExternalWrite,
    EffectKind::Financial,
];

/// Visibility-only policy applied before authorization estimates are rendered.
///
/// This is a narrowing surface policy, not an authority source. A runtime/effect
/// listed here can still be omitted by missing grants, denied trust ceilings, or
/// an authorizer denial. A runtime/effect absent here is omitted before the
/// authorizer is consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySurfacePolicy {
    pub allowed_runtimes: Vec<RuntimeKind>,
    pub allowed_effects: Vec<EffectKind>,
    pub include_requires_approval: bool,
    pub max_capabilities: Option<usize>,
}

impl CapabilitySurfacePolicy {
    pub fn allow_all() -> Self {
        Self {
            allowed_runtimes: ALL_RUNTIME_KINDS.to_vec(),
            allowed_effects: ALL_EFFECT_KINDS.to_vec(),
            include_requires_approval: true,
            max_capabilities: None,
        }
    }

    fn allows_runtime(&self, runtime: RuntimeKind) -> bool {
        self.allowed_runtimes.contains(&runtime)
    }

    fn allows_effects(&self, effects: &[EffectKind]) -> bool {
        effects
            .iter()
            .all(|effect| self.allowed_effects.contains(effect))
    }
}

impl Default for CapabilitySurfacePolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisibleCapabilityAccess {
    Available,
    RequiresApproval,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VisibleCapability {
    pub descriptor: CapabilityDescriptor,
    pub access: VisibleCapabilityAccess,
    pub estimated_resources: ResourceEstimate,
}

pub(crate) struct CapabilityCatalog<'a> {
    registry: &'a ExtensionRegistry,
    authorizer: &'a dyn TrustAwareCapabilityDispatchAuthorizer,
    base_version: &'a CapabilitySurfaceVersion,
}

impl<'a> CapabilityCatalog<'a> {
    pub(crate) fn new(
        registry: &'a ExtensionRegistry,
        authorizer: &'a dyn TrustAwareCapabilityDispatchAuthorizer,
        base_version: &'a CapabilitySurfaceVersion,
    ) -> Self {
        Self {
            registry,
            authorizer,
            base_version,
        }
    }

    pub(crate) async fn visible_capabilities<'b>(
        &self,
        request: VisibleCapabilityRequest,
        mut trust_decision_for: impl FnMut(&'b CapabilityDescriptor) -> Option<TrustDecision>,
    ) -> Result<VisibleCapabilitySurface, HostRuntimeError>
    where
        'a: 'b,
    {
        request.context.validate().map_err(|error| {
            HostRuntimeError::invalid_request(format!("invalid execution context: {error}"))
        })?;

        let mut capabilities = Vec::new();
        for descriptor in self.registry.capabilities() {
            if !request.policy.allows_runtime(descriptor.runtime)
                || !request.policy.allows_effects(&descriptor.effects)
            {
                continue;
            }
            let Some(trust_decision) = trust_decision_for(descriptor) else {
                continue;
            };
            let estimate = descriptor
                .resource_profile
                .as_ref()
                .map(|profile| profile.default_estimate.clone())
                .unwrap_or_default();
            let mut context = request.context.clone();
            context.trust = trust_decision.effective_trust.class();

            let access = match self
                .authorizer
                .authorize_dispatch_with_trust(&context, descriptor, &estimate, &trust_decision)
                .await
            {
                Decision::Allow { .. } => VisibleCapabilityAccess::Available,
                Decision::RequireApproval { .. } if request.policy.include_requires_approval => {
                    VisibleCapabilityAccess::RequiresApproval
                }
                Decision::RequireApproval { .. } | Decision::Deny { .. } => continue,
            };

            capabilities.push(VisibleCapability {
                descriptor: descriptor.clone(),
                access,
                estimated_resources: estimate,
            });
        }

        if let Some(max_capabilities) = request.policy.max_capabilities {
            capabilities.truncate(max_capabilities);
        }

        let version = surface_version(self.base_version, &request, &capabilities)?;
        let descriptors = capabilities
            .iter()
            .map(|capability| capability.descriptor.clone())
            .collect();
        Ok(VisibleCapabilitySurface {
            version,
            capabilities,
            descriptors,
        })
    }
}

fn surface_version(
    base_version: &CapabilitySurfaceVersion,
    request: &VisibleCapabilityRequest,
    capabilities: &[VisibleCapability],
) -> Result<CapabilitySurfaceVersion, HostRuntimeError> {
    let capability_payload = capabilities
        .iter()
        .map(|capability| {
            json!({
                "descriptor": &capability.descriptor,
                "estimated_resources": &capability.estimated_resources,
                "access": match capability.access {
                    VisibleCapabilityAccess::Available => "available",
                    VisibleCapabilityAccess::RequiresApproval => "requires_approval",
                },
            })
        })
        .collect::<Vec<_>>();
    let payload = json!({
        "base_version": base_version.as_str(),
        "surface_kind": request.surface_kind.as_str(),
        "policy": {
            "allowed_runtimes": request.policy.allowed_runtimes,
            "allowed_effects": request.policy.allowed_effects,
            "include_requires_approval": request.policy.include_requires_approval,
            "max_capabilities": request.policy.max_capabilities,
        },
        "capabilities": capability_payload,
    });
    let canonical = serde_json::to_vec(&payload)
        .map_err(|error| HostRuntimeError::invalid_request(error.to_string()))?;
    CapabilitySurfaceVersion::new(format!("surface-fnv1a-{:016x}", fnv1a64(&canonical)))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
