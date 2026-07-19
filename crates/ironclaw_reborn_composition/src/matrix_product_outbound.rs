use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use ironclaw_common::hashing::sha256_hex;
use ironclaw_extensions::ExtensionInstallationStore;
use ironclaw_filesystem::{CasExpectation, ContentType, Entry, RootFilesystem, ScopedFilesystem};
#[cfg(any(test, feature = "libsql", feature = "postgres"))]
use ironclaw_host_api::{AgentId, ProjectId, TenantId};
use ironclaw_host_api::{ExtensionId, ResourceScope, ScopedPath};
use ironclaw_matrix_adapter::installation_policy::{
    EgressTargetIndex, InstallationAuditMetadata, MatrixActivationState, MatrixHomeserverOrigin,
    MatrixInstallationPolicy, MatrixInstallationPolicyRejection, MatrixInstallationProjectionCache,
    MatrixOutboundPolicyCheck, MatrixPolicySnapshot, MatrixProductAdapterInstallation,
    MatrixRoomId, MatrixRuntimeArtifactEvidence, authorize_matrix_outbound,
    ensure_matrix_extension_lifecycle_enabled, project_matrix_installation_from_runtime_entry,
};
use ironclaw_product_adapter_registry::{
    ProductAdapterRuntimeEntry, list_enabled_product_adapter_entries,
};
use ironclaw_product_adapters::redaction::RedactedString;
use ironclaw_product_adapters::{
    AdapterInstallationId, AuthRequirement, DeclaredEgressTarget, OutboundDeliverySink,
    ParsedProductInbound, ProductAdapter, ProductAdapterCapabilities, ProductAdapterError,
    ProductAdapterHealth, ProductAdapterId, ProductOutboundEnvelope, ProductOutboundPayload,
    ProductRenderOutcome, ProductSurfaceKind, ProductWorkflowRejectionKind, ProtocolAuthEvidence,
    ProtocolHttpEgress,
};
use ironclaw_product_workflow::{
    ProductOutboundDeliveryError, ProductOutboundDeliveryOutcome, ProductOutboundDeliveryRequest,
    ProductOutboundStatusUpdateFailure, ProductOutboundTargetResolver, ProductWorkflowError,
    ProductWorkflowError as ProductOutboundWorkflowError, prepare_and_render_product_outbound,
};

use crate::extension_host::extension_lifecycle::LifecyclePolicyProjectionCacheRefresher;
use crate::matrix_outbound::MatrixPolicyProviderScope;
use crate::matrix_outbound_targets::{
    MatrixOutboundTargetProviderConfig, MatrixRoomBindingRemovalRequest, MatrixRoomBindingStore,
    matrix_policy_provider_scope_key,
};

pub(crate) const MATRIX_PRODUCT_ADAPTER_EXTENSION_ID: &str = "matrix-product-adapter";
pub const MATRIX_POLICY_PROJECTION_CACHE_ROOT: &str = "/tenant-shared/matrix/policy";
const MATRIX_POLICY_PROJECTION_COMMIT_MARKER_TOMBSTONE: &[u8] = b"invalidated\n";

struct MatrixPolicyProjectionCacheWrite {
    provider: MatrixOutboundTargetProviderConfig,
    provider_scope: ResourceScope,
    provider_cache_path: ScopedPath,
    commit_marker_path: ScopedPath,
    bytes: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct MatrixLifecyclePolicyProjectionCacheRefresher {
    filesystem: Arc<ScopedFilesystem<dyn RootFilesystem>>,
    installation_store: Arc<dyn ExtensionInstallationStore>,
    target_provider_source: MatrixLifecycleTargetProviderSource,
    artifact_evidence: MatrixRuntimeArtifactEvidence,
    policy_owner_actor: String,
}

#[derive(Clone)]
enum MatrixLifecycleTargetProviderSource {
    #[cfg(test)]
    Static(Vec<MatrixOutboundTargetProviderConfig>),
    Shared(Arc<dyn MatrixRoomBindingStore>),
}

impl MatrixLifecycleTargetProviderSource {
    async fn snapshot(
        &self,
    ) -> Result<Vec<MatrixOutboundTargetProviderConfig>, ProductWorkflowError> {
        match self {
            #[cfg(test)]
            Self::Static(target_providers) => Ok(target_providers.clone()),
            Self::Shared(target_source) => {
                target_source
                    .snapshot_provider_configs()
                    .await
                    .map_err(|error| ProductWorkflowError::Transient {
                        reason: format!("Matrix outbound target provider snapshot failed: {error}"),
                    })
            }
        }
    }

    async fn provider_has_removed_room_binding(
        &self,
        provider: &MatrixOutboundTargetProviderConfig,
    ) -> Result<bool, ProductWorkflowError> {
        match self {
            #[cfg(test)]
            Self::Static(_) => Ok(false),
            Self::Shared(target_source) => target_source
                .provider_has_removed_room_binding(provider)
                .await
                .map_err(|error| ProductWorkflowError::Transient {
                    reason: format!(
                        "Matrix outbound target provider tombstone lookup failed: {error}"
                    ),
                }),
        }
    }
}

impl MatrixLifecyclePolicyProjectionCacheRefresher {
    #[cfg(test)]
    pub(crate) fn new(
        filesystem: Arc<dyn RootFilesystem>,
        installation_store: Arc<dyn ExtensionInstallationStore>,
        target_providers: Vec<MatrixOutboundTargetProviderConfig>,
        artifact_evidence: MatrixRuntimeArtifactEvidence,
        policy_owner_actor: String,
    ) -> Result<Self, ProductWorkflowError> {
        Ok(Self {
            filesystem: Arc::new(ScopedFilesystem::new(
                filesystem,
                crate::invocation_mount_view,
            )),
            installation_store,
            target_provider_source: MatrixLifecycleTargetProviderSource::Static(target_providers),
            artifact_evidence,
            policy_owner_actor,
        })
    }

    pub(crate) fn from_shared_target_source(
        filesystem: Arc<dyn RootFilesystem>,
        installation_store: Arc<dyn ExtensionInstallationStore>,
        target_source: Arc<dyn MatrixRoomBindingStore>,
        artifact_evidence: MatrixRuntimeArtifactEvidence,
        policy_owner_actor: String,
    ) -> Result<Self, ProductWorkflowError> {
        Ok(Self {
            filesystem: Arc::new(ScopedFilesystem::new(
                filesystem,
                crate::invocation_mount_view,
            )),
            installation_store,
            target_provider_source: MatrixLifecycleTargetProviderSource::Shared(target_source),
            artifact_evidence,
            policy_owner_actor,
        })
    }

    async fn refresh_projection_cache(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
        force_write_empty: bool,
        publish_markers: bool,
    ) -> Result<(), ProductWorkflowError> {
        if extension_id.as_str() != MATRIX_PRODUCT_ADAPTER_EXTENSION_ID {
            return Ok(());
        }
        let target_providers = self.target_provider_source.snapshot().await?;
        if target_providers.is_empty() {
            return Ok(());
        }
        let entries = list_enabled_product_adapter_entries(self.installation_store.as_ref())
            .await
            .map_err(map_matrix_policy_projection_cache_error)?;
        let matching_entries = entries
            .into_iter()
            .filter(|entry| entry.installation().extension_id() == extension_id)
            .collect::<Vec<_>>();
        let mut writes = Vec::new();
        for provider in &target_providers {
            let provider_scope =
                matrix_policy_projection_resource_scope_for_provider(scope, provider);
            let provider_cache_path = matrix_policy_projection_cache_path_for_provider(provider)?;
            let commit_marker_path =
                matrix_policy_projection_commit_marker_path_for_cache_path(&provider_cache_path)?;
            let mut cache = MatrixInstallationProjectionCache::new();
            let mut projected = false;
            for entry in &matching_entries {
                let installation_id =
                    AdapterInstallationId::new(entry.installation().installation_id().as_str())
                        .map_err(map_matrix_policy_projection_cache_error)?;
                if provider.installation_id != installation_id {
                    continue;
                }
                projected = true;
                let at_ms = matrix_policy_projection_timestamp_ms();
                let installation = project_matrix_installation_from_runtime_entry(
                    entry,
                    self.artifact_evidence.clone(),
                    self.matrix_policy_from_runtime_entry(entry, provider, &target_providers)?,
                    InstallationAuditMetadata::new(&self.policy_owner_actor, at_ms)
                        .map_err(map_matrix_policy_projection_rejection)?,
                )
                .map_err(map_matrix_policy_projection_rejection)?;
                cache
                    .insert_projection(installation, &self.policy_owner_actor, at_ms)
                    .map_err(map_matrix_policy_projection_rejection)?;
            }
            if !projected && !force_write_empty {
                continue;
            }
            let bytes = cache
                .to_json_bytes()
                .map_err(map_matrix_policy_projection_cache_error)?;
            writes.push(MatrixPolicyProjectionCacheWrite {
                provider: provider.clone(),
                provider_scope,
                provider_cache_path,
                commit_marker_path,
                bytes,
            });
        }
        for write in &writes {
            if let Err(error) = self
                .filesystem
                .put(
                    &write.provider_scope,
                    &write.commit_marker_path,
                    Entry::bytes(MATRIX_POLICY_PROJECTION_COMMIT_MARKER_TOMBSTONE.to_vec()),
                    CasExpectation::Any,
                )
                .await
            {
                self.invalidate_projection_cache_body(
                    &write.provider_scope,
                    &write.provider_cache_path,
                )
                .await?;
                return Err(map_matrix_policy_projection_cache_error(error));
            }
        }
        let mut written = Vec::new();
        for write in &writes {
            if let Err(error) = self
                .filesystem
                .put(
                    &write.provider_scope,
                    &write.provider_cache_path,
                    Entry::bytes(write.bytes.clone()).with_content_type(ContentType::json()),
                    CasExpectation::Any,
                )
                .await
            {
                if !force_write_empty && publish_markers {
                    self.invalidate_written_projection_caches(&written).await?;
                }
                return Err(map_matrix_policy_projection_cache_error(error));
            }
            written.push((
                write.provider_scope.clone(),
                write.provider_cache_path.clone(),
                write.commit_marker_path.clone(),
            ));
        }
        if !publish_markers {
            return Ok(());
        }
        let mut committed_markers = Vec::new();
        for write in &writes {
            if self
                .target_provider_source
                .provider_has_removed_room_binding(&write.provider)
                .await?
            {
                self.invalidate_projection_cache_body(
                    &write.provider_scope,
                    &write.provider_cache_path,
                )
                .await?;
                self.invalidate_projection_commit_markers(&[(
                    write.provider_scope.clone(),
                    write.commit_marker_path.clone(),
                )])
                .await?;
                continue;
            }
            if let Err(error) = self
                .filesystem
                .put(
                    &write.provider_scope,
                    &write.commit_marker_path,
                    matrix_policy_projection_commit_marker_entry(&write.bytes),
                    CasExpectation::Any,
                )
                .await
            {
                self.invalidate_projection_commit_markers(&committed_markers)
                    .await?;
                return Err(map_matrix_policy_projection_cache_error(error));
            }
            committed_markers.push((
                write.provider_scope.clone(),
                write.commit_marker_path.clone(),
            ));
        }
        Ok(())
    }

    async fn publish_prepared_projection_cache(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ProductWorkflowError> {
        if extension_id.as_str() != MATRIX_PRODUCT_ADAPTER_EXTENSION_ID {
            return Ok(());
        }
        let target_providers = self.target_provider_source.snapshot().await?;
        if target_providers.is_empty() {
            return Ok(());
        }
        let entries = list_enabled_product_adapter_entries(self.installation_store.as_ref())
            .await
            .map_err(map_matrix_policy_projection_cache_error)?;
        let matching_entries = entries
            .into_iter()
            .filter(|entry| entry.installation().extension_id() == extension_id)
            .collect::<Vec<_>>();
        let mut committed_markers = Vec::new();
        for provider in &target_providers {
            if !matching_entries.iter().any(|entry| {
                AdapterInstallationId::new(entry.installation().installation_id().as_str())
                    .map(|installation_id| installation_id == provider.installation_id)
                    .unwrap_or(false)
            }) {
                continue;
            }
            let provider_scope =
                matrix_policy_projection_resource_scope_for_provider(scope, provider);
            let provider_cache_path = matrix_policy_projection_cache_path_for_provider(provider)?;
            let commit_marker_path =
                matrix_policy_projection_commit_marker_path_for_cache_path(&provider_cache_path)?;
            let body = self
                .filesystem
                .get(&provider_scope, &provider_cache_path)
                .await
                .map_err(map_matrix_policy_projection_cache_error)?
                .ok_or_else(|| ProductWorkflowError::Transient {
                    reason:
                        "Matrix policy projection cache refresh failed: staged cache body missing"
                            .to_string(),
                })?
                .entry
                .body;
            if self
                .target_provider_source
                .provider_has_removed_room_binding(provider)
                .await?
                || !self.prepared_projection_cache_matches_current_provider(
                    &body,
                    provider,
                    &matching_entries,
                    &target_providers,
                )?
            {
                self.invalidate_projection_cache_body(&provider_scope, &provider_cache_path)
                    .await?;
                self.invalidate_projection_commit_markers(&[(
                    provider_scope.clone(),
                    commit_marker_path.clone(),
                )])
                .await?;
                continue;
            }
            if let Err(error) = self
                .filesystem
                .put(
                    &provider_scope,
                    &commit_marker_path,
                    matrix_policy_projection_commit_marker_entry(&body),
                    CasExpectation::Any,
                )
                .await
            {
                self.invalidate_projection_commit_markers(&committed_markers)
                    .await?;
                return Err(map_matrix_policy_projection_cache_error(error));
            }
            committed_markers.push((provider_scope, commit_marker_path));
        }
        Ok(())
    }

    fn prepared_projection_cache_matches_current_provider(
        &self,
        body: &[u8],
        provider: &MatrixOutboundTargetProviderConfig,
        matching_entries: &[ProductAdapterRuntimeEntry],
        target_providers: &[MatrixOutboundTargetProviderConfig],
    ) -> Result<bool, ProductWorkflowError> {
        let Some(entry) = matching_entries.iter().find(|entry| {
            AdapterInstallationId::new(entry.installation().installation_id().as_str())
                .map(|installation_id| installation_id == provider.installation_id)
                .unwrap_or(false)
        }) else {
            return Ok(false);
        };
        let cache = MatrixInstallationProjectionCache::from_json_bytes(body)
            .map_err(map_matrix_policy_projection_cache_error)?;
        let Some(installation) = cache.installation(&provider.installation_id) else {
            return Ok(false);
        };
        let current_policy =
            self.matrix_policy_from_runtime_entry(entry, provider, target_providers)?;
        Ok(installation.policy.homeserver == current_policy.homeserver
            && installation.policy.allowed_rooms == current_policy.allowed_rooms
            && installation.policy.allowed_senders == current_policy.allowed_senders
            && installation.policy.egress_target_index == current_policy.egress_target_index
            && installation.policy.credential_handle == current_policy.credential_handle)
    }

    async fn invalidate_projection_commit_markers(
        &self,
        committed_markers: &[(ResourceScope, ScopedPath)],
    ) -> Result<(), ProductWorkflowError> {
        for (provider_scope, commit_marker_path) in committed_markers {
            self.filesystem
                .put(
                    provider_scope,
                    commit_marker_path,
                    Entry::bytes(MATRIX_POLICY_PROJECTION_COMMIT_MARKER_TOMBSTONE.to_vec()),
                    CasExpectation::Any,
                )
                .await
                .map_err(map_matrix_policy_projection_cache_error)?;
        }
        Ok(())
    }

    async fn invalidate_written_projection_caches(
        &self,
        written: &[(ResourceScope, ScopedPath, ScopedPath)],
    ) -> Result<(), ProductWorkflowError> {
        let empty_bytes = MatrixInstallationProjectionCache::new()
            .to_json_bytes()
            .map_err(map_matrix_policy_projection_cache_error)?;
        for (provider_scope, provider_cache_path, commit_marker_path) in written {
            self.filesystem
                .put(
                    provider_scope,
                    commit_marker_path,
                    Entry::bytes(MATRIX_POLICY_PROJECTION_COMMIT_MARKER_TOMBSTONE.to_vec()),
                    CasExpectation::Any,
                )
                .await
                .map_err(map_matrix_policy_projection_cache_error)?;
            self.filesystem
                .put(
                    provider_scope,
                    provider_cache_path,
                    Entry::bytes(empty_bytes.clone()).with_content_type(ContentType::json()),
                    CasExpectation::Any,
                )
                .await
                .map_err(map_matrix_policy_projection_cache_error)?;
        }
        Ok(())
    }

    async fn invalidate_projection_cache_body(
        &self,
        provider_scope: &ResourceScope,
        provider_cache_path: &ScopedPath,
    ) -> Result<(), ProductWorkflowError> {
        let empty_bytes = MatrixInstallationProjectionCache::new()
            .to_json_bytes()
            .map_err(map_matrix_policy_projection_cache_error)?;
        self.filesystem
            .put(
                provider_scope,
                provider_cache_path,
                Entry::bytes(empty_bytes).with_content_type(ContentType::json()),
                CasExpectation::Any,
            )
            .await
            .map_err(map_matrix_policy_projection_cache_error)?;
        Ok(())
    }

    async fn invalidate_projection_commit_marker_for_removal_request(
        &self,
        scope: &ResourceScope,
        request: &MatrixRoomBindingRemovalRequest,
    ) -> Result<(), ProductWorkflowError> {
        let provider_scope = matrix_policy_projection_resource_scope_for_provider_scope(
            scope,
            &MatrixPolicyProviderScope {
                tenant_id: request.tenant_id.clone(),
                agent_id: request.agent_id.clone(),
                project_id: request.project_id.clone(),
            },
        );
        let provider_cache_path = matrix_policy_projection_cache_path_for_removal_request(request)?;
        let commit_marker_path =
            matrix_policy_projection_commit_marker_path_for_cache_path(&provider_cache_path)?;
        self.filesystem
            .put(
                &provider_scope,
                &commit_marker_path,
                Entry::bytes(MATRIX_POLICY_PROJECTION_COMMIT_MARKER_TOMBSTONE.to_vec()),
                CasExpectation::Any,
            )
            .await
            .map_err(map_matrix_policy_projection_cache_error)?;
        Ok(())
    }

    fn matrix_policy_from_runtime_entry(
        &self,
        entry: &ProductAdapterRuntimeEntry,
        provider: &MatrixOutboundTargetProviderConfig,
        target_providers: &[MatrixOutboundTargetProviderConfig],
    ) -> Result<MatrixInstallationPolicy, ProductWorkflowError> {
        let installation_id =
            AdapterInstallationId::new(entry.installation().installation_id().as_str())
                .map_err(map_matrix_policy_projection_cache_error)?;
        let room_routes = target_providers
            .iter()
            .filter(|candidate| {
                candidate.tenant_id == provider.tenant_id
                    && candidate.agent_id == provider.agent_id
                    && candidate.project_id == provider.project_id
                    && candidate.installation_id == installation_id
            })
            .flat_map(|provider| provider.configured_room_routes.iter());
        let mut allowed_rooms = BTreeSet::new();
        let mut allowed_senders = BTreeSet::new();
        for route in room_routes {
            allowed_rooms.insert(
                MatrixRoomId::new(route.room_id.clone())
                    .map_err(map_matrix_policy_projection_rejection)?,
            );
            allowed_senders.insert(route.matrix_sender_user_id.clone());
        }
        let (egress_target_index, target) = entry
            .adapter()
            .declared_egress()
            .iter()
            .enumerate()
            .find(|(_, target)| target.credential_handle.is_some())
            .ok_or_else(|| ProductWorkflowError::InvalidBindingRequest {
                reason: "Matrix ProductAdapter entry declares no credentialed egress target"
                    .to_string(),
            })?;
        let credential_handle = target.credential_handle.clone().ok_or_else(|| {
            ProductWorkflowError::InvalidBindingRequest {
                reason: "Matrix ProductAdapter egress target has no credential handle".to_string(),
            }
        })?;
        let target_index =
            u32::try_from(egress_target_index).map_err(map_matrix_policy_projection_cache_error)?;
        MatrixInstallationPolicy::new(
            MatrixHomeserverOrigin::parse(format!("https://{}", target.host.as_str()))
                .map_err(map_matrix_policy_projection_rejection)?,
            allowed_rooms,
            allowed_senders,
            EgressTargetIndex::new(target_index),
            credential_handle,
        )
        .map_err(map_matrix_policy_projection_rejection)
    }

    pub(crate) async fn invalidate_before_target_binding_removal(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
        request: &MatrixRoomBindingRemovalRequest,
    ) -> Result<(), ProductWorkflowError> {
        if extension_id.as_str() != MATRIX_PRODUCT_ADAPTER_EXTENSION_ID {
            return Ok(());
        }
        self.invalidate_projection_commit_marker_for_removal_request(scope, request)
            .await?;
        Ok(())
    }

    #[cfg(test)]
    async fn refresh_after_lifecycle_activation(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ProductWorkflowError> {
        self.refresh_projection_cache(scope, extension_id, false, true)
            .await
    }

    pub(crate) async fn refresh_after_target_binding_mutation(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ProductWorkflowError> {
        self.refresh_projection_cache(scope, extension_id, true, true)
            .await
    }
}

#[async_trait]
impl LifecyclePolicyProjectionCacheRefresher for MatrixLifecyclePolicyProjectionCacheRefresher {
    async fn prepare_lifecycle_activation_refresh(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ProductWorkflowError> {
        self.refresh_projection_cache(scope, extension_id, false, false)
            .await
    }

    async fn publish_prepared_lifecycle_activation_refresh(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ProductWorkflowError> {
        self.publish_prepared_projection_cache(scope, extension_id)
            .await
    }

    async fn refresh_after_lifecycle_removal(
        &self,
        scope: &ResourceScope,
        extension_id: &ExtensionId,
    ) -> Result<(), ProductWorkflowError> {
        self.refresh_projection_cache(scope, extension_id, true, true)
            .await
    }
}

pub(crate) fn matrix_policy_projection_cache_path_for_provider(
    provider: &MatrixOutboundTargetProviderConfig,
) -> Result<ScopedPath, ProductWorkflowError> {
    matrix_policy_projection_cache_path_for_provider_key(&matrix_policy_provider_scope_key(
        &provider.tenant_id,
        &provider.agent_id,
        provider.project_id.as_ref(),
        &provider.installation_id,
    ))
}

pub(crate) fn matrix_policy_projection_cache_path_for_provider_key(
    provider_scope_key: &str,
) -> Result<ScopedPath, ProductWorkflowError> {
    ScopedPath::new(format!(
        "{MATRIX_POLICY_PROJECTION_CACHE_ROOT}/{provider_scope_key}/installation-projection-cache.json"
    ))
    .map_err(|error| ProductWorkflowError::Transient {
        reason: format!("Matrix policy projection cache path is invalid: {error}"),
    })
}

fn matrix_policy_projection_cache_path_for_removal_request(
    request: &MatrixRoomBindingRemovalRequest,
) -> Result<ScopedPath, ProductWorkflowError> {
    matrix_policy_projection_cache_path_for_provider_key(&matrix_policy_provider_scope_key(
        &request.tenant_id,
        &request.agent_id,
        request.project_id.as_ref(),
        &request.installation_id,
    ))
}

pub(crate) fn matrix_policy_projection_commit_marker_path_for_cache_path(
    cache_path: &ScopedPath,
) -> Result<ScopedPath, ProductWorkflowError> {
    ScopedPath::new(format!("{}.commit", cache_path.as_str())).map_err(|error| {
        ProductWorkflowError::Transient {
            reason: format!(
                "Matrix policy projection cache commit marker path is invalid: {error}"
            ),
        }
    })
}

pub(crate) fn matrix_policy_projection_commit_marker_entry(cache_bytes: &[u8]) -> Entry {
    Entry::bytes(matrix_policy_projection_commit_marker_bytes(cache_bytes))
}

fn matrix_policy_projection_commit_marker_bytes(cache_bytes: &[u8]) -> Vec<u8> {
    format!("sha256:{}\n", sha256_hex(cache_bytes)).into_bytes()
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) fn matrix_policy_projection_cache_path_for_route_scope(
    tenant_id: &TenantId,
    agent_id: Option<&AgentId>,
    project_id: Option<&ProjectId>,
    installation_id: &AdapterInstallationId,
) -> Result<ScopedPath, ProductWorkflowError> {
    let Some(agent_id) = agent_id else {
        return Err(ProductWorkflowError::InvalidBindingRequest {
            reason: "Matrix policy projection cache requires an agent-scoped provider".to_string(),
        });
    };
    matrix_policy_projection_cache_path_for_provider_key(&matrix_policy_provider_scope_key(
        tenant_id,
        agent_id,
        project_id,
        installation_id,
    ))
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) fn matrix_policy_projection_resource_scope(scope: &ResourceScope) -> ResourceScope {
    scope.tenant_shared_managed_scope()
}

pub(crate) fn matrix_policy_projection_resource_scope_for_provider(
    scope: &ResourceScope,
    provider: &MatrixOutboundTargetProviderConfig,
) -> ResourceScope {
    matrix_policy_projection_resource_scope_for_provider_scope(
        scope,
        &MatrixPolicyProviderScope {
            tenant_id: provider.tenant_id.clone(),
            agent_id: provider.agent_id.clone(),
            project_id: provider.project_id.clone(),
        },
    )
}

pub(crate) fn matrix_policy_projection_resource_scope_for_provider_scope(
    scope: &ResourceScope,
    provider_scope: &MatrixPolicyProviderScope,
) -> ResourceScope {
    provider_scope.to_policy_resource_scope(scope)
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) fn matrix_policy_projection_cache_path_for_route(
    route: &crate::matrix_outbound::FrozenProductDeliveryRoute,
) -> Result<ScopedPath, ProductWorkflowError> {
    let installation_id = AdapterInstallationId::new(route.installation_id.clone())
        .map_err(map_matrix_policy_projection_cache_error)?;
    if let Some(provider_scope) = route.matrix_metadata().policy_provider_scope.as_ref() {
        return matrix_policy_projection_cache_path_for_route_scope(
            &provider_scope.tenant_id,
            Some(&provider_scope.agent_id),
            provider_scope.project_id.as_ref(),
            &installation_id,
        );
    }
    matrix_policy_projection_cache_path_for_route_scope(
        &route.scope().tenant_id,
        route.scope().agent_id.as_ref(),
        route.scope().project_id.as_ref(),
        &installation_id,
    )
}

#[cfg(any(test, feature = "libsql", feature = "postgres"))]
pub(crate) fn matrix_policy_projection_resource_scope_for_route(
    route: &crate::matrix_outbound::FrozenProductDeliveryRoute,
) -> ResourceScope {
    let route_scope = route.scope().to_resource_scope();
    route
        .matrix_metadata()
        .policy_provider_scope
        .as_ref()
        .map(|provider_scope| {
            matrix_policy_projection_resource_scope_for_provider_scope(&route_scope, provider_scope)
        })
        .unwrap_or_else(|| matrix_policy_projection_resource_scope(&route_scope))
}

fn matrix_policy_projection_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn map_matrix_policy_projection_rejection(
    error: MatrixInstallationPolicyRejection,
) -> ProductWorkflowError {
    ProductWorkflowError::Transient {
        reason: format!("Matrix policy projection cache refresh failed: {error}"),
    }
}

fn map_matrix_policy_projection_cache_error(error: impl std::fmt::Display) -> ProductWorkflowError {
    ProductWorkflowError::Transient {
        reason: format!("Matrix policy projection cache refresh failed: {error}"),
    }
}

pub trait MatrixOutboundPolicyAuthorizer: Send + Sync {
    fn authorize_matrix_outbound(
        &self,
        snapshot: &MatrixPolicySnapshot,
        check: &MatrixOutboundPolicyCheck,
    ) -> Result<(), MatrixInstallationPolicyRejection>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultMatrixOutboundPolicyAuthorizer;

impl MatrixOutboundPolicyAuthorizer for DefaultMatrixOutboundPolicyAuthorizer {
    /// Validates a source-verified R002C policy snapshot. Production callers must
    /// pass a current snapshot from the policy owner; this type does not rehydrate
    /// policy state on its own.
    fn authorize_matrix_outbound(
        &self,
        snapshot: &MatrixPolicySnapshot,
        check: &MatrixOutboundPolicyCheck,
    ) -> Result<(), MatrixInstallationPolicyRejection> {
        authorize_matrix_outbound(snapshot, check)
    }
}

#[async_trait]
pub trait MatrixPolicySnapshotSource: Send + Sync {
    async fn resolve_matrix_policy_snapshot(
        &self,
        adapter_id: &ProductAdapterId,
        installation_id: &AdapterInstallationId,
    ) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection>;
}

#[derive(Clone)]
pub struct FilesystemMatrixPolicySnapshotSource<F: ?Sized> {
    filesystem: Arc<ScopedFilesystem<F>>,
    scope: ResourceScope,
    cache_path: ScopedPath,
}

impl<F> FilesystemMatrixPolicySnapshotSource<F>
where
    F: RootFilesystem + ?Sized,
{
    pub fn new(
        filesystem: Arc<ScopedFilesystem<F>>,
        scope: ResourceScope,
        cache_path: ScopedPath,
    ) -> Self {
        Self {
            filesystem,
            scope,
            cache_path,
        }
    }
}

impl<F> FilesystemMatrixPolicySnapshotSource<F>
where
    F: RootFilesystem + Send + Sync + ?Sized,
{
    pub async fn resolve_enabled_matrix_policy_snapshot_for_installation(
        &self,
        installation_id: &AdapterInstallationId,
    ) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection> {
        let installation = self
            .matrix_policy_installation(installation_id)
            .await?
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        matrix_policy_snapshot_from_installation(installation)
    }

    async fn matrix_policy_installation(
        &self,
        installation_id: &AdapterInstallationId,
    ) -> Result<Option<MatrixProductAdapterInstallation>, MatrixInstallationPolicyRejection> {
        let entry = self
            .filesystem
            .get(&self.scope, &self.cache_path)
            .await
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        let commit_marker_path =
            matrix_policy_projection_commit_marker_path_for_cache_path(&self.cache_path)
                .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
        let Some(commit_marker) = self
            .filesystem
            .get(&self.scope, &commit_marker_path)
            .await
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?
        else {
            return Ok(None);
        };
        if commit_marker.entry.body
            != matrix_policy_projection_commit_marker_bytes(&entry.entry.body)
        {
            return Ok(None);
        }
        let cache = MatrixInstallationProjectionCache::from_json_bytes(&entry.entry.body)
            .map_err(|_| MatrixInstallationPolicyRejection::InvalidPolicyValue)?;
        Ok(cache.installation(installation_id).cloned())
    }
}

#[async_trait]
impl<F> MatrixPolicySnapshotSource for FilesystemMatrixPolicySnapshotSource<F>
where
    F: RootFilesystem + Send + Sync + ?Sized,
{
    async fn resolve_matrix_policy_snapshot(
        &self,
        adapter_id: &ProductAdapterId,
        installation_id: &AdapterInstallationId,
    ) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection> {
        let installation = self
            .matrix_policy_installation(installation_id)
            .await?
            .ok_or(MatrixInstallationPolicyRejection::InstallationNotFound)?;
        if &installation.adapter_id != adapter_id {
            return Err(MatrixInstallationPolicyRejection::AdapterMismatch);
        }
        matrix_policy_snapshot_from_installation(installation)
    }
}

fn matrix_policy_snapshot_from_installation(
    installation: MatrixProductAdapterInstallation,
) -> Result<MatrixPolicySnapshot, MatrixInstallationPolicyRejection> {
    match installation.activation {
        MatrixActivationState::Enabled => {}
        MatrixActivationState::Disabled => {
            return Err(MatrixInstallationPolicyRejection::InstallationDisabled);
        }
        MatrixActivationState::Deleting => {
            return Err(MatrixInstallationPolicyRejection::InstallationDeleting);
        }
    }
    Ok(MatrixPolicySnapshot {
        adapter_id: installation.adapter_id,
        installation_id: installation.installation_id,
        homeserver: installation.policy.homeserver,
        allowed_rooms: installation.policy.allowed_rooms,
        allowed_senders: installation.policy.allowed_senders,
        egress_target_index: installation.policy.egress_target_index,
        credential_handle: installation.policy.credential_handle,
        policy_revision: installation.policy_revision,
    })
}

pub struct MatrixProductOutboundEntrypoint<'a> {
    pub extension_installation_store: &'a dyn ExtensionInstallationStore,
    pub snapshot_source: &'a dyn MatrixPolicySnapshotSource,
    pub policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    pub outbound_policy: &'a ironclaw_outbound::OutboundPolicyService<'a>,
    pub communication_preferences: &'a dyn ironclaw_outbound::CommunicationPreferenceRepository,
    pub target_resolver: &'a dyn ProductOutboundTargetResolver,
    pub adapter: &'a dyn ProductAdapter,
    pub egress: &'a dyn ProtocolHttpEgress,
    pub delivery_sink: &'a dyn OutboundDeliverySink,
}

pub struct MatrixProductOutboundDeliveryInput {
    pub delivery: ironclaw_outbound::PrepareCommunicationDeliveryRequest,
    pub payload: ProductOutboundPayload,
    pub projection_cursor: ironclaw_product_adapters::ProjectionCursor,
    pub require_direct_message_target: bool,
}

impl MatrixProductOutboundEntrypoint<'_> {
    pub async fn prepare_and_render(
        &self,
        input: MatrixProductOutboundDeliveryInput,
    ) -> Result<ProductOutboundDeliveryOutcome, MatrixProductOutboundDeliveryError> {
        prepare_and_render_matrix_product_outbound(MatrixProductOutboundDeliveryRequest {
            extension_installation_store: self.extension_installation_store,
            snapshot_source: self.snapshot_source,
            resolved_snapshot: None,
            policy_authorizer: self.policy_authorizer,
            outbound_policy: self.outbound_policy,
            communication_preferences: self.communication_preferences,
            target_resolver: self.target_resolver,
            delivery: input.delivery,
            payload: input.payload,
            projection_cursor: input.projection_cursor,
            adapter: self.adapter,
            egress: self.egress,
            delivery_sink: self.delivery_sink,
            require_direct_message_target: input.require_direct_message_target,
        })
        .await
    }

    pub async fn prepare_and_render_with_snapshot(
        &self,
        input: MatrixProductOutboundDeliveryInput,
        snapshot: MatrixPolicySnapshot,
    ) -> Result<ProductOutboundDeliveryOutcome, MatrixProductOutboundDeliveryError> {
        prepare_and_render_matrix_product_outbound(MatrixProductOutboundDeliveryRequest {
            extension_installation_store: self.extension_installation_store,
            snapshot_source: self.snapshot_source,
            resolved_snapshot: Some(snapshot),
            policy_authorizer: self.policy_authorizer,
            outbound_policy: self.outbound_policy,
            communication_preferences: self.communication_preferences,
            target_resolver: self.target_resolver,
            delivery: input.delivery,
            payload: input.payload,
            projection_cursor: input.projection_cursor,
            adapter: self.adapter,
            egress: self.egress,
            delivery_sink: self.delivery_sink,
            require_direct_message_target: input.require_direct_message_target,
        })
        .await
    }
}

struct MatrixProductOutboundDeliveryRequest<'a> {
    extension_installation_store: &'a dyn ExtensionInstallationStore,
    snapshot_source: &'a dyn MatrixPolicySnapshotSource,
    resolved_snapshot: Option<MatrixPolicySnapshot>,
    policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    outbound_policy: &'a ironclaw_outbound::OutboundPolicyService<'a>,
    communication_preferences: &'a dyn ironclaw_outbound::CommunicationPreferenceRepository,
    target_resolver: &'a dyn ProductOutboundTargetResolver,
    delivery: ironclaw_outbound::PrepareCommunicationDeliveryRequest,
    payload: ProductOutboundPayload,
    projection_cursor: ironclaw_product_adapters::ProjectionCursor,
    adapter: &'a dyn ProductAdapter,
    egress: &'a dyn ProtocolHttpEgress,
    delivery_sink: &'a dyn OutboundDeliverySink,
    require_direct_message_target: bool,
}

#[derive(Debug)]
pub enum MatrixProductOutboundDeliveryError {
    Unavailable {
        reason: String,
    },
    Lifecycle(MatrixInstallationPolicyRejection),
    TargetResolution {
        source: ProductOutboundWorkflowError,
        status_update_error: Option<ProductOutboundStatusUpdateFailure>,
    },
    Policy {
        rejection: MatrixInstallationPolicyRejection,
        status_update_error: Option<ProductOutboundStatusUpdateFailure>,
    },
    Delivery(ProductOutboundDeliveryError),
}

async fn prepare_and_render_matrix_product_outbound(
    request: MatrixProductOutboundDeliveryRequest<'_>,
) -> Result<ProductOutboundDeliveryOutcome, MatrixProductOutboundDeliveryError> {
    let snapshot = match request.resolved_snapshot {
        Some(snapshot) => snapshot,
        None => request
            .snapshot_source
            .resolve_matrix_policy_snapshot(
                request.adapter.adapter_id(),
                request.adapter.installation_id(),
            )
            .await
            .map_err(|rejection| {
                record_matrix_product_outbound_policy_failure("snapshot", &rejection);
                MatrixProductOutboundDeliveryError::Policy {
                    rejection,
                    status_update_error: None,
                }
            })?,
    };

    ensure_matrix_extension_lifecycle_enabled(
        request.extension_installation_store,
        &snapshot.installation_id,
    )
    .await
    .map_err(|rejection| {
        record_matrix_product_outbound_policy_failure("lifecycle", &rejection);
        MatrixProductOutboundDeliveryError::Lifecycle(rejection)
    })?;

    let policy_failure = Arc::new(Mutex::new(None));
    let gated_adapter = MatrixPolicyGatedProductAdapter {
        inner: request.adapter,
        snapshot,
        policy_authorizer: request.policy_authorizer,
        policy_failure: Arc::clone(&policy_failure),
    };

    let outcome = prepare_and_render_product_outbound(
        request.outbound_policy,
        request.communication_preferences,
        request.target_resolver,
        ProductOutboundDeliveryRequest {
            delivery: request.delivery,
            payload: request.payload,
            projection_cursor: request.projection_cursor,
            adapter: &gated_adapter,
            egress: request.egress,
            delivery_sink: request.delivery_sink,
            require_direct_message_target: request.require_direct_message_target,
        },
    )
    .await
    .map_err(|error| map_matrix_product_outbound_delivery_error(error, &policy_failure))?;
    Ok(outcome)
}

fn map_matrix_product_outbound_delivery_error(
    error: ProductOutboundDeliveryError,
    policy_failure: &Arc<Mutex<Option<MatrixInstallationPolicyRejection>>>,
) -> MatrixProductOutboundDeliveryError {
    match error {
        ProductOutboundDeliveryError::Workflow {
            source,
            status_update_error,
        } => {
            record_matrix_product_outbound_workflow_failure("target_resolution", &source);
            MatrixProductOutboundDeliveryError::TargetResolution {
                source,
                status_update_error,
            }
        }
        ProductOutboundDeliveryError::Adapter {
            source,
            status_update_error,
        } => {
            if let Some(rejection) = policy_failure
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                record_matrix_product_outbound_policy_failure("policy", &rejection);
                MatrixProductOutboundDeliveryError::Policy {
                    rejection,
                    status_update_error,
                }
            } else {
                MatrixProductOutboundDeliveryError::Delivery(
                    ProductOutboundDeliveryError::Adapter {
                        source,
                        status_update_error,
                    },
                )
            }
        }
        other => MatrixProductOutboundDeliveryError::Delivery(other),
    }
}

struct MatrixPolicyGatedProductAdapter<'a> {
    inner: &'a dyn ProductAdapter,
    snapshot: MatrixPolicySnapshot,
    policy_authorizer: &'a dyn MatrixOutboundPolicyAuthorizer,
    policy_failure: Arc<Mutex<Option<MatrixInstallationPolicyRejection>>>,
}

#[async_trait]
impl ProductAdapter for MatrixPolicyGatedProductAdapter<'_> {
    fn adapter_id(&self) -> &ProductAdapterId {
        self.inner.adapter_id()
    }

    fn installation_id(&self) -> &AdapterInstallationId {
        self.inner.installation_id()
    }

    fn surface_kind(&self) -> ProductSurfaceKind {
        self.inner.surface_kind()
    }

    fn capabilities(&self) -> &ProductAdapterCapabilities {
        self.inner.capabilities()
    }

    fn auth_requirement(&self) -> &AuthRequirement {
        self.inner.auth_requirement()
    }

    fn declared_egress(&self) -> &[DeclaredEgressTarget] {
        self.inner.declared_egress()
    }

    fn parse_inbound(
        &self,
        raw_payload: &[u8],
        auth_evidence: &ProtocolAuthEvidence,
    ) -> Result<ParsedProductInbound, ProductAdapterError> {
        self.inner.parse_inbound(raw_payload, auth_evidence)
    }

    async fn render_outbound(
        &self,
        envelope: ProductOutboundEnvelope,
        egress: &dyn ProtocolHttpEgress,
        delivery_sink: &dyn OutboundDeliverySink,
    ) -> Result<ProductRenderOutcome, ProductAdapterError> {
        let check = match matrix_outbound_policy_check_from_envelope(&self.snapshot, &envelope) {
            Ok(check) => check,
            Err(error) => {
                *self
                    .policy_failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                return Err(map_matrix_policy_rejection_to_adapter_error(error));
            }
        };
        if let Err(rejection) = self
            .policy_authorizer
            .authorize_matrix_outbound(&self.snapshot, &check)
        {
            *self
                .policy_failure
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(rejection);
            return Err(map_matrix_policy_rejection_to_adapter_error(rejection));
        }
        self.inner
            .render_outbound(envelope, egress, delivery_sink)
            .await
    }

    fn health(&self) -> ProductAdapterHealth {
        self.inner.health()
    }
}

fn matrix_outbound_policy_check_from_envelope(
    snapshot: &MatrixPolicySnapshot,
    envelope: &ProductOutboundEnvelope,
) -> Result<MatrixOutboundPolicyCheck, MatrixInstallationPolicyRejection> {
    let room_id = MatrixRoomId::new(
        envelope
            .target
            .external_conversation_ref
            .conversation_id()
            .to_string(),
    )?;
    let transaction_id = format!("ironclaw-{}", envelope.delivery_attempt_id);
    let path = crate::matrix_outbound::matrix_send_policy_path(room_id.as_str(), &transaction_id);
    Ok(MatrixOutboundPolicyCheck {
        adapter_id: envelope.adapter_id.clone(),
        installation_id: envelope.installation_id.clone(),
        homeserver: snapshot.homeserver.clone(),
        room_id,
        egress_target_index: snapshot.egress_target_index,
        credential_handle: snapshot.credential_handle.clone(),
        path,
        guest_authorization_header_present: false,
        policy_revision: snapshot.policy_revision,
    })
}

fn map_matrix_policy_rejection_to_adapter_error(
    rejection: MatrixInstallationPolicyRejection,
) -> ProductAdapterError {
    let (kind, status_code) = match rejection {
        MatrixInstallationPolicyRejection::InstallationDisabled
        | MatrixInstallationPolicyRejection::InstallationDeleting
        | MatrixInstallationPolicyRejection::InstallationNotFound
        | MatrixInstallationPolicyRejection::AdapterMismatch
        | MatrixInstallationPolicyRejection::InstallationMismatch
        | MatrixInstallationPolicyRejection::RoomNotAllowed
        | MatrixInstallationPolicyRejection::SenderNotAllowed
        | MatrixInstallationPolicyRejection::HomeserverMismatch
        | MatrixInstallationPolicyRejection::CredentialHandleMismatch
        | MatrixInstallationPolicyRejection::GuestCredentialMaterialRejected
        | MatrixInstallationPolicyRejection::PolicyRevisionMismatch => {
            (ProductWorkflowRejectionKind::Unauthorized, 403)
        }
        _ => (ProductWorkflowRejectionKind::InvalidRequest, 400),
    };
    ProductAdapterError::WorkflowRejected {
        kind,
        status_code,
        retryable: false,
        reason: RedactedString::new(format!("matrix outbound policy rejected: {rejection:?}")),
    }
}

fn record_matrix_product_outbound_policy_failure(
    stage: &'static str,
    rejection: &MatrixInstallationPolicyRejection,
) {
    tracing::debug!(
        target = "ironclaw::reborn::matrix_product_outbound",
        stage,
        reason_code = ?rejection,
        "matrix product outbound policy gate failed"
    );
}

fn record_matrix_product_outbound_workflow_failure(
    stage: &'static str,
    source: &ProductOutboundWorkflowError,
) {
    tracing::debug!(
        target = "ironclaw::reborn::matrix_product_outbound",
        stage,
        reason = %source,
        "matrix product outbound shared workflow stage failed"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ironclaw_extensions::{
        ExtensionActivationState, ExtensionInstallation, ExtensionInstallationId,
        ExtensionManifestRecord, ExtensionManifestRef, InMemoryExtensionInstallationStore,
        InstallationOwner, MANIFEST_SCHEMA_VERSION, ManifestHash, ManifestSource,
    };
    use ironclaw_filesystem::{
        BackendCapabilities, DirEntry, FileStat, FilesystemError, FilesystemOperation,
        InMemoryBackend, RecordVersion, RootFilesystem,
    };
    use ironclaw_host_api::{
        AgentId, ExtensionId, InvocationId, ProjectId, ResourceScope, TenantId, UserId, VirtualPath,
    };
    use ironclaw_matrix_adapter::installation_policy::{
        ArtifactSha256, ComponentArtifactId, MatrixUserId, WitPackageName, WitWorldName,
    };
    use ironclaw_product_adapters::{AdapterInstallationId, ProductAdapterId};

    use super::*;
    use crate::matrix_outbound_targets::{
        FilesystemMatrixRoomBindingStore, MatrixConfiguredRoomRoute,
        MatrixOutboundTargetProviderConfig, MatrixRoomBindingRemovalOutcome,
        MatrixRoomBindingRemovalRequest, MatrixRoomBindingStore,
    };

    #[tokio::test]
    async fn matrix_lifecycle_refresher_projects_cache_from_runtime_sources_not_static_policy() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let source_room = "!source-backed-room:example.org";
        let source_sender = "@source-backed-user:example.org";
        let actor_user_id = "user:source-backed-agent";
        let provider = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: source_room.to_string(),
                subject_user_id: UserId::new(actor_user_id).expect("actor user id"),
                matrix_sender_user_id: MatrixUserId::new(source_sender).expect("matrix sender"),
            }],
        };
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");
        let scope = matrix_source_backed_scope();

        refresher
            .refresh_after_lifecycle_activation(
                &scope,
                &ExtensionId::new("matrix-product-adapter").expect("extension id"),
            )
            .await
            .expect("refresh projection cache");

        let source = FilesystemMatrixPolicySnapshotSource::new(
            crate::wrap_scoped(backend),
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
            matrix_policy_projection_cache_path_for_provider_key(
                &crate::matrix_outbound_targets::matrix_policy_provider_scope_key(
                    &TenantId::new("matrix-source-backed-tenant").expect("tenant"),
                    &AgentId::new("matrix-source-backed-agent").expect("agent"),
                    Some(&ProjectId::new("matrix-source-backed-project").expect("project")),
                    &installation_id,
                ),
            )
            .expect("cache path"),
        );
        let snapshot = source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter id"),
                &installation_id,
            )
            .await
            .expect("source-backed snapshot");
        assert_eq!(snapshot.installation_id, installation_id);
        assert_eq!(snapshot.homeserver.host(), "matrix.source.example.org");
        assert!(
            snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == source_room)
        );
        assert!(
            snapshot
                .allowed_senders
                .iter()
                .any(|sender| sender.as_str() == source_sender)
        );
        assert_eq!(snapshot.allowed_rooms.len(), 1);
        assert_eq!(snapshot.allowed_senders.len(), 1);
        assert!(
            !snapshot
                .allowed_senders
                .iter()
                .any(|sender| sender.as_str() == actor_user_id),
            "Matrix policy must not derive senders from IronClaw actor ids"
        );
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_rebuilds_shared_source_snapshot_after_room_binding_removal()
    {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![
                MatrixConfiguredRoomRoute {
                    room_id: "!fresh-shared-room-a:example.org".to_string(),
                    subject_user_id: UserId::new("user:fresh-shared-room-a").expect("actor a"),
                    matrix_sender_user_id: MatrixUserId::new("@fresh-shared-room-a:example.org")
                        .expect("matrix sender a"),
                },
                MatrixConfiguredRoomRoute {
                    room_id: "!stale-shared-room-b:example.org".to_string(),
                    subject_user_id: UserId::new("user:stale-shared-room-b").expect("actor b"),
                    matrix_sender_user_id: MatrixUserId::new("@stale-shared-room-b:example.org")
                        .expect("matrix sender b"),
                },
            ],
        };
        let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
            Arc::clone(&root),
            [provider.tenant_id.clone()],
        ));
        target_source
            .seed_from_configs(std::slice::from_ref(&provider))
            .await
            .expect("seed filesystem Matrix target source");
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
            root,
            Arc::clone(&store) as Arc<dyn ExtensionInstallationStore>,
            target_source.clone() as Arc<dyn MatrixRoomBindingStore>,
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("shared-source refresher config");
        let scope = matrix_source_backed_scope();
        let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
        let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
        let source = FilesystemMatrixPolicySnapshotSource::new(
            crate::wrap_scoped(backend),
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
            matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
        );

        refresher
            .refresh_after_lifecycle_activation(&scope, &extension_id)
            .await
            .expect("initial projection with rooms A and B");
        let initial_snapshot = source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("initial snapshot");
        assert!(
            initial_snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!stale-shared-room-b:example.org")
        );

        let removal_request = MatrixRoomBindingRemovalRequest {
            tenant_id: provider.tenant_id.clone(),
            agent_id: provider.agent_id.clone(),
            project_id: provider.project_id.clone(),
            installation_id: provider.installation_id.clone(),
            room_id: crate::matrix_outbound::MatrixRoomId::new(
                "!stale-shared-room-b:example.org".to_string(),
            )
            .expect("room B"),
            subject_user_id: UserId::new("user:stale-shared-room-b").expect("actor b"),
        };
        refresher
            .invalidate_before_target_binding_removal(&scope, &extension_id, &removal_request)
            .await
            .expect("pre-invalidate projection before durable room binding removal");
        assert_eq!(
            source
                .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
                .await
                .expect_err("pre-invalidation must make the stale projection fail closed"),
            MatrixInstallationPolicyRejection::InstallationNotFound
        );

        let outcome = target_source
            .remove_room_binding(removal_request)
            .await
            .expect("remove room B from shared source");
        assert_eq!(outcome, MatrixRoomBindingRemovalOutcome::Removed);

        refresher
            .refresh_after_target_binding_mutation(&scope, &extension_id)
            .await
            .expect("projection refresh from mutated shared source");
        let refreshed_snapshot = source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("refreshed snapshot");
        assert!(
            refreshed_snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!fresh-shared-room-a:example.org")
        );
        assert!(
            !refreshed_snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!stale-shared-room-b:example.org"),
            "projection refresh must rebuild from the shared source after room B is removed"
        );
    }

    #[tokio::test]
    async fn matrix_lifecycle_pre_invalidation_uses_removal_request_when_snapshot_is_empty() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!empty-snapshot-remove:example.org".to_string(),
                subject_user_id: UserId::new("user:empty-snapshot-remove").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@empty-snapshot-remove:example.org")
                    .expect("matrix sender"),
            }],
        };
        let scope = matrix_source_backed_scope();
        let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
        let initial_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            Arc::clone(&root),
            Arc::clone(&store) as Arc<dyn ExtensionInstallationStore>,
            vec![provider.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("initial refresher");
        initial_refresher
            .refresh_after_lifecycle_activation(&scope, &extension_id)
            .await
            .expect("publish initial cache");

        let source = FilesystemMatrixPolicySnapshotSource::new(
            crate::wrap_scoped(backend),
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
            matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
        );
        source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect("initial snapshot resolves");

        let empty_target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
            Arc::clone(&root),
            [provider.tenant_id.clone()],
        ));
        let removal_refresher =
            MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
                root,
                store,
                empty_target_source,
                matrix_source_backed_artifact_evidence(),
                "matrix-source-backed-policy-owner".to_string(),
            )
            .expect("removal refresher");
        removal_refresher
            .invalidate_before_target_binding_removal(
                &scope,
                &extension_id,
                &MatrixRoomBindingRemovalRequest {
                    tenant_id: provider.tenant_id.clone(),
                    agent_id: provider.agent_id.clone(),
                    project_id: provider.project_id.clone(),
                    installation_id: provider.installation_id.clone(),
                    room_id: crate::matrix_outbound::MatrixRoomId::new(
                        "!empty-snapshot-remove:example.org".to_string(),
                    )
                    .expect("room"),
                    subject_user_id: UserId::new("user:empty-snapshot-remove").expect("actor"),
                },
            )
            .await
            .expect("pre-invalidation must not need current target snapshot");

        assert_eq!(
            source
                .resolve_matrix_policy_snapshot(
                    &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                    &installation_id,
                )
                .await
                .expect_err("request-derived pre-invalidation tombstones the exact marker"),
            MatrixInstallationPolicyRejection::InstallationNotFound
        );
    }

    #[tokio::test]
    async fn matrix_lifecycle_prepared_publish_refuses_stale_body_after_room_binding_tombstone() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![
                MatrixConfiguredRoomRoute {
                    room_id: "!prepared-fresh-room:example.org".to_string(),
                    subject_user_id: UserId::new("user:prepared-fresh-room").expect("actor a"),
                    matrix_sender_user_id: MatrixUserId::new("@prepared-fresh-room:example.org")
                        .expect("matrix sender a"),
                },
                MatrixConfiguredRoomRoute {
                    room_id: "!prepared-stale-room:example.org".to_string(),
                    subject_user_id: UserId::new("user:prepared-stale-room").expect("actor b"),
                    matrix_sender_user_id: MatrixUserId::new("@prepared-stale-room:example.org")
                        .expect("matrix sender b"),
                },
            ],
        };
        let target_source = Arc::new(FilesystemMatrixRoomBindingStore::new(
            Arc::clone(&root),
            [provider.tenant_id.clone()],
        ));
        target_source
            .seed_from_configs(std::slice::from_ref(&provider))
            .await
            .expect("seed target source");
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::from_shared_target_source(
            root,
            Arc::clone(&store) as Arc<dyn ExtensionInstallationStore>,
            target_source.clone() as Arc<dyn MatrixRoomBindingStore>,
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher");
        let scope = matrix_source_backed_scope();
        let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
        let source = FilesystemMatrixPolicySnapshotSource::new(
            crate::wrap_scoped(backend),
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider),
            matrix_policy_projection_cache_path_for_provider(&provider).expect("cache path"),
        );

        refresher
            .prepare_lifecycle_activation_refresh(&scope, &extension_id)
            .await
            .expect("prepare stale body with both rooms");
        target_source
            .remove_room_binding(MatrixRoomBindingRemovalRequest {
                tenant_id: provider.tenant_id.clone(),
                agent_id: provider.agent_id.clone(),
                project_id: provider.project_id.clone(),
                installation_id: provider.installation_id.clone(),
                room_id: crate::matrix_outbound::MatrixRoomId::new(
                    "!prepared-stale-room:example.org".to_string(),
                )
                .expect("room"),
                subject_user_id: UserId::new("user:prepared-stale-room").expect("actor b"),
            })
            .await
            .expect("remove stale room");
        refresher
            .publish_prepared_lifecycle_activation_refresh(&scope, &extension_id)
            .await
            .expect("stale prepared publish is ignored fail-closed");

        assert_eq!(
            source
                .resolve_matrix_policy_snapshot(
                    &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                    &installation_id,
                )
                .await
                .expect_err("stale prepared body must not get a valid commit marker"),
            MatrixInstallationPolicyRejection::InstallationNotFound
        );
        refresher
            .refresh_after_target_binding_mutation(&scope, &extension_id)
            .await
            .expect("fresh refresh after mutation");
        let snapshot = source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect("fresh snapshot");
        assert!(
            snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!prepared-fresh-room:example.org")
        );
        assert!(
            !snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!prepared-stale-room:example.org")
        );
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_keeps_same_installation_providers_scope_isolated() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider_a = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!provider-a:example.org".to_string(),
                subject_user_id: UserId::new("user:provider-a").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@provider-a:example.org")
                    .expect("matrix sender"),
            }],
        };
        let provider_b = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-other-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-other-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!provider-b:example.org".to_string(),
                subject_user_id: UserId::new("user:provider-b").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@provider-b:example.org")
                    .expect("matrix sender"),
            }],
        };
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider_a.clone(), provider_b.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");
        let scope = matrix_source_backed_scope();

        refresher
            .refresh_after_lifecycle_activation(
                &scope,
                &ExtensionId::new("matrix-product-adapter").expect("extension id"),
            )
            .await
            .expect("refresh projection cache");

        let scoped = crate::wrap_scoped(backend);
        let source_a = FilesystemMatrixPolicySnapshotSource::new(
            Arc::clone(&scoped),
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_a),
            matrix_policy_projection_cache_path_for_provider(&provider_a).expect("path a"),
        );
        let source_b = FilesystemMatrixPolicySnapshotSource::new(
            scoped,
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_b),
            matrix_policy_projection_cache_path_for_provider(&provider_b).expect("path b"),
        );
        let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
        let snapshot_a = source_a
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("snapshot a");
        let snapshot_b = source_b
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("snapshot b");

        assert!(
            snapshot_a
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!provider-a:example.org")
        );
        assert!(
            !snapshot_a
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!provider-b:example.org")
        );
        assert!(
            snapshot_b
                .allowed_senders
                .iter()
                .any(|sender| sender.as_str() == "@provider-b:example.org")
        );
        assert!(
            !snapshot_b
                .allowed_senders
                .iter()
                .any(|sender| sender.as_str() == "@provider-a:example.org")
        );
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_uses_provider_tenant_shared_scope_for_each_provider() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider_a = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-provider-tenant-a").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!provider-tenant-a:example.org".to_string(),
                subject_user_id: UserId::new("user:provider-tenant-a").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@provider-tenant-a:example.org")
                    .expect("matrix sender"),
            }],
        };
        let provider_b = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-provider-tenant-b").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!provider-tenant-b:example.org".to_string(),
                subject_user_id: UserId::new("user:provider-tenant-b").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@provider-tenant-b:example.org")
                    .expect("matrix sender"),
            }],
        };
        let lifecycle_scope = matrix_source_backed_scope();
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider_a.clone(), provider_b.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");

        refresher
            .refresh_after_lifecycle_activation(
                &lifecycle_scope,
                &ExtensionId::new("matrix-product-adapter").expect("extension id"),
            )
            .await
            .expect("refresh projection cache");

        let scoped = crate::wrap_scoped(backend);
        let lifecycle_tenant_scope = matrix_policy_projection_resource_scope(&lifecycle_scope);
        let provider_a_scope =
            matrix_policy_projection_resource_scope_for_provider(&lifecycle_scope, &provider_a);
        let provider_b_scope =
            matrix_policy_projection_resource_scope_for_provider(&lifecycle_scope, &provider_b);
        let provider_a_path = matrix_policy_projection_cache_path_for_provider(&provider_a)
            .expect("provider a cache path");
        let provider_b_path = matrix_policy_projection_cache_path_for_provider(&provider_b)
            .expect("provider b cache path");

        assert!(
            scoped
                .get(&provider_a_scope, &provider_a_path)
                .await
                .expect("provider a scoped cache lookup")
                .is_some(),
            "provider A cache must land in provider A tenant-shared scope"
        );
        assert!(
            scoped
                .get(&provider_b_scope, &provider_b_path)
                .await
                .expect("provider b scoped cache lookup")
                .is_some(),
            "provider B cache must land in provider B tenant-shared scope"
        );
        assert!(
            scoped
                .get(&lifecycle_tenant_scope, &provider_a_path)
                .await
                .expect("lifecycle scoped provider a cache lookup")
                .is_none(),
            "provider cache must not be written under the lifecycle caller tenant"
        );
        assert!(
            scoped
                .get(&lifecycle_tenant_scope, &provider_b_path)
                .await
                .expect("lifecycle scoped provider b cache lookup")
                .is_none(),
            "provider cache must not be written under the lifecycle caller tenant"
        );

        let source_a = FilesystemMatrixPolicySnapshotSource::new(
            Arc::clone(&scoped),
            provider_a_scope,
            provider_a_path,
        );
        let source_b =
            FilesystemMatrixPolicySnapshotSource::new(scoped, provider_b_scope, provider_b_path);
        let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
        let snapshot_a = source_a
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("provider a snapshot");
        let snapshot_b = source_b
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("provider b snapshot");

        assert!(
            snapshot_a
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!provider-tenant-a:example.org")
        );
        assert!(
            snapshot_b
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!provider-tenant-b:example.org")
        );
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_partial_write_failure_is_fail_closed_when_cleanup_fails() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend.clone(), [4, 5]));
        let root: Arc<dyn RootFilesystem> = failing_backend;
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider_a = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!partial-provider-a:example.org".to_string(),
                subject_user_id: UserId::new("user:partial-provider-a").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@partial-provider-a:example.org")
                    .expect("matrix sender"),
            }],
        };
        let provider_b = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-partial-other-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-partial-other-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!partial-provider-b:example.org".to_string(),
                subject_user_id: UserId::new("user:partial-provider-b").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@partial-provider-b:example.org")
                    .expect("matrix sender"),
            }],
        };
        let scope = matrix_source_backed_scope();
        let provider_a_scope =
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_a);
        let provider_a_path = matrix_policy_projection_cache_path_for_provider(&provider_a)
            .expect("provider a cache path");
        let provider_b_scope =
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_b);
        let provider_b_path = matrix_policy_projection_cache_path_for_provider(&provider_b)
            .expect("provider b cache path");
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider_a, provider_b],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");

        refresher
            .refresh_after_lifecycle_activation(
                &scope,
                &ExtensionId::new("matrix-product-adapter").expect("extension id"),
            )
            .await
            .expect_err("second provider write fails");

        let scoped = crate::wrap_scoped(backend);
        let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
        let provider_a_source = FilesystemMatrixPolicySnapshotSource::new(
            Arc::clone(&scoped),
            provider_a_scope,
            provider_a_path,
        );
        let provider_b_source =
            FilesystemMatrixPolicySnapshotSource::new(scoped, provider_b_scope, provider_b_path);

        assert!(matches!(
            provider_a_source
                .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
                .await
                .expect_err("provider a cache must be invalidated after partial failure"),
            MatrixInstallationPolicyRejection::InstallationNotFound
        ));
        assert!(matches!(
            provider_b_source
                .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
                .await
                .expect_err("provider b cache must not become authoritative after write failure"),
            MatrixInstallationPolicyRejection::InstallationNotFound
        ));
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_partial_marker_publish_failure_stays_post_publish_only() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend.clone(), [6, 7]));
        let root: Arc<dyn RootFilesystem> = failing_backend;
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider_a = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!marker-provider-a:example.org".to_string(),
                subject_user_id: UserId::new("user:marker-provider-a").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@marker-provider-a:example.org")
                    .expect("matrix sender"),
            }],
        };
        let provider_b = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-marker-other-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-marker-other-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!marker-provider-b:example.org".to_string(),
                subject_user_id: UserId::new("user:marker-provider-b").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@marker-provider-b:example.org")
                    .expect("matrix sender"),
            }],
        };
        let scope = matrix_source_backed_scope();
        let provider_a_scope =
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_a);
        let provider_a_path = matrix_policy_projection_cache_path_for_provider(&provider_a)
            .expect("provider a cache path");
        let provider_b_scope =
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_b);
        let provider_b_path = matrix_policy_projection_cache_path_for_provider(&provider_b)
            .expect("provider b cache path");
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider_a, provider_b],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");
        let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");

        refresher
            .prepare_lifecycle_activation_refresh(&scope, &extension_id)
            .await
            .expect("prepare writes staged bodies under tombstoned markers");
        let error = refresher
            .publish_prepared_lifecycle_activation_refresh(&scope, &extension_id)
            .await
            .expect_err("second provider marker publish fails");
        let ProductWorkflowError::Transient { reason } = error else {
            panic!("expected marker write failure, got {error}");
        };
        assert!(
            reason.contains("test projection cache write failed"),
            "unexpected marker write failure: {reason}"
        );

        let scoped = crate::wrap_scoped(backend);
        let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");
        let provider_a_source = FilesystemMatrixPolicySnapshotSource::new(
            Arc::clone(&scoped),
            provider_a_scope,
            provider_a_path,
        );
        let provider_b_source =
            FilesystemMatrixPolicySnapshotSource::new(scoped, provider_b_scope, provider_b_path);

        provider_a_source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("provider a marker was published before cleanup failed");
        assert!(matches!(
            provider_b_source
                .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
                .await
                .expect_err("provider b marker must not become authoritative after write failure"),
            MatrixInstallationPolicyRejection::InstallationNotFound
        ));
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_room_removal_tombstone_failure_fails_closed_for_stale_room()
    {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider_with_stale_room = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![
                MatrixConfiguredRoomRoute {
                    room_id: "!fresh-room-a:example.org".to_string(),
                    subject_user_id: UserId::new("user:fresh-room-a").expect("actor a"),
                    matrix_sender_user_id: MatrixUserId::new("@fresh-room-a:example.org")
                        .expect("matrix sender a"),
                },
                MatrixConfiguredRoomRoute {
                    room_id: "!stale-room-b:example.org".to_string(),
                    subject_user_id: UserId::new("user:stale-room-b").expect("actor b"),
                    matrix_sender_user_id: MatrixUserId::new("@stale-room-b:example.org")
                        .expect("matrix sender b"),
                },
            ],
        };
        let provider_after_room_removal = MatrixOutboundTargetProviderConfig {
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!fresh-room-a:example.org".to_string(),
                subject_user_id: UserId::new("user:fresh-room-a").expect("actor a"),
                matrix_sender_user_id: MatrixUserId::new("@fresh-room-a:example.org")
                    .expect("matrix sender a"),
            }],
            ..provider_with_stale_room.clone()
        };
        let initial_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            backend.clone(),
            Arc::clone(&store) as Arc<dyn ExtensionInstallationStore>,
            vec![provider_with_stale_room.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("initial refresher config");
        let scope = matrix_source_backed_scope();
        let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
        let policy_scope =
            matrix_policy_projection_resource_scope_for_provider(&scope, &provider_with_stale_room);
        let cache_path =
            matrix_policy_projection_cache_path_for_provider(&provider_with_stale_room)
                .expect("cache path");
        let adapter_id = ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter");

        initial_refresher
            .refresh_after_lifecycle_activation(&scope, &extension_id)
            .await
            .expect("initial projection with rooms A and B");

        let source = FilesystemMatrixPolicySnapshotSource::new(
            crate::wrap_scoped(backend.clone()),
            policy_scope,
            cache_path,
        );
        let initial_snapshot = source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect("initial snapshot");
        assert!(
            initial_snapshot
                .allowed_rooms
                .iter()
                .any(|room| room.as_str() == "!stale-room-b:example.org"),
            "setup must publish stale room B before the removal refresh"
        );

        let failing_backend = Arc::new(FailOnNthPutFilesystem::new(backend, [1]));
        let removal_refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            failing_backend,
            store,
            vec![provider_after_room_removal],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("removal refresher config");
        removal_refresher
            .refresh_after_lifecycle_activation(&scope, &extension_id)
            .await
            .expect_err("room removal refresh cannot publish the invalidation tombstone");

        let rejection = source
            .resolve_matrix_policy_snapshot(&adapter_id, &installation_id)
            .await
            .expect_err(
                "failed room removal refresh must fail closed instead of serving stale room B",
            );
        assert!(matches!(
            rejection,
            MatrixInstallationPolicyRejection::InstallationNotFound
        ));
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_removal_invalidates_provider_cache_namespace() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id: installation_id.clone(),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!remove-cache:example.org".to_string(),
                subject_user_id: UserId::new("user:remove-cache").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@remove-cache:example.org")
                    .expect("matrix sender"),
            }],
        };
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            Arc::clone(&store) as Arc<dyn ExtensionInstallationStore>,
            vec![provider.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");
        let scope = matrix_source_backed_scope();
        let cache_path = matrix_policy_projection_cache_path_for_provider(&provider).expect("path");
        let policy_scope = matrix_policy_projection_resource_scope_for_provider(&scope, &provider);

        refresher
            .refresh_after_lifecycle_activation(
                &scope,
                &ExtensionId::new("matrix-product-adapter").expect("extension id"),
            )
            .await
            .expect("activation refresh");
        store
            .set_activation_state(
                &ExtensionInstallationId::new("matrix-source-backed-install")
                    .expect("installation id"),
                ExtensionActivationState::Disabled,
            )
            .await
            .expect("disable matrix installation");
        refresher
            .refresh_after_lifecycle_removal(
                &scope,
                &ExtensionId::new("matrix-product-adapter").expect("extension id"),
            )
            .await
            .expect("removal refresh");

        let source = FilesystemMatrixPolicySnapshotSource::new(
            crate::wrap_scoped(backend),
            policy_scope,
            cache_path,
        );
        let error = source
            .resolve_matrix_policy_snapshot(
                &ProductAdapterId::new("matrix-product-adapter/inbound").expect("adapter"),
                &installation_id,
            )
            .await
            .expect_err("removal invalidates provider cache");
        assert!(matches!(
            error,
            MatrixInstallationPolicyRejection::InstallationNotFound
        ));
    }

    #[tokio::test]
    async fn matrix_lifecycle_refresher_ignores_unrelated_extension_lifecycle() {
        let store = Arc::new(InMemoryExtensionInstallationStore::default());
        seed_enabled_matrix_runtime_entry(store.as_ref()).await;
        let backend = Arc::new(InMemoryBackend::default());
        let root: Arc<dyn RootFilesystem> = backend.clone();
        let installation_id =
            AdapterInstallationId::new("matrix-source-backed-install").expect("installation id");
        let provider = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            agent_id: AgentId::new("matrix-source-backed-agent").expect("agent"),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            installation_id,
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: "!unrelated:example.org".to_string(),
                subject_user_id: UserId::new("user:unrelated").expect("actor"),
                matrix_sender_user_id: MatrixUserId::new("@unrelated:example.org")
                    .expect("matrix sender"),
            }],
        };
        let refresher = MatrixLifecyclePolicyProjectionCacheRefresher::new(
            root,
            store,
            vec![provider.clone()],
            matrix_source_backed_artifact_evidence(),
            "matrix-source-backed-policy-owner".to_string(),
        )
        .expect("refresher config");
        let scope = matrix_source_backed_scope();

        refresher
            .refresh_after_lifecycle_activation(
                &scope,
                &ExtensionId::new("github").expect("extension id"),
            )
            .await
            .expect("unrelated extension refresh is ignored");

        let scoped = crate::wrap_scoped(backend);
        let missing = scoped
            .get(
                &matrix_policy_projection_resource_scope(&scope),
                &matrix_policy_projection_cache_path_for_provider(&provider).expect("path"),
            )
            .await
            .expect("cache lookup");
        assert!(missing.is_none());
    }

    async fn seed_enabled_matrix_runtime_entry(store: &InMemoryExtensionInstallationStore) {
        let extension_id = ExtensionId::new("matrix-product-adapter").expect("extension id");
        store
            .upsert_manifest(matrix_runtime_manifest_record())
            .await
            .expect("upsert manifest");
        store
            .upsert_installation(
                ExtensionInstallation::new(
                    ExtensionInstallationId::new("matrix-source-backed-install")
                        .expect("installation id"),
                    extension_id.clone(),
                    ExtensionActivationState::Enabled,
                    ExtensionManifestRef::new(
                        extension_id,
                        Some(ManifestHash::new("sha256:matrix-source-backed").expect("hash")),
                    ),
                    Vec::new(),
                    chrono::Utc::now(),
                    InstallationOwner::Tenant,
                )
                .expect("installation"),
            )
            .await
            .expect("upsert installation");
    }

    fn matrix_runtime_manifest_record() -> ExtensionManifestRecord {
        let host_ports =
            ironclaw_host_runtime::default_host_port_catalog().expect("default host port catalog");
        let contracts =
            crate::extension_host::host_api_contracts::product_extension_host_api_contract_registry()
                .expect("host API contracts");
        ExtensionManifestRecord::from_toml_with_contracts(
            format!(
                r#"
schema_version = "{schema}"
id = "matrix-product-adapter"
name = "Matrix"
version = "0.1.0"
description = "Matrix source-backed projection fixture"
trust = "first_party_requested"

[runtime]
kind = "wasm"
module = "wasm/matrix.wasm"

[[host_api]]
id = "ironclaw.product_adapter/v1"
section = "product_adapter.inbound"

[product_adapter.inbound]
surface_kind = "external_channel"

[product_adapter.inbound.auth]
kind = "shared_secret_header"
header_name = "x-matrix-webhook-secret"

[product_adapter.inbound.capabilities]
flags = ["inbound_messages", "external_final_reply_push"]

[[product_adapter.inbound.required_credentials]]
handle = "matrix-source-access-token"

[[product_adapter.inbound.egress]]
host = "matrix.source.example.org"
credential_handle = "matrix-source-access-token"
"#,
                schema = MANIFEST_SCHEMA_VERSION
            )
            .as_str(),
            ManifestSource::HostBundled,
            &host_ports,
            Some(ManifestHash::new("sha256:matrix-source-backed").expect("hash")),
            &contracts,
        )
        .expect("manifest")
    }

    fn matrix_source_backed_artifact_evidence() -> MatrixRuntimeArtifactEvidence {
        MatrixRuntimeArtifactEvidence {
            artifact_id: ComponentArtifactId::new("matrix-source-backed-component")
                .expect("artifact id"),
            artifact_sha256: ArtifactSha256::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("artifact sha"),
            wit_package: WitPackageName::new("near:source-backed-adapter@0.1.0")
                .expect("wit package"),
            wit_world: WitWorldName::new("source-backed-product-adapter").expect("wit world"),
        }
    }

    fn matrix_source_backed_scope() -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("matrix-source-backed-tenant").expect("tenant"),
            user_id: UserId::new("matrix-source-backed-owner").expect("user"),
            agent_id: Some(AgentId::new("matrix-source-backed-agent").expect("agent")),
            project_id: Some(ProjectId::new("matrix-source-backed-project").expect("project")),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    struct FailOnNthPutFilesystem {
        inner: Arc<InMemoryBackend>,
        fail_on_puts: Vec<usize>,
        put_count: Mutex<usize>,
    }

    impl FailOnNthPutFilesystem {
        fn new(inner: Arc<InMemoryBackend>, fail_on_puts: impl IntoIterator<Item = usize>) -> Self {
            Self {
                inner,
                fail_on_puts: fail_on_puts.into_iter().collect(),
                put_count: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl RootFilesystem for FailOnNthPutFilesystem {
        fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities()
        }

        async fn put(
            &self,
            path: &VirtualPath,
            entry: Entry,
            cas: CasExpectation,
        ) -> Result<RecordVersion, FilesystemError> {
            {
                let mut put_count = self
                    .put_count
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *put_count += 1;
                if self.fail_on_puts.contains(&*put_count) {
                    return Err(FilesystemError::Backend {
                        path: path.clone(),
                        operation: FilesystemOperation::WriteFile,
                        reason: "test projection cache write failed".to_string(),
                    });
                }
            }
            self.inner.put(path, entry, cas).await
        }

        async fn get(
            &self,
            path: &VirtualPath,
        ) -> Result<Option<ironclaw_filesystem::VersionedEntry>, FilesystemError> {
            self.inner.get(path).await
        }

        async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
            self.inner.list_dir(path).await
        }

        async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
            self.inner.stat(path).await
        }

        async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
            self.inner.delete(path).await
        }
    }
}
