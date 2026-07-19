use async_trait::async_trait;
use ironclaw_common::hashing::sha256_hex;
use ironclaw_filesystem::{
    CasExpectation, ContentType, Entry, FilesystemError, RootFilesystem, ScopedFilesystem,
};
use ironclaw_host_api::{
    AgentId, ExtensionId, ProjectId, ResourceScope, ScopedPath, TenantId, UserId, VirtualPath,
};
use ironclaw_matrix_adapter::installation_policy::MatrixUserId;
use ironclaw_outbound::{
    CommunicationDeliveryIntent, OutboundError, ReplyTargetBindingClaim,
    ReplyTargetBindingValidator, ReplyTargetValidationRequest, RunNotificationOrigin,
    ThreadProjectionAccessClaim, ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
};
use ironclaw_product_adapters::AdapterInstallationId;
use ironclaw_product_adapters::ExternalConversationRef;
use ironclaw_product_workflow::{
    ProductOutboundTargetResolver, ProductWorkflowError, RebornOutboundDeliveryTargetCapabilities,
    RebornOutboundDeliveryTargetId, RebornOutboundDeliveryTargetSummary, RebornServicesError,
    RebornServicesErrorCode, RebornServicesErrorKind, VerifiedProductOutboundTargetMetadata,
    WebUiAuthenticatedCaller,
};
use ironclaw_turns::ReplyTargetBindingRef;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::matrix_outbound::MatrixPolicyProviderScope;
use crate::matrix_outbound::MatrixRoomId;
use crate::matrix_product_outbound::MatrixLifecyclePolicyProjectionCacheRefresher;
use crate::outbound::outbound_preferences::OutboundDeliveryTargetEntry;
use crate::outbound::{
    MutableOutboundDeliveryTargetRegistry, OutboundDeliveryTargetProvider,
    OutboundDeliveryTargetRegistrationOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatrixConfiguredRoomRoute {
    pub(crate) room_id: String,
    pub(crate) subject_user_id: UserId,
    pub(crate) matrix_sender_user_id: MatrixUserId,
}

/// Host-trusted Matrix outbound target configuration.
///
/// This config must be derived from deployment or host-owned installation
/// policy, not browser/API input. The tenant, agent, project, installation, and
/// room route fields become delivery authority for Matrix target discovery.
#[derive(Debug, Clone)]
pub(crate) struct MatrixOutboundTargetProviderConfig {
    pub(crate) tenant_id: TenantId,
    pub(crate) agent_id: AgentId,
    pub(crate) project_id: Option<ProjectId>,
    pub(crate) installation_id: AdapterInstallationId,
    pub(crate) configured_room_routes: Vec<MatrixConfiguredRoomRoute>,
}

#[derive(Clone)]
pub(crate) struct MatrixHostOutboundTargetProvider {
    source: MatrixHostOutboundTargetProviderSource,
}

#[derive(Clone)]
enum MatrixHostOutboundTargetProviderSource {
    Static(MatrixHostOutboundTargetProviderConfig),
    Store(Arc<dyn MatrixRoomBindingStore>),
}

impl fmt::Debug for MatrixHostOutboundTargetProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatrixHostOutboundTargetProvider")
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Debug for MatrixHostOutboundTargetProviderSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(config) => f.debug_tuple("Static").field(config).finish(),
            Self::Store(store) => f.debug_tuple("Store").field(store).finish(),
        }
    }
}

#[derive(Debug, Clone)]
struct MatrixHostOutboundTargetProviderConfig {
    tenant_id: TenantId,
    agent_id: AgentId,
    project_id: Option<ProjectId>,
    installation_id: AdapterInstallationId,
    configured_room_routes: Vec<ValidatedMatrixConfiguredRoomRoute>,
    room_target_id_prefix: String,
    room_binding_ref_prefix: String,
    policy_provider_scope_key: String,
}

#[derive(Clone)]
pub(crate) struct MatrixHostProductOutboundTargetResolver {
    source: MatrixHostProductOutboundTargetResolverSource,
}

#[derive(Clone)]
enum MatrixHostProductOutboundTargetResolverSource {
    #[cfg(test)]
    Static(Vec<MatrixHostOutboundTargetProvider>),
    Store(Arc<dyn MatrixRoomBindingStore>),
}

impl fmt::Debug for MatrixHostProductOutboundTargetResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatrixHostProductOutboundTargetResolver")
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Debug for MatrixHostProductOutboundTargetResolverSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(test)]
            Self::Static(providers) => f.debug_tuple("Static").field(providers).finish(),
            Self::Store(store) => f.debug_tuple("Store").field(store).finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MatrixHostReplyTargetPolicy {
    resolver: MatrixHostProductOutboundTargetResolver,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedMatrixOutboundTarget {
    pub(crate) installation_id: AdapterInstallationId,
    pub(crate) policy_provider_scope_key: String,
    pub(crate) policy_provider_scope: MatrixPolicyProviderScope,
    pub(crate) room_id: MatrixRoomId,
    pub(crate) reply_target_binding_ref: ReplyTargetBindingRef,
}

#[derive(Debug, Clone)]
struct ValidatedMatrixConfiguredRoomRoute {
    room_id: MatrixRoomId,
    subject_user_id: UserId,
    route_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatrixRoomBinding {
    pub(crate) tenant_id: TenantId,
    pub(crate) agent_id: AgentId,
    pub(crate) project_id: Option<ProjectId>,
    pub(crate) installation_id: AdapterInstallationId,
    pub(crate) room_id: MatrixRoomId,
    pub(crate) subject_user_id: UserId,
    pub(crate) matrix_sender_user_id: MatrixUserId,
}

#[async_trait]
pub(crate) trait MatrixRoomBindingStore: Send + Sync + fmt::Debug {
    async fn snapshot_provider_configs(
        &self,
    ) -> Result<Vec<MatrixOutboundTargetProviderConfig>, RebornServicesError>;

    async fn list_room_bindings(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        subject_user_id: &UserId,
    ) -> Result<Vec<MatrixRoomBinding>, RebornServicesError>;

    #[cfg(test)]
    async fn resolve_room_binding(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        installation_id: &AdapterInstallationId,
        room_id: &MatrixRoomId,
        subject_user_id: &UserId,
    ) -> Result<Option<MatrixRoomBinding>, RebornServicesError>;

    async fn remove_room_binding(
        &self,
        request: MatrixRoomBindingRemovalRequest,
    ) -> Result<MatrixRoomBindingRemovalOutcome, RebornServicesError>;

    async fn upsert_room_binding(
        &self,
        request: MatrixRoomBindingUpsertRequest,
    ) -> Result<MatrixRoomBindingUpsertOutcome, RebornServicesError>;

    async fn update_room_binding(
        &self,
        request: MatrixRoomBindingUpdateRequest,
    ) -> Result<MatrixRoomBindingUpdateOutcome, RebornServicesError>;

    async fn provider_has_removed_room_binding(
        &self,
        provider: &MatrixOutboundTargetProviderConfig,
    ) -> Result<bool, RebornServicesError>;
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct MutableMatrixOutboundTargetProviders {
    configs: Arc<RwLock<Vec<MatrixOutboundTargetProviderConfig>>>,
}

#[derive(Clone)]
pub(crate) struct FilesystemMatrixRoomBindingStore {
    root_filesystem: Arc<dyn RootFilesystem>,
    filesystem: Arc<ScopedFilesystem<dyn RootFilesystem>>,
    tenant_ids: Arc<RwLock<Vec<TenantId>>>,
}

impl fmt::Debug for FilesystemMatrixRoomBindingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilesystemMatrixRoomBindingStore")
            .field("filesystem", &self.filesystem)
            .field("tenant_ids", &self.tenant_ids)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMatrixRoomBinding {
    tenant_id: String,
    agent_id: String,
    project_id: Option<String>,
    installation_id: String,
    room_id: String,
    subject_user_id: String,
    matrix_sender_user_id: String,
    #[serde(default)]
    deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMatrixRoomBindingTenantIndex {
    tenant_ids: Vec<String>,
}

const MATRIX_ROOM_BINDING_STORE_ROOT: &str = "/tenant-shared/matrix/room-bindings";
const MATRIX_ROOM_BINDING_STORE_SEED_MARKER: &str =
    "/tenant-shared/matrix/room-bindings/.seeded.json";
const MATRIX_ROOM_BINDING_TENANT_INDEX: &str = "/tenants/.matrix-room-bindings/tenants.json";
const MATRIX_ROOM_BINDING_STORE_ACTOR: &str = "user:matrix-room-binding-store";
const MATRIX_ROOM_BINDING_STORE_MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRoomBindingRemovalRequest {
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub project_id: Option<ProjectId>,
    pub installation_id: AdapterInstallationId,
    pub room_id: MatrixRoomId,
    pub subject_user_id: UserId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixRoomBindingRemovalOutcome {
    Removed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRoomBindingUpsertRequest {
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub project_id: Option<ProjectId>,
    pub installation_id: AdapterInstallationId,
    pub room_id: MatrixRoomId,
    pub subject_user_id: UserId,
    pub matrix_sender_user_id: MatrixUserId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixRoomBindingUpsertOutcome {
    Created,
    Updated,
    Unchanged,
    ReboundTombstone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRoomBindingUpdateRequest {
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub project_id: Option<ProjectId>,
    pub installation_id: AdapterInstallationId,
    pub previous_room_id: MatrixRoomId,
    pub subject_user_id: UserId,
    pub new_room_id: MatrixRoomId,
    pub new_matrix_sender_user_id: MatrixUserId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixRoomBindingUpdateOutcome {
    Updated,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatrixRoomBindingMutationAuthority {
    HostOwnedMatrixAdmin,
}

#[derive(Debug, Clone)]
pub(crate) struct MatrixRoomBindingMutationContext {
    scope: ResourceScope,
    extension_id: ExtensionId,
    authority: MatrixRoomBindingMutationAuthority,
}

#[derive(Clone)]
pub(crate) struct MatrixRoomBindingAuthority {
    target_source: Arc<dyn MatrixRoomBindingStore>,
    refresher: Arc<MatrixLifecyclePolicyProjectionCacheRefresher>,
}

impl MatrixRoomBindingMutationContext {
    pub(crate) fn for_host_owned_matrix_admin(
        scope: ResourceScope,
        extension_id: ExtensionId,
    ) -> Self {
        Self {
            scope,
            extension_id,
            authority: MatrixRoomBindingMutationAuthority::HostOwnedMatrixAdmin,
        }
    }

    fn authorize(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
    ) -> Result<(), ProductWorkflowError> {
        match self.authority {
            MatrixRoomBindingMutationAuthority::HostOwnedMatrixAdmin => {}
        }
        if &self.scope.tenant_id != tenant_id
            || self.scope.agent_id.as_ref() != Some(agent_id)
            || self.scope.project_id.as_ref() != project_id
        {
            return Err(ProductWorkflowError::BindingAccessDenied);
        }
        Ok(())
    }
}

impl MatrixRoomBindingAuthority {
    pub(crate) fn new(
        target_source: Arc<dyn MatrixRoomBindingStore>,
        refresher: impl Into<Arc<MatrixLifecyclePolicyProjectionCacheRefresher>>,
    ) -> Self {
        Self {
            target_source,
            refresher: refresher.into(),
        }
    }

    pub(crate) async fn upsert_room_binding(
        &self,
        context: MatrixRoomBindingMutationContext,
        request: MatrixRoomBindingUpsertRequest,
    ) -> Result<MatrixRoomBindingUpsertOutcome, ProductWorkflowError> {
        context.authorize(
            &request.tenant_id,
            &request.agent_id,
            request.project_id.as_ref(),
        )?;
        let outcome = self
            .target_source
            .upsert_room_binding(request)
            .await
            .map_err(map_matrix_target_store_workflow_error)?;
        self.refresher
            .refresh_after_target_binding_mutation(&context.scope, &context.extension_id)
            .await?;
        Ok(outcome)
    }

    pub(crate) async fn update_room_binding(
        &self,
        context: MatrixRoomBindingMutationContext,
        request: MatrixRoomBindingUpdateRequest,
    ) -> Result<MatrixRoomBindingUpdateOutcome, ProductWorkflowError> {
        context.authorize(
            &request.tenant_id,
            &request.agent_id,
            request.project_id.as_ref(),
        )?;
        self.refresher
            .invalidate_before_target_binding_removal(
                &context.scope,
                &context.extension_id,
                &MatrixRoomBindingRemovalRequest {
                    tenant_id: request.tenant_id.clone(),
                    agent_id: request.agent_id.clone(),
                    project_id: request.project_id.clone(),
                    installation_id: request.installation_id.clone(),
                    room_id: request.previous_room_id.clone(),
                    subject_user_id: request.subject_user_id.clone(),
                },
            )
            .await?;
        let outcome = self
            .target_source
            .update_room_binding(request)
            .await
            .map_err(map_matrix_target_store_workflow_error)?;
        self.refresher
            .refresh_after_target_binding_mutation(&context.scope, &context.extension_id)
            .await?;
        Ok(outcome)
    }
}

#[cfg(test)]
impl MutableMatrixOutboundTargetProviders {
    pub(crate) fn new(
        configs: impl IntoIterator<Item = MatrixOutboundTargetProviderConfig>,
    ) -> Result<Self, RebornServicesError> {
        let configs = configs.into_iter().collect::<Vec<_>>();
        validate_matrix_outbound_target_provider_configs(&configs)?;
        Ok(Self {
            configs: Arc::new(RwLock::new(configs)),
        })
    }

    pub(crate) fn snapshot(
        &self,
    ) -> Result<Vec<MatrixOutboundTargetProviderConfig>, RebornServicesError> {
        self.configs
            .read()
            .map(|configs| configs.clone())
            .map_err(|_| matrix_target_backend_error())
    }

    pub(crate) async fn remove_room_binding(
        &self,
        request: MatrixRoomBindingRemovalRequest,
    ) -> Result<MatrixRoomBindingRemovalOutcome, RebornServicesError> {
        MatrixRoomBindingStore::remove_room_binding(self, request).await
    }
}

#[cfg(test)]
#[async_trait]
impl MatrixRoomBindingStore for MutableMatrixOutboundTargetProviders {
    async fn snapshot_provider_configs(
        &self,
    ) -> Result<Vec<MatrixOutboundTargetProviderConfig>, RebornServicesError> {
        self.snapshot()
    }

    async fn list_room_bindings(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        subject_user_id: &UserId,
    ) -> Result<Vec<MatrixRoomBinding>, RebornServicesError> {
        let configs = self
            .configs
            .read()
            .map_err(|_| matrix_target_backend_error())?;
        configs
            .iter()
            .filter(|config| {
                &config.tenant_id == tenant_id
                    && &config.agent_id == agent_id
                    && config.project_id.as_ref() == project_id
            })
            .flat_map(|config| {
                config
                    .configured_room_routes
                    .iter()
                    .filter(move |route| &route.subject_user_id == subject_user_id)
                    .map(move |route| (config, route))
            })
            .map(|(config, route)| {
                MatrixRoomId::new(route.room_id.clone())
                    .map_err(|_| matrix_target_config_error())
                    .map(|room_id| MatrixRoomBinding {
                        tenant_id: config.tenant_id.clone(),
                        agent_id: config.agent_id.clone(),
                        project_id: config.project_id.clone(),
                        installation_id: config.installation_id.clone(),
                        room_id,
                        subject_user_id: route.subject_user_id.clone(),
                        matrix_sender_user_id: route.matrix_sender_user_id.clone(),
                    })
            })
            .collect()
    }

    #[cfg(test)]
    async fn resolve_room_binding(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        installation_id: &AdapterInstallationId,
        room_id: &MatrixRoomId,
        subject_user_id: &UserId,
    ) -> Result<Option<MatrixRoomBinding>, RebornServicesError> {
        Ok(self
            .list_room_bindings(tenant_id, agent_id, project_id, subject_user_id)
            .await?
            .into_iter()
            .find(|binding| {
                &binding.installation_id == installation_id && &binding.room_id == room_id
            }))
    }

    async fn remove_room_binding(
        &self,
        request: MatrixRoomBindingRemovalRequest,
    ) -> Result<MatrixRoomBindingRemovalOutcome, RebornServicesError> {
        let mut configs = self
            .configs
            .write()
            .map_err(|_| matrix_target_backend_error())?;
        let mut removed = false;
        for config in configs.iter_mut().filter(|config| {
            config.tenant_id == request.tenant_id
                && config.agent_id == request.agent_id
                && config.project_id == request.project_id
                && config.installation_id == request.installation_id
        }) {
            let before = config.configured_room_routes.len();
            config.configured_room_routes.retain(|route| {
                route.room_id != request.room_id.as_str()
                    || route.subject_user_id != request.subject_user_id
            });
            removed |= config.configured_room_routes.len() != before;
        }
        if removed {
            Ok(MatrixRoomBindingRemovalOutcome::Removed)
        } else {
            Ok(MatrixRoomBindingRemovalOutcome::NotFound)
        }
    }

    async fn upsert_room_binding(
        &self,
        request: MatrixRoomBindingUpsertRequest,
    ) -> Result<MatrixRoomBindingUpsertOutcome, RebornServicesError> {
        let mut configs = self
            .configs
            .write()
            .map_err(|_| matrix_target_backend_error())?;
        if let Some(config) = configs.iter_mut().find(|config| {
            config.tenant_id == request.tenant_id
                && config.agent_id == request.agent_id
                && config.project_id == request.project_id
                && config.installation_id == request.installation_id
        }) {
            if let Some(route) = config.configured_room_routes.iter_mut().find(|route| {
                route.room_id == request.room_id.as_str()
                    && route.subject_user_id == request.subject_user_id
            }) {
                if route.matrix_sender_user_id == request.matrix_sender_user_id {
                    return Ok(MatrixRoomBindingUpsertOutcome::Unchanged);
                }
                route.matrix_sender_user_id = request.matrix_sender_user_id;
                return Ok(MatrixRoomBindingUpsertOutcome::Updated);
            }
            config
                .configured_room_routes
                .push(MatrixConfiguredRoomRoute {
                    room_id: request.room_id.as_str().to_string(),
                    subject_user_id: request.subject_user_id,
                    matrix_sender_user_id: request.matrix_sender_user_id,
                });
            return Ok(MatrixRoomBindingUpsertOutcome::Created);
        }
        configs.push(MatrixOutboundTargetProviderConfig {
            tenant_id: request.tenant_id,
            agent_id: request.agent_id,
            project_id: request.project_id,
            installation_id: request.installation_id,
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: request.room_id.as_str().to_string(),
                subject_user_id: request.subject_user_id,
                matrix_sender_user_id: request.matrix_sender_user_id,
            }],
        });
        Ok(MatrixRoomBindingUpsertOutcome::Created)
    }

    async fn update_room_binding(
        &self,
        request: MatrixRoomBindingUpdateRequest,
    ) -> Result<MatrixRoomBindingUpdateOutcome, RebornServicesError> {
        let remove_outcome = self
            .remove_room_binding(MatrixRoomBindingRemovalRequest {
                tenant_id: request.tenant_id.clone(),
                agent_id: request.agent_id.clone(),
                project_id: request.project_id.clone(),
                installation_id: request.installation_id.clone(),
                room_id: request.previous_room_id,
                subject_user_id: request.subject_user_id.clone(),
            })
            .await?;
        if remove_outcome == MatrixRoomBindingRemovalOutcome::NotFound {
            return Ok(MatrixRoomBindingUpdateOutcome::NotFound);
        }
        self.upsert_room_binding(MatrixRoomBindingUpsertRequest {
            tenant_id: request.tenant_id,
            agent_id: request.agent_id,
            project_id: request.project_id,
            installation_id: request.installation_id,
            room_id: request.new_room_id,
            subject_user_id: request.subject_user_id,
            matrix_sender_user_id: request.new_matrix_sender_user_id,
        })
        .await?;
        Ok(MatrixRoomBindingUpdateOutcome::Updated)
    }

    async fn provider_has_removed_room_binding(
        &self,
        _provider: &MatrixOutboundTargetProviderConfig,
    ) -> Result<bool, RebornServicesError> {
        Ok(false)
    }
}

impl FilesystemMatrixRoomBindingStore {
    pub(crate) fn new(
        filesystem: Arc<dyn RootFilesystem>,
        tenant_ids: impl IntoIterator<Item = TenantId>,
    ) -> Self {
        Self {
            root_filesystem: Arc::clone(&filesystem),
            filesystem: Arc::new(ScopedFilesystem::new(
                filesystem,
                crate::matrix_room_binding_store_mount_view,
            )),
            tenant_ids: Arc::new(RwLock::new(Vec::new())),
        }
        .with_tenant_ids(tenant_ids)
    }

    fn with_tenant_ids(self, tenant_ids: impl IntoIterator<Item = TenantId>) -> Self {
        if let Ok(mut known) = self.tenant_ids.write() {
            for tenant_id in tenant_ids {
                if !known.iter().any(|known| known == &tenant_id) {
                    known.push(tenant_id);
                }
            }
        }
        self
    }

    pub(crate) async fn seed_from_configs(
        &self,
        configs: &[MatrixOutboundTargetProviderConfig],
    ) -> Result<(), RebornServicesError> {
        validate_matrix_outbound_target_provider_configs(configs)?;
        let mut indexed_tenant_added = false;
        {
            let mut tenant_ids = self
                .tenant_ids
                .write()
                .map_err(|_| matrix_target_backend_error())?;
            for config in configs {
                if !tenant_ids
                    .iter()
                    .any(|tenant_id| tenant_id == &config.tenant_id)
                {
                    tenant_ids.push(config.tenant_id.clone());
                    indexed_tenant_added = true;
                }
            }
        }
        if indexed_tenant_added || !configs.is_empty() {
            self.write_tenant_index().await?;
        }
        let tenants = self.tenant_ids()?;
        for tenant_id in tenants {
            if self.seed_marker_exists(&tenant_id).await? {
                continue;
            }
            for config in configs
                .iter()
                .filter(|config| config.tenant_id == tenant_id)
            {
                for route in &config.configured_room_routes {
                    let room_id = MatrixRoomId::new(route.room_id.clone())
                        .map_err(|_| matrix_target_config_error())?;
                    let binding = MatrixRoomBinding {
                        tenant_id: config.tenant_id.clone(),
                        agent_id: config.agent_id.clone(),
                        project_id: config.project_id.clone(),
                        installation_id: config.installation_id.clone(),
                        room_id,
                        subject_user_id: route.subject_user_id.clone(),
                        matrix_sender_user_id: route.matrix_sender_user_id.clone(),
                    };
                    self.write_binding(&binding).await?;
                }
            }
            self.write_seed_marker(&tenant_id).await?;
        }
        Ok(())
    }

    fn tenant_ids(&self) -> Result<Vec<TenantId>, RebornServicesError> {
        self.tenant_ids
            .read()
            .map(|tenant_ids| tenant_ids.clone())
            .map_err(|_| matrix_target_backend_error())
    }

    async fn tenant_ids_for_snapshot(&self) -> Result<Vec<TenantId>, RebornServicesError> {
        let mut known = self.tenant_ids()?;
        let indexed = self.read_tenant_index().await?;
        let mut changed = false;
        for tenant_id in indexed {
            if !known.iter().any(|known| known == &tenant_id) {
                known.push(tenant_id);
                changed = true;
            }
        }
        known.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        known.dedup_by(|left, right| left.as_str() == right.as_str());
        if changed {
            let mut tenant_ids = self
                .tenant_ids
                .write()
                .map_err(|_| matrix_target_backend_error())?;
            *tenant_ids = known.clone();
        }
        Ok(known)
    }

    async fn remember_tenant(&self, tenant_id: TenantId) -> Result<(), RebornServicesError> {
        let mut changed = false;
        {
            let mut tenant_ids = self
                .tenant_ids
                .write()
                .map_err(|_| matrix_target_backend_error())?;
            if !tenant_ids.iter().any(|known| known == &tenant_id) {
                tenant_ids.push(tenant_id);
                changed = true;
            }
        }
        if changed {
            self.write_tenant_index().await?;
        }
        Ok(())
    }

    fn tenant_index_path() -> Result<VirtualPath, RebornServicesError> {
        VirtualPath::new(MATRIX_ROOM_BINDING_TENANT_INDEX)
            .map_err(|_| matrix_target_backend_error())
    }

    async fn read_tenant_index(&self) -> Result<Vec<TenantId>, RebornServicesError> {
        let path = Self::tenant_index_path()?;
        let Some(versioned) = self
            .root_filesystem
            .get(&path)
            .await
            .map_err(map_matrix_target_filesystem_error)?
        else {
            return Ok(Vec::new());
        };
        let stored: StoredMatrixRoomBindingTenantIndex =
            serde_json::from_slice(&versioned.entry.body)
                .map_err(|_| matrix_target_backend_error())?;
        stored
            .tenant_ids
            .into_iter()
            .map(TenantId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| matrix_target_backend_error())
    }

    async fn write_tenant_index(&self) -> Result<(), RebornServicesError> {
        let mut merged = self.tenant_ids()?;
        for tenant_id in self.read_tenant_index().await? {
            if !merged.iter().any(|known| known == &tenant_id) {
                merged.push(tenant_id);
            }
        }
        merged.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        merged.dedup_by(|left, right| left.as_str() == right.as_str());
        {
            let mut tenant_ids = self
                .tenant_ids
                .write()
                .map_err(|_| matrix_target_backend_error())?;
            *tenant_ids = merged.clone();
        }
        let tenant_ids = merged
            .into_iter()
            .map(|tenant_id| tenant_id.as_str().to_string())
            .collect::<Vec<_>>();
        let stored = StoredMatrixRoomBindingTenantIndex { tenant_ids };
        let bytes = serde_json::to_vec(&stored).map_err(|_| matrix_target_backend_error())?;
        // The current filesystem path exposes unconditional put but no
        // compare-and-swap loop hook, so read-merge-write is the best available
        // protection against dropping tenant IDs recorded by peer processes.
        self.root_filesystem
            .put(
                &Self::tenant_index_path()?,
                Entry::bytes(bytes).with_content_type(ContentType::json()),
                CasExpectation::Any,
            )
            .await
            .map(|_| ())
            .map_err(map_matrix_target_filesystem_error)
    }

    fn scope_for_tenant(&self, tenant_id: &TenantId) -> Result<ResourceScope, RebornServicesError> {
        Ok(ResourceScope {
            tenant_id: tenant_id.clone(),
            user_id: UserId::new(MATRIX_ROOM_BINDING_STORE_ACTOR)
                .map_err(|_| matrix_target_backend_error())?,
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: ironclaw_host_api::InvocationId::new(),
        })
    }

    fn root_path() -> Result<ScopedPath, RebornServicesError> {
        ScopedPath::new(MATRIX_ROOM_BINDING_STORE_ROOT).map_err(|_| matrix_target_backend_error())
    }

    fn seed_marker_path() -> Result<ScopedPath, RebornServicesError> {
        ScopedPath::new(MATRIX_ROOM_BINDING_STORE_SEED_MARKER)
            .map_err(|_| matrix_target_backend_error())
    }

    fn binding_path(binding: &MatrixRoomBinding) -> Result<ScopedPath, RebornServicesError> {
        Self::binding_path_for_key(
            &binding.tenant_id,
            &binding.agent_id,
            binding.project_id.as_ref(),
            &binding.installation_id,
            &binding.room_id,
            &binding.subject_user_id,
        )
    }

    fn binding_path_for_key(
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        installation_id: &AdapterInstallationId,
        room_id: &MatrixRoomId,
        subject_user_id: &UserId,
    ) -> Result<ScopedPath, RebornServicesError> {
        let mut input = Vec::new();
        push_route_key_segment(&mut input, tenant_id.as_str());
        push_route_key_segment(&mut input, agent_id.as_str());
        push_route_key_segment(&mut input, project_id.map(ProjectId::as_str).unwrap_or(""));
        push_route_key_segment(&mut input, installation_id.as_str());
        push_route_key_segment(&mut input, room_id.as_str());
        push_route_key_segment(&mut input, subject_user_id.as_str());
        ScopedPath::new(format!(
            "{MATRIX_ROOM_BINDING_STORE_ROOT}/{}.json",
            sha256_hex(&input)
        ))
        .map_err(|_| matrix_target_backend_error())
    }

    async fn seed_marker_exists(&self, tenant_id: &TenantId) -> Result<bool, RebornServicesError> {
        let scope = self.scope_for_tenant(tenant_id)?;
        let path = Self::seed_marker_path()?;
        match self.filesystem.get(&scope, &path).await {
            Ok(entry) => Ok(entry.is_some()),
            Err(error) if matrix_target_filesystem_not_found(&error) => Ok(false),
            Err(error) => Err(map_matrix_target_filesystem_error(error)),
        }
    }

    async fn write_seed_marker(&self, tenant_id: &TenantId) -> Result<(), RebornServicesError> {
        let scope = self.scope_for_tenant(tenant_id)?;
        let path = Self::seed_marker_path()?;
        let bytes = serde_json::to_vec(&serde_json::json!({ "seeded": true }))
            .map_err(|_| matrix_target_backend_error())?;
        self.filesystem
            .put(
                &scope,
                &path,
                Entry::bytes(bytes).with_content_type(ContentType::json()),
                CasExpectation::Any,
            )
            .await
            .map(|_| ())
            .map_err(map_matrix_target_filesystem_error)
    }

    async fn write_binding(&self, binding: &MatrixRoomBinding) -> Result<(), RebornServicesError> {
        let scope = self.scope_for_tenant(&binding.tenant_id)?;
        let path = Self::binding_path(binding)?;
        if self.binding_path_has_tombstone(&scope, &path).await? {
            return Ok(());
        }
        self.write_binding_at_path(&scope, &path, binding).await
    }

    async fn write_binding_allow_rebind(
        &self,
        binding: &MatrixRoomBinding,
    ) -> Result<(), RebornServicesError> {
        let scope = self.scope_for_tenant(&binding.tenant_id)?;
        let path = Self::binding_path(binding)?;
        self.write_binding_at_path(&scope, &path, binding).await
    }

    async fn write_binding_at_path(
        &self,
        scope: &ResourceScope,
        path: &ScopedPath,
        binding: &MatrixRoomBinding,
    ) -> Result<(), RebornServicesError> {
        let stored = StoredMatrixRoomBinding::from_binding(binding);
        let bytes = serde_json::to_vec(&stored).map_err(|_| matrix_target_backend_error())?;
        self.filesystem
            .put(
                &scope,
                &path,
                Entry::bytes(bytes).with_content_type(ContentType::json()),
                CasExpectation::Any,
            )
            .await
            .map(|_| ())
            .map_err(map_matrix_target_filesystem_error)
    }

    async fn read_binding_at_path(
        &self,
        scope: &ResourceScope,
        path: &ScopedPath,
    ) -> Result<Option<StoredMatrixRoomBinding>, RebornServicesError> {
        let Some(versioned) = self
            .filesystem
            .get(scope, path)
            .await
            .map_err(map_matrix_target_filesystem_error)?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&versioned.entry.body)
            .map(Some)
            .map_err(|_| matrix_target_backend_error())
    }

    async fn write_binding_tombstone(
        &self,
        request: &MatrixRoomBindingRemovalRequest,
    ) -> Result<(), RebornServicesError> {
        let scope = self.scope_for_tenant(&request.tenant_id)?;
        let path = Self::binding_path_for_key(
            &request.tenant_id,
            &request.agent_id,
            request.project_id.as_ref(),
            &request.installation_id,
            &request.room_id,
            &request.subject_user_id,
        )?;
        let stored = StoredMatrixRoomBinding::tombstone_from_request(request);
        let bytes = serde_json::to_vec(&stored).map_err(|_| matrix_target_backend_error())?;
        self.filesystem
            .put(
                &scope,
                &path,
                Entry::bytes(bytes).with_content_type(ContentType::json()),
                CasExpectation::Any,
            )
            .await
            .map_err(map_matrix_target_filesystem_error)?;
        if !self.binding_path_has_tombstone(&scope, &path).await? {
            return Err(matrix_target_backend_error());
        }
        Ok(())
    }

    async fn binding_path_has_tombstone(
        &self,
        scope: &ResourceScope,
        path: &ScopedPath,
    ) -> Result<bool, RebornServicesError> {
        let Some(versioned) = self
            .filesystem
            .get(scope, path)
            .await
            .map_err(map_matrix_target_filesystem_error)?
        else {
            return Ok(false);
        };
        let stored: StoredMatrixRoomBinding = serde_json::from_slice(&versioned.entry.body)
            .map_err(|_| matrix_target_backend_error())?;
        Ok(stored.is_deleted())
    }

    async fn binding_key_has_tombstone(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        installation_id: &AdapterInstallationId,
        room_id: &MatrixRoomId,
        subject_user_id: &UserId,
    ) -> Result<bool, RebornServicesError> {
        let scope = self.scope_for_tenant(tenant_id)?;
        let path = Self::binding_path_for_key(
            tenant_id,
            agent_id,
            project_id,
            installation_id,
            room_id,
            subject_user_id,
        )?;
        self.binding_path_has_tombstone(&scope, &path).await
    }

    async fn read_bindings_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<MatrixRoomBinding>, RebornServicesError> {
        let scope = self.scope_for_tenant(tenant_id)?;
        let root_path = Self::root_path()?;
        let entries = match self
            .filesystem
            .list_dir_bounded(&scope, &root_path, MATRIX_ROOM_BINDING_STORE_MAX_RECORDS)
            .await
        {
            Ok(entries) => entries,
            Err(error) if matrix_target_filesystem_not_found(&error) => return Ok(Vec::new()),
            Err(error) => return Err(map_matrix_target_filesystem_error(error)),
        };
        let mut bindings = Vec::new();
        for entry in entries {
            let name = entry.name.as_str();
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            let path = ScopedPath::new(format!("{MATRIX_ROOM_BINDING_STORE_ROOT}/{name}"))
                .map_err(|_| matrix_target_backend_error())?;
            let Some(versioned) = self
                .filesystem
                .get(&scope, &path)
                .await
                .map_err(map_matrix_target_filesystem_error)?
            else {
                continue;
            };
            let stored: StoredMatrixRoomBinding = serde_json::from_slice(&versioned.entry.body)
                .map_err(|_| matrix_target_backend_error())?;
            if stored.is_deleted() {
                continue;
            }
            let binding = stored.into_binding()?;
            if &binding.tenant_id == tenant_id {
                bindings.push(binding);
            }
        }
        Ok(bindings)
    }
}

impl StoredMatrixRoomBinding {
    fn from_binding(binding: &MatrixRoomBinding) -> Self {
        Self {
            tenant_id: binding.tenant_id.as_str().to_string(),
            agent_id: binding.agent_id.as_str().to_string(),
            project_id: binding
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str().to_string()),
            installation_id: binding.installation_id.as_str().to_string(),
            room_id: binding.room_id.as_str().to_string(),
            subject_user_id: binding.subject_user_id.as_str().to_string(),
            matrix_sender_user_id: binding.matrix_sender_user_id.as_str().to_string(),
            deleted: false,
        }
    }

    fn tombstone_from_request(request: &MatrixRoomBindingRemovalRequest) -> Self {
        Self {
            tenant_id: request.tenant_id.as_str().to_string(),
            agent_id: request.agent_id.as_str().to_string(),
            project_id: request
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str().to_string()),
            installation_id: request.installation_id.as_str().to_string(),
            room_id: request.room_id.as_str().to_string(),
            subject_user_id: request.subject_user_id.as_str().to_string(),
            matrix_sender_user_id: String::new(),
            deleted: true,
        }
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn into_binding(self) -> Result<MatrixRoomBinding, RebornServicesError> {
        Ok(MatrixRoomBinding {
            tenant_id: TenantId::new(self.tenant_id).map_err(|_| matrix_target_backend_error())?,
            agent_id: AgentId::new(self.agent_id).map_err(|_| matrix_target_backend_error())?,
            project_id: self
                .project_id
                .map(ProjectId::new)
                .transpose()
                .map_err(|_| matrix_target_backend_error())?,
            installation_id: AdapterInstallationId::new(self.installation_id)
                .map_err(|_| matrix_target_backend_error())?,
            room_id: MatrixRoomId::new(self.room_id).map_err(|_| matrix_target_backend_error())?,
            subject_user_id: UserId::new(self.subject_user_id)
                .map_err(|_| matrix_target_backend_error())?,
            matrix_sender_user_id: MatrixUserId::new(self.matrix_sender_user_id)
                .map_err(|_| matrix_target_backend_error())?,
        })
    }
}

#[async_trait]
impl MatrixRoomBindingStore for FilesystemMatrixRoomBindingStore {
    async fn snapshot_provider_configs(
        &self,
    ) -> Result<Vec<MatrixOutboundTargetProviderConfig>, RebornServicesError> {
        let mut bindings = Vec::new();
        for tenant_id in self.tenant_ids_for_snapshot().await? {
            bindings.extend(self.read_bindings_for_tenant(&tenant_id).await?);
        }
        matrix_provider_configs_from_bindings(bindings)
    }

    async fn list_room_bindings(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        subject_user_id: &UserId,
    ) -> Result<Vec<MatrixRoomBinding>, RebornServicesError> {
        Ok(self
            .read_bindings_for_tenant(tenant_id)
            .await?
            .into_iter()
            .filter(|binding| {
                &binding.agent_id == agent_id
                    && binding.project_id.as_ref() == project_id
                    && &binding.subject_user_id == subject_user_id
            })
            .collect())
    }

    #[cfg(test)]
    async fn resolve_room_binding(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        project_id: Option<&ProjectId>,
        installation_id: &AdapterInstallationId,
        room_id: &MatrixRoomId,
        subject_user_id: &UserId,
    ) -> Result<Option<MatrixRoomBinding>, RebornServicesError> {
        let path = Self::binding_path_for_key(
            tenant_id,
            agent_id,
            project_id,
            installation_id,
            room_id,
            subject_user_id,
        )?;
        let scope = self.scope_for_tenant(tenant_id)?;
        let Some(versioned) = self
            .filesystem
            .get(&scope, &path)
            .await
            .map_err(map_matrix_target_filesystem_error)?
        else {
            return Ok(None);
        };
        let stored: StoredMatrixRoomBinding = serde_json::from_slice(&versioned.entry.body)
            .map_err(|_| matrix_target_backend_error())?;
        if stored.is_deleted() {
            return Ok(None);
        }
        stored.into_binding().map(Some)
    }

    async fn remove_room_binding(
        &self,
        request: MatrixRoomBindingRemovalRequest,
    ) -> Result<MatrixRoomBindingRemovalOutcome, RebornServicesError> {
        self.remember_tenant(request.tenant_id.clone()).await?;
        let path = Self::binding_path_for_key(
            &request.tenant_id,
            &request.agent_id,
            request.project_id.as_ref(),
            &request.installation_id,
            &request.room_id,
            &request.subject_user_id,
        )?;
        let scope = self.scope_for_tenant(&request.tenant_id)?;
        let existing = self
            .filesystem
            .get(&scope, &path)
            .await
            .map_err(map_matrix_target_filesystem_error)?;
        let outcome = match existing {
            Some(versioned) => {
                let stored: StoredMatrixRoomBinding = serde_json::from_slice(&versioned.entry.body)
                    .map_err(|_| matrix_target_backend_error())?;
                if stored.is_deleted() {
                    MatrixRoomBindingRemovalOutcome::NotFound
                } else {
                    MatrixRoomBindingRemovalOutcome::Removed
                }
            }
            None => MatrixRoomBindingRemovalOutcome::NotFound,
        };
        self.write_binding_tombstone(&request).await?;
        Ok(outcome)
    }

    async fn upsert_room_binding(
        &self,
        request: MatrixRoomBindingUpsertRequest,
    ) -> Result<MatrixRoomBindingUpsertOutcome, RebornServicesError> {
        self.remember_tenant(request.tenant_id.clone()).await?;
        let binding = MatrixRoomBinding {
            tenant_id: request.tenant_id,
            agent_id: request.agent_id,
            project_id: request.project_id,
            installation_id: request.installation_id,
            room_id: request.room_id,
            subject_user_id: request.subject_user_id,
            matrix_sender_user_id: request.matrix_sender_user_id,
        };
        let scope = self.scope_for_tenant(&binding.tenant_id)?;
        let path = Self::binding_path(&binding)?;
        let outcome = match self.read_binding_at_path(&scope, &path).await? {
            Some(stored) if stored.is_deleted() => MatrixRoomBindingUpsertOutcome::ReboundTombstone,
            Some(stored) => {
                let existing = stored.into_binding()?;
                if existing.matrix_sender_user_id == binding.matrix_sender_user_id {
                    MatrixRoomBindingUpsertOutcome::Unchanged
                } else {
                    MatrixRoomBindingUpsertOutcome::Updated
                }
            }
            None => MatrixRoomBindingUpsertOutcome::Created,
        };
        self.write_binding_allow_rebind(&binding).await?;
        Ok(outcome)
    }

    async fn update_room_binding(
        &self,
        request: MatrixRoomBindingUpdateRequest,
    ) -> Result<MatrixRoomBindingUpdateOutcome, RebornServicesError> {
        self.remember_tenant(request.tenant_id.clone()).await?;
        let previous_path = Self::binding_path_for_key(
            &request.tenant_id,
            &request.agent_id,
            request.project_id.as_ref(),
            &request.installation_id,
            &request.previous_room_id,
            &request.subject_user_id,
        )?;
        let scope = self.scope_for_tenant(&request.tenant_id)?;
        let Some(previous) = self.read_binding_at_path(&scope, &previous_path).await? else {
            return Ok(MatrixRoomBindingUpdateOutcome::NotFound);
        };
        if previous.is_deleted() {
            return Ok(MatrixRoomBindingUpdateOutcome::NotFound);
        }
        self.write_binding_tombstone(&MatrixRoomBindingRemovalRequest {
            tenant_id: request.tenant_id.clone(),
            agent_id: request.agent_id.clone(),
            project_id: request.project_id.clone(),
            installation_id: request.installation_id.clone(),
            room_id: request.previous_room_id,
            subject_user_id: request.subject_user_id.clone(),
        })
        .await?;
        self.write_binding_allow_rebind(&MatrixRoomBinding {
            tenant_id: request.tenant_id,
            agent_id: request.agent_id,
            project_id: request.project_id,
            installation_id: request.installation_id,
            room_id: request.new_room_id,
            subject_user_id: request.subject_user_id,
            matrix_sender_user_id: request.new_matrix_sender_user_id,
        })
        .await?;
        Ok(MatrixRoomBindingUpdateOutcome::Updated)
    }

    async fn provider_has_removed_room_binding(
        &self,
        provider: &MatrixOutboundTargetProviderConfig,
    ) -> Result<bool, RebornServicesError> {
        for route in &provider.configured_room_routes {
            let room_id = MatrixRoomId::new(route.room_id.clone())
                .map_err(|_| matrix_target_config_error())?;
            if self
                .binding_key_has_tombstone(
                    &provider.tenant_id,
                    &provider.agent_id,
                    provider.project_id.as_ref(),
                    &provider.installation_id,
                    &room_id,
                    &route.subject_user_id,
                )
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl MatrixHostProductOutboundTargetResolver {
    #[cfg(test)]
    pub(crate) fn new(
        configs: impl IntoIterator<Item = MatrixOutboundTargetProviderConfig>,
    ) -> Result<Self, RebornServicesError> {
        let providers = configs
            .into_iter()
            .map(MatrixHostOutboundTargetProvider::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            source: MatrixHostProductOutboundTargetResolverSource::Static(providers),
        })
    }

    pub(crate) fn from_shared_source(
        target_source: Arc<dyn MatrixRoomBindingStore>,
    ) -> Result<Self, RebornServicesError> {
        Ok(Self {
            source: MatrixHostProductOutboundTargetResolverSource::Store(target_source),
        })
    }

    async fn providers_for_read(
        &self,
    ) -> Result<Vec<MatrixHostOutboundTargetProvider>, RebornServicesError> {
        match &self.source {
            MatrixHostProductOutboundTargetResolverSource::Store(target_source) => target_source
                .snapshot_provider_configs()
                .await?
                .into_iter()
                .map(MatrixHostOutboundTargetProvider::new)
                .collect(),
            #[cfg(test)]
            MatrixHostProductOutboundTargetResolverSource::Static(providers) => {
                Ok(providers.clone())
            }
        }
    }

    pub(crate) async fn resolve_requested_target(
        &self,
        request: &ironclaw_outbound::CommunicationDeliveryResolutionRequest,
    ) -> Option<ResolvedMatrixOutboundTarget> {
        let providers = self.providers_for_read().await.ok()?;
        let requested_target = match &request.intent {
            CommunicationDeliveryIntent::RequestedOutbound(context) => &context.requested_target,
            CommunicationDeliveryIntent::RunNotification(context) => match &context.origin {
                RunNotificationOrigin::LiveSourceRoute { source_route }
                | RunNotificationOrigin::TriggeredFromSourceRoute { source_route, .. } => {
                    &source_route.reply_target_binding_ref
                }
                RunNotificationOrigin::Triggered { .. }
                | RunNotificationOrigin::SystemEvent { .. } => return None,
            },
        };
        providers.iter().find_map(|provider| {
            let provider_config = provider.static_config()?;
            if provider_config.tenant_id != request.scope.tenant_id
                || Some(&provider_config.agent_id) != request.scope.agent_id.as_ref()
                || provider_config.project_id != request.scope.project_id
            {
                return None;
            }
            let route_key = provider.route_key_for_reply_target_binding_ref(requested_target)?;
            let route = provider.configured_route_for_key(route_key)?;
            if route.subject_user_id == request.actor.user_id {
                Some(ResolvedMatrixOutboundTarget {
                    installation_id: provider_config.installation_id.clone(),
                    policy_provider_scope_key: provider_config.policy_provider_scope_key.clone(),
                    policy_provider_scope: matrix_policy_provider_scope_from_config(
                        provider_config,
                    ),
                    room_id: route.room_id.clone(),
                    reply_target_binding_ref: requested_target.clone(),
                })
            } else {
                None
            }
        })
    }

    async fn resolve_target(
        &self,
        target: &ReplyTargetBindingRef,
    ) -> Option<ResolvedMatrixOutboundTarget> {
        let providers = self.providers_for_read().await.ok()?;
        providers.iter().find_map(|provider| {
            let provider_config = provider.static_config()?;
            let route_key = provider.route_key_for_reply_target_binding_ref(target)?;
            let route = provider.configured_route_for_key(route_key)?;
            Some(ResolvedMatrixOutboundTarget {
                installation_id: provider_config.installation_id.clone(),
                policy_provider_scope_key: provider_config.policy_provider_scope_key.clone(),
                policy_provider_scope: matrix_policy_provider_scope_from_config(provider_config),
                room_id: route.room_id.clone(),
                reply_target_binding_ref: target.clone(),
            })
        })
    }

    async fn resolve_candidate(
        &self,
        request: &ReplyTargetValidationRequest,
    ) -> Option<ValidatedMatrixConfiguredRoomRoute> {
        let providers = self.providers_for_read().await.ok()?;
        providers.iter().find_map(|provider| {
            let provider_config = provider.static_config()?;
            if provider_config.tenant_id != request.candidate.tenant_id
                || Some(&provider_config.agent_id) != request.candidate.agent_id.as_ref()
                || provider_config.project_id != request.candidate.project_id
            {
                return None;
            }
            let route_key =
                provider.route_key_for_reply_target_binding_ref(&request.candidate.target)?;
            let route = provider.configured_route_for_key(route_key)?;
            if route.subject_user_id == request.actor.user_id {
                Some(route.clone())
            } else {
                None
            }
        })
    }
}

impl MatrixHostReplyTargetPolicy {
    pub(crate) fn new(resolver: MatrixHostProductOutboundTargetResolver) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl ThreadProjectionAccessPolicy for MatrixHostReplyTargetPolicy {
    /// Matrix final-reply delivery validates reply targets only. Projection
    /// subscriptions are denied here so this policy cannot accidentally grant
    /// broader thread-read authority for a Matrix room binding.
    async fn authorize_projection_access(
        &self,
        _request: ThreadProjectionAccessRequest,
    ) -> Result<ThreadProjectionAccessClaim, OutboundError> {
        Err(OutboundError::AccessDenied)
    }
}

#[async_trait]
impl ReplyTargetBindingValidator for MatrixHostReplyTargetPolicy {
    async fn validate_reply_target(
        &self,
        request: ReplyTargetValidationRequest,
    ) -> Result<ReplyTargetBindingClaim, OutboundError> {
        if self.resolver.resolve_candidate(&request).await.is_some() {
            Ok(ReplyTargetBindingClaim::new(request.candidate.target))
        } else {
            Err(OutboundError::AccessDenied)
        }
    }
}

#[async_trait]
impl ProductOutboundTargetResolver for MatrixHostProductOutboundTargetResolver {
    async fn resolve_product_outbound_target_metadata(
        &self,
        target: &ironclaw_outbound::ValidatedReplyTargetBinding,
        require_direct_message: bool,
    ) -> Result<
        VerifiedProductOutboundTargetMetadata,
        ironclaw_product_workflow::ProductWorkflowError,
    > {
        if require_direct_message {
            return Err(
                ironclaw_product_workflow::ProductWorkflowError::OutboundTargetNotDirectMessage,
            );
        }
        let resolved = self.resolve_target(target.target()).await.ok_or_else(|| {
            ironclaw_product_workflow::ProductWorkflowError::BindingRequired {
                reason: "Matrix outbound target binding is not configured".to_string(),
            }
        })?;
        Ok(VerifiedProductOutboundTargetMetadata {
            external_conversation_ref: ExternalConversationRef::new(
                None,
                resolved.room_id.as_str(),
                None,
                None,
            )
            .map_err(|error| {
                ironclaw_product_workflow::ProductWorkflowError::BindingRequired {
                    reason: format!("Matrix outbound target metadata invalid: {error}"),
                }
            })?,
            external_actor_ref: None,
        })
    }
}

impl MatrixHostOutboundTargetProvider {
    pub(crate) fn new(
        config: MatrixOutboundTargetProviderConfig,
    ) -> Result<Self, RebornServicesError> {
        Self::config_from_provider_config(config).map(|config| Self {
            source: MatrixHostOutboundTargetProviderSource::Static(config),
        })
    }

    fn config_from_provider_config(
        config: MatrixOutboundTargetProviderConfig,
    ) -> Result<MatrixHostOutboundTargetProviderConfig, RebornServicesError> {
        let room_target_id_prefix = format!("matrix:room:{}:", config.installation_id.as_str());
        let room_binding_ref_prefix =
            format!("reply:matrix:room:{}:", config.installation_id.as_str());
        let policy_provider_scope_key = matrix_policy_provider_scope_key(
            &config.tenant_id,
            &config.agent_id,
            config.project_id.as_ref(),
            &config.installation_id,
        );
        let configured_room_routes = config
            .configured_room_routes
            .iter()
            .cloned()
            .map(|route| {
                MatrixRoomId::new(route.room_id)
                    .map_err(|_| matrix_target_config_error())
                    .map(|room_id| ValidatedMatrixConfiguredRoomRoute {
                        route_key: matrix_route_key(
                            &config,
                            route.subject_user_id.as_str(),
                            room_id.as_str(),
                        ),
                        room_id,
                        subject_user_id: route.subject_user_id,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MatrixHostOutboundTargetProviderConfig {
            tenant_id: config.tenant_id,
            agent_id: config.agent_id,
            project_id: config.project_id,
            installation_id: config.installation_id,
            configured_room_routes,
            room_target_id_prefix,
            room_binding_ref_prefix,
            policy_provider_scope_key,
        })
    }

    pub(crate) fn from_shared_source(
        target_source: Arc<dyn MatrixRoomBindingStore>,
    ) -> Result<Self, RebornServicesError> {
        Ok(Self {
            source: MatrixHostOutboundTargetProviderSource::Store(target_source),
        })
    }

    async fn providers_for_read(
        &self,
    ) -> Result<Vec<MatrixHostOutboundTargetProvider>, RebornServicesError> {
        match &self.source {
            MatrixHostOutboundTargetProviderSource::Store(target_source) => target_source
                .snapshot_provider_configs()
                .await?
                .into_iter()
                .map(MatrixHostOutboundTargetProvider::new)
                .collect(),
            MatrixHostOutboundTargetProviderSource::Static(_) => Ok(vec![self.clone()]),
        }
    }

    fn static_config(&self) -> Option<&MatrixHostOutboundTargetProviderConfig> {
        match &self.source {
            MatrixHostOutboundTargetProviderSource::Static(config) => Some(config),
            MatrixHostOutboundTargetProviderSource::Store(_) => None,
        }
    }

    fn caller_matches_provider_context(&self, caller: &WebUiAuthenticatedCaller) -> bool {
        let Some(config) = self.static_config() else {
            return false;
        };
        caller.tenant_id == config.tenant_id
            && caller.agent_id.as_ref() == Some(&config.agent_id)
            && caller.project_id == config.project_id
    }

    fn route_key_for_target_id<'a>(
        &self,
        target_id: &'a RebornOutboundDeliveryTargetId,
    ) -> Option<&'a str> {
        target_id
            .as_str()
            .strip_prefix(&self.static_config()?.room_target_id_prefix)
    }

    fn route_key_for_reply_target_binding_ref<'a>(
        &self,
        target: &'a ReplyTargetBindingRef,
    ) -> Option<&'a str> {
        target
            .as_str()
            .strip_prefix(&self.static_config()?.room_binding_ref_prefix)
    }

    fn configured_route_for_key(
        &self,
        route_key: &str,
    ) -> Option<&ValidatedMatrixConfiguredRoomRoute> {
        self.static_config()?
            .configured_room_routes
            .iter()
            .find(|route| route.route_key == route_key)
    }

    fn entry_for_room_route(
        &self,
        route: &ValidatedMatrixConfiguredRoomRoute,
    ) -> Result<OutboundDeliveryTargetEntry, RebornServicesError> {
        debug_assert!(route.room_id.as_str().starts_with('!'));
        let Some(config) = self.static_config() else {
            return Err(matrix_target_backend_error());
        };
        let target_id = RebornOutboundDeliveryTargetId::new(format!(
            "{}{}",
            config.room_target_id_prefix, route.route_key
        ))
        .map_err(|_| matrix_target_backend_error())?;
        Ok(OutboundDeliveryTargetEntry {
            summary: RebornOutboundDeliveryTargetSummary::new(
                target_id,
                "matrix",
                "Matrix room",
                Some("Configured Matrix room".to_string()),
            )
            .map_err(|_| matrix_target_backend_error())?,
            capabilities: RebornOutboundDeliveryTargetCapabilities {
                final_replies: true,
                gate_prompts: false,
                auth_prompts: false,
            },
            reply_target_binding_ref: ReplyTargetBindingRef::new(format!(
                "{}{}",
                config.room_binding_ref_prefix, route.route_key
            ))
            .map_err(|_| matrix_target_backend_error())?,
        })
    }

    fn provider_for_binding(
        binding: MatrixRoomBinding,
    ) -> Result<MatrixHostOutboundTargetProvider, RebornServicesError> {
        MatrixHostOutboundTargetProvider::new(MatrixOutboundTargetProviderConfig {
            tenant_id: binding.tenant_id,
            agent_id: binding.agent_id,
            project_id: binding.project_id,
            installation_id: binding.installation_id,
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: binding.room_id.as_str().to_string(),
                subject_user_id: binding.subject_user_id,
                matrix_sender_user_id: binding.matrix_sender_user_id,
            }],
        })
    }

    fn resolve_for_route_key(
        &self,
        caller: &WebUiAuthenticatedCaller,
        route_key: &str,
    ) -> Result<Option<OutboundDeliveryTargetEntry>, RebornServicesError> {
        if !self.caller_matches_provider_context(caller) {
            return Ok(None);
        }
        let Some(route) = self.configured_route_for_key(route_key) else {
            return Ok(None);
        };
        if route.subject_user_id != caller.user_id {
            return Ok(None);
        }
        self.entry_for_room_route(route).map(Some)
    }
}

#[async_trait]
impl OutboundDeliveryTargetProvider for MatrixHostOutboundTargetProvider {
    async fn list_outbound_delivery_targets(
        &self,
        caller: &WebUiAuthenticatedCaller,
    ) -> Result<Vec<OutboundDeliveryTargetEntry>, RebornServicesError> {
        if let MatrixHostOutboundTargetProviderSource::Store(target_source) = &self.source {
            let Some(agent_id) = caller.agent_id.as_ref() else {
                return Ok(Vec::new());
            };
            let bindings = target_source
                .list_room_bindings(
                    &caller.tenant_id,
                    agent_id,
                    caller.project_id.as_ref(),
                    &caller.user_id,
                )
                .await?;
            let mut entries = Vec::with_capacity(bindings.len());
            for binding in bindings {
                let provider = Self::provider_for_binding(binding)?;
                entries.extend(provider.list_outbound_delivery_targets(caller).await?);
            }
            return Ok(entries);
        }
        if !self.caller_matches_provider_context(caller) {
            return Ok(Vec::new());
        }
        let Some(config) = self.static_config() else {
            return Err(matrix_target_backend_error());
        };
        config
            .configured_room_routes
            .iter()
            .filter(|route| route.subject_user_id == caller.user_id)
            .map(|route| self.entry_for_room_route(route))
            .collect()
    }

    async fn resolve_outbound_delivery_target(
        &self,
        caller: &WebUiAuthenticatedCaller,
        target_id: &RebornOutboundDeliveryTargetId,
    ) -> Result<Option<OutboundDeliveryTargetEntry>, RebornServicesError> {
        if matches!(
            self.source,
            MatrixHostOutboundTargetProviderSource::Store(_)
        ) {
            for provider in self.providers_for_read().await? {
                if let Some(entry) = provider
                    .resolve_outbound_delivery_target(caller, target_id)
                    .await?
                {
                    return Ok(Some(entry));
                }
            }
            return Ok(None);
        }
        let Some(route_key) = self.route_key_for_target_id(target_id) else {
            return Ok(None);
        };
        self.resolve_for_route_key(caller, route_key)
    }

    async fn resolve_reply_target_binding(
        &self,
        caller: &WebUiAuthenticatedCaller,
        target: &ReplyTargetBindingRef,
    ) -> Result<Option<OutboundDeliveryTargetEntry>, RebornServicesError> {
        if matches!(
            self.source,
            MatrixHostOutboundTargetProviderSource::Store(_)
        ) {
            for provider in self.providers_for_read().await? {
                if let Some(entry) = provider
                    .resolve_reply_target_binding(caller, target)
                    .await?
                {
                    return Ok(Some(entry));
                }
            }
            return Ok(None);
        }
        let Some(route_key) = self.route_key_for_reply_target_binding_ref(target) else {
            return Ok(None);
        };
        self.resolve_for_route_key(caller, route_key)
    }
}

fn validate_matrix_outbound_target_provider_configs(
    configs: &[MatrixOutboundTargetProviderConfig],
) -> Result<(), RebornServicesError> {
    configs
        .iter()
        .cloned()
        .map(MatrixHostOutboundTargetProvider::new)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

pub(crate) fn validate_matrix_outbound_target_provider_configs_for_runtime(
    configs: &[MatrixOutboundTargetProviderConfig],
) -> Result<(), RebornServicesError> {
    validate_matrix_outbound_target_provider_configs(configs)
}

fn matrix_provider_configs_from_bindings(
    bindings: Vec<MatrixRoomBinding>,
) -> Result<Vec<MatrixOutboundTargetProviderConfig>, RebornServicesError> {
    let mut configs: Vec<MatrixOutboundTargetProviderConfig> = Vec::new();
    for binding in bindings {
        let route = MatrixConfiguredRoomRoute {
            room_id: binding.room_id.as_str().to_string(),
            subject_user_id: binding.subject_user_id,
            matrix_sender_user_id: binding.matrix_sender_user_id,
        };
        if let Some(config) = configs.iter_mut().find(|config| {
            config.tenant_id == binding.tenant_id
                && config.agent_id == binding.agent_id
                && config.project_id == binding.project_id
                && config.installation_id == binding.installation_id
        }) {
            config.configured_room_routes.push(route);
        } else {
            configs.push(MatrixOutboundTargetProviderConfig {
                tenant_id: binding.tenant_id,
                agent_id: binding.agent_id,
                project_id: binding.project_id,
                installation_id: binding.installation_id,
                configured_room_routes: vec![route],
            });
        }
    }
    validate_matrix_outbound_target_provider_configs(&configs)?;
    Ok(configs)
}

fn matrix_policy_provider_scope_from_config(
    config: &MatrixHostOutboundTargetProviderConfig,
) -> MatrixPolicyProviderScope {
    MatrixPolicyProviderScope {
        tenant_id: config.tenant_id.clone(),
        agent_id: config.agent_id.clone(),
        project_id: config.project_id.clone(),
    }
}

#[cfg(test)]
pub(crate) fn register_matrix_outbound_target_provider(
    registry: &MutableOutboundDeliveryTargetRegistry,
    config: MatrixOutboundTargetProviderConfig,
) -> Result<OutboundDeliveryTargetRegistrationOutcome, RebornServicesError> {
    let provider_key = matrix_outbound_target_provider_key(&config);
    let provider = MatrixHostOutboundTargetProvider::new(config)?;
    registry.register_provider(provider_key, std::sync::Arc::new(provider))
}

pub(crate) fn register_matrix_outbound_target_provider_source(
    registry: &MutableOutboundDeliveryTargetRegistry,
    target_source: Arc<dyn MatrixRoomBindingStore>,
) -> Result<OutboundDeliveryTargetRegistrationOutcome, RebornServicesError> {
    let provider = MatrixHostOutboundTargetProvider::from_shared_source(target_source)?;
    registry.register_provider(
        "matrix:outbound-target-provider:shared".to_string(),
        std::sync::Arc::new(provider),
    )
}

pub(crate) fn matrix_policy_provider_scope_key(
    tenant_id: &TenantId,
    agent_id: &AgentId,
    project_id: Option<&ProjectId>,
    installation_id: &AdapterInstallationId,
) -> String {
    let mut input = Vec::new();
    push_route_key_segment(&mut input, tenant_id.as_str());
    push_route_key_segment(&mut input, agent_id.as_str());
    push_route_key_segment(&mut input, project_id.map(ProjectId::as_str).unwrap_or(""));
    push_route_key_segment(&mut input, installation_id.as_str());
    sha256_hex(&input)
}

#[cfg(test)]
fn matrix_outbound_target_provider_key(config: &MatrixOutboundTargetProviderConfig) -> String {
    format!(
        "matrix:outbound-target-provider:{}",
        matrix_policy_provider_scope_key(
            &config.tenant_id,
            &config.agent_id,
            config.project_id.as_ref(),
            &config.installation_id,
        )
    )
}

fn matrix_route_key(
    config: &MatrixOutboundTargetProviderConfig,
    subject_user_id: &str,
    room_id: &str,
) -> String {
    let mut input = Vec::new();
    push_route_key_segment(&mut input, config.tenant_id.as_str());
    push_route_key_segment(&mut input, config.agent_id.as_str());
    push_route_key_segment(
        &mut input,
        config
            .project_id
            .as_ref()
            .map(ProjectId::as_str)
            .unwrap_or(""),
    );
    push_route_key_segment(&mut input, config.installation_id.as_str());
    push_route_key_segment(&mut input, subject_user_id);
    push_route_key_segment(&mut input, room_id);
    sha256_hex(&input)
}

fn push_route_key_segment(input: &mut Vec<u8>, segment: &str) {
    input.extend_from_slice(segment.len().to_string().as_bytes());
    input.push(b':');
    input.extend_from_slice(segment.as_bytes());
    input.push(b'|');
}

fn matrix_target_config_error() -> RebornServicesError {
    RebornServicesError {
        code: RebornServicesErrorCode::InvalidRequest,
        kind: RebornServicesErrorKind::Validation,
        status_code: 400,
        retryable: false,
        field: Some("configured_room_routes.room_id".to_string()),
        validation_code: None,
    }
}

fn matrix_target_backend_error() -> RebornServicesError {
    RebornServicesError {
        code: RebornServicesErrorCode::Unavailable,
        kind: RebornServicesErrorKind::ServiceUnavailable,
        status_code: 503,
        retryable: true,
        field: None,
        validation_code: None,
    }
}

fn map_matrix_target_filesystem_error(error: FilesystemError) -> RebornServicesError {
    if matrix_target_filesystem_not_found(&error) {
        return matrix_target_backend_error();
    }
    matrix_target_backend_error()
}

fn map_matrix_target_store_workflow_error(error: RebornServicesError) -> ProductWorkflowError {
    if error.status_code >= 500 || error.retryable {
        ProductWorkflowError::Transient {
            reason: format!("Matrix room binding store mutation failed: {error}"),
        }
    } else {
        ProductWorkflowError::InvalidBindingRequest {
            reason: format!("Matrix room binding store mutation rejected: {error}"),
        }
    }
}

fn matrix_target_filesystem_not_found(error: &FilesystemError) -> bool {
    matches!(error, FilesystemError::NotFound { .. })
}

#[cfg(test)]
mod tests {
    use ironclaw_event_projections::ProjectionScope;
    use ironclaw_filesystem::{InMemoryBackend, RootFilesystem};
    use ironclaw_host_api::{AgentId, ProjectId, TenantId, ThreadId, UserId};
    use ironclaw_matrix_adapter::installation_policy::MatrixUserId;
    use ironclaw_outbound::{
        CommunicationDeliveryIntent, CommunicationDeliveryResolutionRequest, CommunicationModality,
        RequestedOutboundContext, RequestedOutboundKind, RunNotificationContext,
        RunNotificationEventKind, RunNotificationOrigin, SourceRouteContext,
        ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
    };
    use ironclaw_product_adapters::AdapterInstallationId;
    use ironclaw_product_workflow::{RebornOutboundDeliveryTargetId, WebUiAuthenticatedCaller};
    use ironclaw_turns::{ReplyTargetBindingRef, TurnActor, TurnScope};
    use std::sync::Arc;

    use crate::matrix_outbound_targets::{
        FilesystemMatrixRoomBindingStore, MatrixConfiguredRoomRoute,
        MatrixHostOutboundTargetProvider, MatrixHostProductOutboundTargetResolver,
        MatrixHostReplyTargetPolicy, MatrixOutboundTargetProviderConfig,
        MatrixRoomBindingRemovalOutcome, MatrixRoomBindingRemovalRequest, MatrixRoomBindingStore,
        MutableMatrixOutboundTargetProviders,
    };
    use crate::outbound::{
        MutableOutboundDeliveryTargetRegistry, OutboundDeliveryTargetProvider,
        OutboundDeliveryTargetRegistrationOutcome,
    };

    const TENANT: &str = "tenant:matrix";
    const OTHER_TENANT: &str = "tenant:other";
    const USER: &str = "user:alice";
    const OTHER_USER: &str = "user:bob";
    const AGENT: &str = "agent:matrix";
    const PROJECT: &str = "project:matrix";
    const INSTALLATION: &str = "inst_matrix";
    const OTHER_INSTALLATION: &str = "inst_other";
    const ROOM: &str = "!room:example.org";
    const OTHER_ROOM: &str = "!other:example.org";
    const ROOM_B: &str = "!room-b:example.org";
    const MATRIX_USER: &str = "@alice:example.org";
    const OTHER_MATRIX_USER: &str = "@bob:example.org";

    fn caller(user_id: &str) -> WebUiAuthenticatedCaller {
        WebUiAuthenticatedCaller::new(
            TenantId::new(TENANT).expect("tenant"),
            UserId::new(user_id).expect("user"),
            Some(AgentId::new(AGENT).expect("agent")),
            Some(ProjectId::new(PROJECT).expect("project")),
        )
    }

    fn foreign_tenant_caller() -> WebUiAuthenticatedCaller {
        WebUiAuthenticatedCaller::new(
            TenantId::new(OTHER_TENANT).expect("tenant"),
            UserId::new(USER).expect("user"),
            Some(AgentId::new(AGENT).expect("agent")),
            Some(ProjectId::new(PROJECT).expect("project")),
        )
    }

    fn caller_for_tenant(tenant_id: &str, user_id: &str) -> WebUiAuthenticatedCaller {
        WebUiAuthenticatedCaller::new(
            TenantId::new(tenant_id).expect("tenant"),
            UserId::new(user_id).expect("user"),
            Some(AgentId::new(AGENT).expect("agent")),
            Some(ProjectId::new(PROJECT).expect("project")),
        )
    }

    fn provider_config(
        installation_id: &str,
        configured_room_routes: Vec<MatrixConfiguredRoomRoute>,
    ) -> MatrixOutboundTargetProviderConfig {
        MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new(TENANT).expect("tenant"),
            agent_id: AgentId::new(AGENT).expect("agent"),
            project_id: Some(ProjectId::new(PROJECT).expect("project")),
            installation_id: AdapterInstallationId::new(installation_id).expect("installation"),
            configured_room_routes,
        }
    }

    fn room_route(
        room_id: &str,
        subject_user_id: &str,
        matrix_sender_user_id: &str,
    ) -> MatrixConfiguredRoomRoute {
        MatrixConfiguredRoomRoute {
            room_id: room_id.to_string(),
            subject_user_id: UserId::new(subject_user_id).expect("subject user"),
            matrix_sender_user_id: MatrixUserId::new(matrix_sender_user_id).expect("matrix sender"),
        }
    }

    fn build_provider(installation_id: &str) -> MatrixHostOutboundTargetProvider {
        MatrixHostOutboundTargetProvider::new(provider_config(
            installation_id,
            vec![
                room_route(ROOM, USER, MATRIX_USER),
                room_route(OTHER_ROOM, OTHER_USER, OTHER_MATRIX_USER),
            ],
        ))
        .expect("valid Matrix target provider config")
    }

    fn workflow_scope() -> TurnScope {
        TurnScope::new(
            TenantId::new(TENANT).expect("tenant"),
            Some(AgentId::new(AGENT).expect("agent")),
            Some(ProjectId::new(PROJECT).expect("project")),
            ThreadId::new("thread:matrix").expect("thread"),
        )
    }

    fn delivery_resolution_request(
        target: ReplyTargetBindingRef,
    ) -> CommunicationDeliveryResolutionRequest {
        CommunicationDeliveryResolutionRequest {
            scope: workflow_scope(),
            actor: TurnActor::new(UserId::new(USER).expect("user")),
            modality: CommunicationModality::Text,
            intent: CommunicationDeliveryIntent::RequestedOutbound(RequestedOutboundContext {
                requested_target: target,
                requested_kind: RequestedOutboundKind::ProductMessage,
            }),
        }
    }

    fn live_source_route_resolution_request(
        target: ReplyTargetBindingRef,
    ) -> CommunicationDeliveryResolutionRequest {
        CommunicationDeliveryResolutionRequest {
            scope: workflow_scope(),
            actor: TurnActor::new(UserId::new(USER).expect("user")),
            modality: CommunicationModality::Text,
            intent: CommunicationDeliveryIntent::RunNotification(RunNotificationContext {
                event_kind: RunNotificationEventKind::FinalReplyReady,
                origin: RunNotificationOrigin::LiveSourceRoute {
                    source_route: SourceRouteContext {
                        reply_target_binding_ref: target,
                    },
                },
            }),
        }
    }

    #[tokio::test]
    async fn matrix_private_provider_registers_through_shared_outbound_target_registry() {
        let registry = MutableOutboundDeliveryTargetRegistry::default();

        let outcome = super::register_matrix_outbound_target_provider(
            &registry,
            provider_config(INSTALLATION, vec![room_route(ROOM, USER, MATRIX_USER)]),
        )
        .expect("Matrix outbound target provider should register");

        assert_eq!(
            outcome,
            OutboundDeliveryTargetRegistrationOutcome::Registered
        );
        let listed = registry
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("registered Matrix provider should list through shared registry");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].summary.channel.as_str(), "matrix");
        assert!(listed[0].capabilities.final_replies);
    }

    #[tokio::test]
    async fn matrix_resolver_derives_installation_from_requested_reply_target() {
        let second = build_provider(OTHER_INSTALLATION);
        let second_target = second
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("second installation target list")
            .into_iter()
            .next()
            .expect("second installation target");
        let resolver = MatrixHostProductOutboundTargetResolver::new([
            provider_config(INSTALLATION, vec![room_route(ROOM, USER, MATRIX_USER)]),
            provider_config(
                OTHER_INSTALLATION,
                vec![room_route(ROOM, USER, MATRIX_USER)],
            ),
        ])
        .expect("multi-installation resolver");

        let resolved = resolver
            .resolve_requested_target(&delivery_resolution_request(
                second_target.reply_target_binding_ref,
            ))
            .await
            .expect("requested Matrix target resolves");

        assert_eq!(
            resolved.installation_id,
            AdapterInstallationId::new(OTHER_INSTALLATION).expect("installation")
        );
        assert_eq!(resolved.room_id.as_str(), ROOM);
    }

    #[tokio::test]
    async fn matrix_resolver_derives_installation_from_live_source_route_notification() {
        let second = build_provider(OTHER_INSTALLATION);
        let second_target = second
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("second installation target list")
            .into_iter()
            .next()
            .expect("second installation target");
        let resolver = MatrixHostProductOutboundTargetResolver::new([
            provider_config(INSTALLATION, vec![room_route(ROOM, USER, MATRIX_USER)]),
            provider_config(
                OTHER_INSTALLATION,
                vec![room_route(ROOM, USER, MATRIX_USER)],
            ),
        ])
        .expect("multi-installation resolver");

        let resolved = resolver
            .resolve_requested_target(&live_source_route_resolution_request(
                second_target.reply_target_binding_ref,
            ))
            .await
            .expect("live source-route Matrix target resolves");

        assert_eq!(
            resolved.installation_id,
            AdapterInstallationId::new(OTHER_INSTALLATION).expect("installation")
        );
        assert_eq!(resolved.room_id.as_str(), ROOM);
    }

    #[tokio::test]
    async fn matrix_reply_target_policy_denies_projection_access() {
        let resolver = MatrixHostProductOutboundTargetResolver::new([provider_config(
            INSTALLATION,
            vec![room_route(ROOM, USER, MATRIX_USER)],
        )])
        .expect("resolver");
        let policy = MatrixHostReplyTargetPolicy::new(resolver);
        let scope = workflow_scope();

        let error = policy
            .authorize_projection_access(ThreadProjectionAccessRequest {
                actor: TurnActor::new(UserId::new(USER).expect("user")),
                scope: ProjectionScope::from_resource_scope(&scope.to_resource_scope()),
                thread_id: scope.thread_id.clone(),
            })
            .await
            .expect_err("Matrix live caller does not authorize projection subscriptions");

        assert!(matches!(
            error,
            ironclaw_outbound::OutboundError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn matrix_private_provider_key_scopes_same_installation_across_tenants() {
        let registry = MutableOutboundDeliveryTargetRegistry::default();
        let installation_id = INSTALLATION;
        let first = provider_config(installation_id, vec![room_route(ROOM, USER, MATRIX_USER)]);
        let second = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new(OTHER_TENANT).expect("other tenant"),
            agent_id: AgentId::new(AGENT).expect("agent"),
            project_id: Some(ProjectId::new(PROJECT).expect("project")),
            installation_id: AdapterInstallationId::new(installation_id).expect("installation"),
            configured_room_routes: vec![room_route(OTHER_ROOM, USER, MATRIX_USER)],
        };

        assert_eq!(
            super::register_matrix_outbound_target_provider(&registry, first)
                .expect("first Matrix provider registers"),
            OutboundDeliveryTargetRegistrationOutcome::Registered
        );
        assert_eq!(
            super::register_matrix_outbound_target_provider(&registry, second)
                .expect("second Matrix provider registers"),
            OutboundDeliveryTargetRegistrationOutcome::Registered,
            "same installation id in another tenant must not replace the first provider"
        );

        assert_eq!(
            registry
                .list_outbound_delivery_targets(&caller_for_tenant(TENANT, USER))
                .await
                .expect("first tenant target list")
                .len(),
            1
        );
        assert_eq!(
            registry
                .list_outbound_delivery_targets(&caller_for_tenant(OTHER_TENANT, USER))
                .await
                .expect("second tenant target list")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn matrix_room_target_lists_opaque_refs_without_room_id_leakage() {
        let provider = build_provider(INSTALLATION);

        let listed = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("target list");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].summary.channel.as_str(), "matrix");
        assert!(listed[0].capabilities.final_replies);
        assert!(
            !listed[0].summary.target_id.as_str().contains(ROOM),
            "listed target id must not expose raw Matrix room id"
        );
        assert!(
            !listed[0].reply_target_binding_ref.as_str().contains(ROOM),
            "listed reply binding ref must not expose raw Matrix room id"
        );
        assert!(
            !listed[0].summary.display_name.as_str().contains(ROOM),
            "listed display name must not expose raw Matrix room id"
        );
        assert!(
            !listed[0]
                .summary
                .description
                .as_ref()
                .map(|description| description.as_str().contains(ROOM))
                .unwrap_or(false),
            "listed description must not expose raw Matrix room id"
        );
    }

    #[tokio::test]
    async fn matrix_room_target_resolves_listed_opaque_refs_for_owner() {
        let provider = build_provider(INSTALLATION);

        let listed = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("target list");
        let listed = listed.first().expect("owned Matrix room target");

        let resolved = provider
            .resolve_outbound_delivery_target(&caller(USER), &listed.summary.target_id)
            .await
            .expect("target resolve")
            .expect("owned Matrix room target");

        assert_eq!(
            resolved.reply_target_binding_ref,
            listed.reply_target_binding_ref
        );
        assert_eq!(
            provider
                .resolve_reply_target_binding(&caller(USER), &listed.reply_target_binding_ref)
                .await
                .expect("binding resolve")
                .expect("owned Matrix room binding")
                .summary
                .target_id,
            listed.summary.target_id
        );
    }

    #[tokio::test]
    async fn matrix_room_binding_removal_shared_source_drops_listing_resolution_and_resolver() {
        let source = MutableMatrixOutboundTargetProviders::new([provider_config(
            INSTALLATION,
            vec![
                room_route(ROOM, USER, MATRIX_USER),
                room_route(ROOM_B, USER, MATRIX_USER),
            ],
        )])
        .expect("shared Matrix target source");
        let store: Arc<dyn super::MatrixRoomBindingStore> = Arc::new(source.clone());
        let provider = MatrixHostOutboundTargetProvider::from_shared_source(Arc::clone(&store))
            .expect("provider");
        let resolver =
            MatrixHostProductOutboundTargetResolver::from_shared_source(Arc::clone(&store))
                .expect("resolver");

        let listed = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("initial target list");
        assert_eq!(listed.len(), 2);
        let mut room_b_binding = None;
        for target in &listed {
            let Some(resolved) = resolver
                .resolve_requested_target(&delivery_resolution_request(
                    target.reply_target_binding_ref.clone(),
                ))
                .await
            else {
                continue;
            };
            if resolved.room_id.as_str() == ROOM_B {
                room_b_binding = Some(target.reply_target_binding_ref.clone());
                break;
            }
        }
        let room_b_binding = room_b_binding.expect("room B binding should initially resolve");

        let outcome = source
            .remove_room_binding(MatrixRoomBindingRemovalRequest {
                tenant_id: TenantId::new(TENANT).expect("tenant"),
                agent_id: AgentId::new(AGENT).expect("agent"),
                project_id: Some(ProjectId::new(PROJECT).expect("project")),
                installation_id: AdapterInstallationId::new(INSTALLATION).expect("installation"),
                room_id: crate::matrix_outbound::MatrixRoomId::new(ROOM_B.to_string())
                    .expect("room B"),
                subject_user_id: UserId::new(USER).expect("user"),
            })
            .await
            .expect("room B removal");
        assert_eq!(outcome, MatrixRoomBindingRemovalOutcome::Removed);

        let after_removal = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("target list after room B removal");
        assert_eq!(after_removal.len(), 1);
        assert!(
            provider
                .resolve_reply_target_binding(&caller(USER), &room_b_binding)
                .await
                .expect("room B binding lookup after removal")
                .is_none()
        );
        assert!(
            resolver
                .resolve_requested_target(&delivery_resolution_request(room_b_binding))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn matrix_room_binding_removal_is_scoped_to_subject_in_shared_room() {
        let source = MutableMatrixOutboundTargetProviders::new([provider_config(
            INSTALLATION,
            vec![
                room_route(ROOM, USER, MATRIX_USER),
                room_route(ROOM, OTHER_USER, OTHER_MATRIX_USER),
                room_route(ROOM_B, USER, MATRIX_USER),
            ],
        )])
        .expect("shared Matrix target source");
        let store: Arc<dyn super::MatrixRoomBindingStore> = Arc::new(source.clone());
        let provider = MatrixHostOutboundTargetProvider::from_shared_source(Arc::clone(&store))
            .expect("provider");
        let resolver =
            MatrixHostProductOutboundTargetResolver::from_shared_source(Arc::clone(&store))
                .expect("resolver");

        let alice_initial = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("alice initial target list");
        let bob_initial = provider
            .list_outbound_delivery_targets(&caller(OTHER_USER))
            .await
            .expect("bob initial target list");
        assert_eq!(alice_initial.len(), 2);
        assert_eq!(bob_initial.len(), 1);
        let mut alice_room_binding = None;
        for target in &alice_initial {
            let Some(resolved) = resolver
                .resolve_requested_target(&delivery_resolution_request(
                    target.reply_target_binding_ref.clone(),
                ))
                .await
            else {
                continue;
            };
            if resolved.room_id.as_str() == ROOM {
                alice_room_binding = Some(target.reply_target_binding_ref.clone());
                break;
            }
        }
        let alice_room_binding =
            alice_room_binding.expect("alice shared-room binding initially resolves");
        let bob_room_binding = bob_initial[0].reply_target_binding_ref.clone();

        assert_eq!(
            store
                .resolve_room_binding(
                    &TenantId::new(TENANT).expect("tenant"),
                    &AgentId::new(AGENT).expect("agent"),
                    Some(&ProjectId::new(PROJECT).expect("project")),
                    &AdapterInstallationId::new(INSTALLATION).expect("installation"),
                    &crate::matrix_outbound::MatrixRoomId::new(ROOM.to_string()).expect("room"),
                    &UserId::new(OTHER_USER).expect("other user"),
                )
                .await
                .expect("store resolves bob room binding")
                .expect("bob room binding")
                .subject_user_id
                .as_str(),
            OTHER_USER
        );

        let outcome = source
            .remove_room_binding(MatrixRoomBindingRemovalRequest {
                tenant_id: TenantId::new(TENANT).expect("tenant"),
                agent_id: AgentId::new(AGENT).expect("agent"),
                project_id: Some(ProjectId::new(PROJECT).expect("project")),
                installation_id: AdapterInstallationId::new(INSTALLATION).expect("installation"),
                room_id: crate::matrix_outbound::MatrixRoomId::new(ROOM.to_string()).expect("room"),
                subject_user_id: UserId::new(USER).expect("user"),
            })
            .await
            .expect("alice shared-room removal");
        assert_eq!(outcome, MatrixRoomBindingRemovalOutcome::Removed);

        let alice_after_removal = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("alice target list after removal");
        let bob_after_removal = provider
            .list_outbound_delivery_targets(&caller(OTHER_USER))
            .await
            .expect("bob target list after removal");
        assert_eq!(alice_after_removal.len(), 1);
        assert_eq!(bob_after_removal.len(), 1);
        assert!(
            provider
                .resolve_reply_target_binding(&caller(USER), &alice_room_binding)
                .await
                .expect("alice shared-room binding lookup after removal")
                .is_none()
        );
        assert!(
            resolver
                .resolve_requested_target(&delivery_resolution_request(alice_room_binding))
                .await
                .is_none()
        );
        assert!(
            provider
                .resolve_reply_target_binding(&caller(OTHER_USER), &bob_room_binding)
                .await
                .expect("bob shared-room binding lookup after alice removal")
                .is_some()
        );
    }

    #[tokio::test]
    async fn filesystem_matrix_room_binding_store_tombstone_survives_reload_and_seed() {
        let filesystem: Arc<dyn RootFilesystem> = Arc::new(InMemoryBackend::default());
        let tenant_id = TenantId::new(TENANT).expect("tenant");
        let config = provider_config(
            INSTALLATION,
            vec![
                room_route(ROOM, USER, MATRIX_USER),
                room_route(ROOM, OTHER_USER, OTHER_MATRIX_USER),
                room_route(ROOM_B, USER, MATRIX_USER),
            ],
        );
        let store =
            FilesystemMatrixRoomBindingStore::new(Arc::clone(&filesystem), [tenant_id.clone()]);
        store
            .seed_from_configs(std::slice::from_ref(&config))
            .await
            .expect("seed filesystem Matrix room binding store");

        let reloaded =
            FilesystemMatrixRoomBindingStore::new(Arc::clone(&filesystem), [tenant_id.clone()]);
        let store_ref: Arc<dyn super::MatrixRoomBindingStore> = Arc::new(reloaded.clone());
        let provider = MatrixHostOutboundTargetProvider::from_shared_source(Arc::clone(&store_ref))
            .expect("provider");
        let resolver =
            MatrixHostProductOutboundTargetResolver::from_shared_source(Arc::clone(&store_ref))
                .expect("resolver");

        let alice_initial = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("alice persisted target list");
        let bob_initial = provider
            .list_outbound_delivery_targets(&caller(OTHER_USER))
            .await
            .expect("bob persisted target list");
        assert_eq!(alice_initial.len(), 2);
        assert_eq!(bob_initial.len(), 1);

        let mut alice_shared_room_binding = None;
        for target in &alice_initial {
            let Some(resolved) = resolver
                .resolve_requested_target(&delivery_resolution_request(
                    target.reply_target_binding_ref.clone(),
                ))
                .await
            else {
                continue;
            };
            if resolved.room_id.as_str() == ROOM {
                alice_shared_room_binding = Some(target.reply_target_binding_ref.clone());
                break;
            }
        }
        let alice_shared_room_binding =
            alice_shared_room_binding.expect("alice shared-room binding resolves before delete");
        let bob_shared_room_binding = bob_initial[0].reply_target_binding_ref.clone();

        assert_eq!(
            reloaded
                .remove_room_binding(MatrixRoomBindingRemovalRequest {
                    tenant_id: tenant_id.clone(),
                    agent_id: AgentId::new(AGENT).expect("agent"),
                    project_id: Some(ProjectId::new(PROJECT).expect("project")),
                    installation_id: AdapterInstallationId::new(INSTALLATION)
                        .expect("installation"),
                    room_id: crate::matrix_outbound::MatrixRoomId::new(ROOM.to_string())
                        .expect("room"),
                    subject_user_id: UserId::new(USER).expect("user"),
                })
                .await
                .expect("remove alice shared-room binding"),
            MatrixRoomBindingRemovalOutcome::Removed
        );

        let post_delete_reload =
            FilesystemMatrixRoomBindingStore::new(Arc::clone(&filesystem), [tenant_id.clone()]);
        assert!(
            post_delete_reload
                .provider_has_removed_room_binding(&config)
                .await
                .expect("provider tombstone lookup"),
            "provider tombstone must remain durable for stale refresh guards"
        );
        assert!(
            post_delete_reload
                .resolve_room_binding(
                    &TenantId::new(TENANT).expect("tenant"),
                    &AgentId::new(AGENT).expect("agent"),
                    Some(&ProjectId::new(PROJECT).expect("project")),
                    &AdapterInstallationId::new(INSTALLATION).expect("installation"),
                    &crate::matrix_outbound::MatrixRoomId::new(ROOM.to_string()).expect("room"),
                    &UserId::new(USER).expect("user"),
                )
                .await
                .expect("alice binding lookup after delete")
                .is_none()
        );
        assert!(
            post_delete_reload
                .resolve_room_binding(
                    &TenantId::new(TENANT).expect("tenant"),
                    &AgentId::new(AGENT).expect("agent"),
                    Some(&ProjectId::new(PROJECT).expect("project")),
                    &AdapterInstallationId::new(INSTALLATION).expect("installation"),
                    &crate::matrix_outbound::MatrixRoomId::new(ROOM.to_string()).expect("room"),
                    &UserId::new(OTHER_USER).expect("other user"),
                )
                .await
                .expect("bob binding lookup after alice delete")
                .is_some()
        );
        let post_delete_scope = post_delete_reload
            .scope_for_tenant(&tenant_id)
            .expect("post-delete scope");
        let seed_marker_path =
            FilesystemMatrixRoomBindingStore::seed_marker_path().expect("seed marker path");
        post_delete_reload
            .filesystem
            .delete(&post_delete_scope, &seed_marker_path)
            .await
            .expect("remove seed marker to force reseed path");
        post_delete_reload
            .seed_from_configs(std::slice::from_ref(&config))
            .await
            .expect("reseed must not overwrite tombstoned Matrix room binding");
        assert!(
            post_delete_reload
                .resolve_room_binding(
                    &TenantId::new(TENANT).expect("tenant"),
                    &AgentId::new(AGENT).expect("agent"),
                    Some(&ProjectId::new(PROJECT).expect("project")),
                    &AdapterInstallationId::new(INSTALLATION).expect("installation"),
                    &crate::matrix_outbound::MatrixRoomId::new(ROOM.to_string()).expect("room"),
                    &UserId::new(USER).expect("user"),
                )
                .await
                .expect("alice binding lookup after reseed")
                .is_none(),
            "config seed must not resurrect a removed binding"
        );

        let alice_after_delete = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("alice target list after durable delete");
        assert_eq!(alice_after_delete.len(), 1);
        assert!(
            provider
                .resolve_reply_target_binding(&caller(USER), &alice_shared_room_binding)
                .await
                .expect("provider resolve after durable delete")
                .is_none()
        );
        assert!(
            resolver
                .resolve_requested_target(&delivery_resolution_request(alice_shared_room_binding))
                .await
                .is_none()
        );
        assert!(
            provider
                .resolve_reply_target_binding(&caller(OTHER_USER), &bob_shared_room_binding)
                .await
                .expect("bob provider resolve after alice durable delete")
                .is_some()
        );
    }

    #[tokio::test]
    async fn matrix_room_target_refuses_foreign_tenant_user_and_installation_targets() {
        let provider = build_provider(INSTALLATION);
        let owner_target = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("owner target list")
            .into_iter()
            .next()
            .expect("owner Matrix room target")
            .summary
            .target_id;

        assert!(
            provider
                .resolve_outbound_delivery_target(&foreign_tenant_caller(), &owner_target)
                .await
                .expect("foreign tenant lookup")
                .is_none()
        );
        assert!(
            provider
                .resolve_outbound_delivery_target(&caller(OTHER_USER), &owner_target)
                .await
                .expect("foreign user lookup")
                .is_none()
        );

        let foreign_installation = build_provider(OTHER_INSTALLATION)
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("foreign installation list")
            .into_iter()
            .next()
            .expect("foreign installation target");

        assert!(
            provider
                .resolve_reply_target_binding(
                    &caller(USER),
                    &foreign_installation.reply_target_binding_ref,
                )
                .await
                .expect("foreign installation binding lookup")
                .is_none()
        );
    }

    #[tokio::test]
    async fn matrix_room_target_rejects_tampered_opaque_refs_for_other_room_key() {
        let provider = build_provider(INSTALLATION);

        let owner_target = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("owner target list")
            .into_iter()
            .next()
            .expect("owner Matrix room target");
        let other_user_target = provider
            .list_outbound_delivery_targets(&caller(OTHER_USER))
            .await
            .expect("other user target list")
            .into_iter()
            .next()
            .expect("other Matrix room target");

        let tampered_target_id =
            RebornOutboundDeliveryTargetId::new(other_user_target.summary.target_id.as_str())
                .expect("tampered target id");
        let tampered_reply_binding_ref = ReplyTargetBindingRef::new(
            other_user_target
                .reply_target_binding_ref
                .as_str()
                .to_owned(),
        )
        .expect("tampered reply binding ref");

        assert_ne!(owner_target.summary.target_id, tampered_target_id);
        assert_ne!(
            owner_target.reply_target_binding_ref,
            tampered_reply_binding_ref
        );
        assert!(
            provider
                .resolve_outbound_delivery_target(&caller(USER), &tampered_target_id)
                .await
                .expect("tampered target lookup")
                .is_none()
        );
        assert!(
            provider
                .resolve_reply_target_binding(&caller(USER), &tampered_reply_binding_ref)
                .await
                .expect("tampered binding lookup")
                .is_none()
        );
    }

    #[test]
    fn matrix_room_target_rejects_invalid_configured_room_ids_before_provider_use() {
        for invalid_room_id in [
            "#alias:example.org",
            "!room",
            "!room:",
            " !room:example.org",
            "!room:example.org ",
            "!room:\nexample.org",
        ] {
            let result = MatrixHostOutboundTargetProvider::new(provider_config(
                INSTALLATION,
                vec![room_route(invalid_room_id, USER, MATRIX_USER)],
            ));

            assert!(
                result.is_err(),
                "invalid configured Matrix room id must be rejected before provider use: {invalid_room_id:?}"
            );
        }
    }
}
