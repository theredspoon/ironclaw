use async_trait::async_trait;
use ironclaw_common::hashing::sha256_hex;
use ironclaw_host_api::{AgentId, ProjectId, TenantId, UserId};
use ironclaw_outbound::{
    CommunicationDeliveryIntent, OutboundError, ReplyTargetBindingClaim,
    ReplyTargetBindingValidator, ReplyTargetValidationRequest, RunNotificationOrigin,
    ThreadProjectionAccessClaim, ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
};
use ironclaw_product_adapters::AdapterInstallationId;
use ironclaw_product_adapters::ExternalConversationRef;
use ironclaw_product_workflow::{
    ProductOutboundTargetResolver, RebornOutboundDeliveryTargetCapabilities,
    RebornOutboundDeliveryTargetId, RebornOutboundDeliveryTargetSummary, RebornServicesError,
    RebornServicesErrorCode, RebornServicesErrorKind, VerifiedProductOutboundTargetMetadata,
    WebUiAuthenticatedCaller,
};
use ironclaw_turns::ReplyTargetBindingRef;

use crate::matrix_outbound::MatrixRoomId;
use crate::outbound::outbound_preferences::OutboundDeliveryTargetEntry;
use crate::outbound::{
    MutableOutboundDeliveryTargetRegistry, OutboundDeliveryTargetProvider,
    OutboundDeliveryTargetRegistrationOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatrixConfiguredRoomRoute {
    pub(crate) room_id: String,
    pub(crate) subject_user_id: UserId,
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

#[derive(Debug, Clone)]
pub(crate) struct MatrixHostOutboundTargetProvider {
    tenant_id: TenantId,
    agent_id: AgentId,
    project_id: Option<ProjectId>,
    installation_id: AdapterInstallationId,
    configured_room_routes: Vec<ValidatedMatrixConfiguredRoomRoute>,
    room_target_id_prefix: String,
    room_binding_ref_prefix: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MatrixHostProductOutboundTargetResolver {
    providers: Vec<MatrixHostOutboundTargetProvider>,
}

#[derive(Debug, Clone)]
pub(crate) struct MatrixHostReplyTargetPolicy {
    resolver: MatrixHostProductOutboundTargetResolver,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedMatrixOutboundTarget {
    pub(crate) installation_id: AdapterInstallationId,
    pub(crate) room_id: MatrixRoomId,
    pub(crate) reply_target_binding_ref: ReplyTargetBindingRef,
}

#[derive(Debug, Clone)]
struct ValidatedMatrixConfiguredRoomRoute {
    room_id: MatrixRoomId,
    subject_user_id: UserId,
    route_key: String,
}

impl MatrixHostProductOutboundTargetResolver {
    pub(crate) fn new(
        configs: impl IntoIterator<Item = MatrixOutboundTargetProviderConfig>,
    ) -> Result<Self, RebornServicesError> {
        let providers = configs
            .into_iter()
            .map(MatrixHostOutboundTargetProvider::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { providers })
    }

    pub(crate) fn resolve_requested_target(
        &self,
        request: &ironclaw_outbound::CommunicationDeliveryResolutionRequest,
    ) -> Option<ResolvedMatrixOutboundTarget> {
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
        self.providers.iter().find_map(|provider| {
            if provider.tenant_id != request.scope.tenant_id
                || Some(&provider.agent_id) != request.scope.agent_id.as_ref()
                || provider.project_id != request.scope.project_id
            {
                return None;
            }
            let route_key = provider.route_key_for_reply_target_binding_ref(requested_target)?;
            let route = provider.configured_route_for_key(route_key)?;
            if route.subject_user_id == request.actor.user_id {
                Some(ResolvedMatrixOutboundTarget {
                    installation_id: provider.installation_id.clone(),
                    room_id: route.room_id.clone(),
                    reply_target_binding_ref: requested_target.clone(),
                })
            } else {
                None
            }
        })
    }

    fn resolve_target(
        &self,
        target: &ReplyTargetBindingRef,
    ) -> Option<(
        &MatrixHostOutboundTargetProvider,
        &ValidatedMatrixConfiguredRoomRoute,
    )> {
        self.providers.iter().find_map(|provider| {
            let route_key = provider.route_key_for_reply_target_binding_ref(target)?;
            provider
                .configured_route_for_key(route_key)
                .map(|route| (provider, route))
        })
    }

    fn resolve_candidate(
        &self,
        request: &ReplyTargetValidationRequest,
    ) -> Option<&ValidatedMatrixConfiguredRoomRoute> {
        self.providers.iter().find_map(|provider| {
            if provider.tenant_id != request.candidate.tenant_id
                || Some(&provider.agent_id) != request.candidate.agent_id.as_ref()
                || provider.project_id != request.candidate.project_id
            {
                return None;
            }
            let route_key =
                provider.route_key_for_reply_target_binding_ref(&request.candidate.target)?;
            let route = provider.configured_route_for_key(route_key)?;
            if route.subject_user_id == request.actor.user_id {
                Some(route)
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
        if self.resolver.resolve_candidate(&request).is_some() {
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
        let (_provider, route) = self.resolve_target(target.target()).ok_or_else(|| {
            ironclaw_product_workflow::ProductWorkflowError::BindingRequired {
                reason: "Matrix outbound target binding is not configured".to_string(),
            }
        })?;
        Ok(VerifiedProductOutboundTargetMetadata {
            external_conversation_ref: ExternalConversationRef::new(
                None,
                route.room_id.as_str(),
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
        let room_target_id_prefix = format!("matrix:room:{}:", config.installation_id.as_str());
        let room_binding_ref_prefix =
            format!("reply:matrix:room:{}:", config.installation_id.as_str());
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
        Ok(Self {
            tenant_id: config.tenant_id,
            agent_id: config.agent_id,
            project_id: config.project_id,
            installation_id: config.installation_id,
            configured_room_routes,
            room_target_id_prefix,
            room_binding_ref_prefix,
        })
    }

    fn caller_matches_provider_context(&self, caller: &WebUiAuthenticatedCaller) -> bool {
        caller.tenant_id == self.tenant_id
            && caller.agent_id.as_ref() == Some(&self.agent_id)
            && caller.project_id == self.project_id
    }

    fn route_key_for_target_id<'a>(
        &self,
        target_id: &'a RebornOutboundDeliveryTargetId,
    ) -> Option<&'a str> {
        target_id.as_str().strip_prefix(&self.room_target_id_prefix)
    }

    fn route_key_for_reply_target_binding_ref<'a>(
        &self,
        target: &'a ReplyTargetBindingRef,
    ) -> Option<&'a str> {
        target.as_str().strip_prefix(&self.room_binding_ref_prefix)
    }

    fn configured_route_for_key(
        &self,
        route_key: &str,
    ) -> Option<&ValidatedMatrixConfiguredRoomRoute> {
        self.configured_room_routes
            .iter()
            .find(|route| route.route_key == route_key)
    }

    fn entry_for_room_route(
        &self,
        route: &ValidatedMatrixConfiguredRoomRoute,
    ) -> Result<OutboundDeliveryTargetEntry, RebornServicesError> {
        debug_assert!(route.room_id.as_str().starts_with('!'));
        let target_id = RebornOutboundDeliveryTargetId::new(format!(
            "{}{}",
            self.room_target_id_prefix, route.route_key
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
                self.room_binding_ref_prefix, route.route_key
            ))
            .map_err(|_| matrix_target_backend_error())?,
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
        if !self.caller_matches_provider_context(caller) {
            return Ok(Vec::new());
        }
        self.configured_room_routes
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
        let Some(route_key) = self.route_key_for_reply_target_binding_ref(target) else {
            return Ok(None);
        };
        self.resolve_for_route_key(caller, route_key)
    }
}

pub(crate) fn register_matrix_outbound_target_provider(
    registry: &MutableOutboundDeliveryTargetRegistry,
    config: MatrixOutboundTargetProviderConfig,
) -> Result<OutboundDeliveryTargetRegistrationOutcome, RebornServicesError> {
    let provider_key = matrix_outbound_target_provider_key(&config);
    let provider = MatrixHostOutboundTargetProvider::new(config)?;
    registry.register_provider(provider_key, std::sync::Arc::new(provider))
}

fn matrix_outbound_target_provider_key(config: &MatrixOutboundTargetProviderConfig) -> String {
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
    format!("matrix:outbound-target-provider:{}", sha256_hex(&input))
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

#[cfg(test)]
mod tests {
    use ironclaw_event_projections::ProjectionScope;
    use ironclaw_host_api::{AgentId, ProjectId, TenantId, ThreadId, UserId};
    use ironclaw_outbound::{
        CommunicationDeliveryIntent, CommunicationDeliveryResolutionRequest, CommunicationModality,
        RequestedOutboundContext, RequestedOutboundKind, RunNotificationContext,
        RunNotificationEventKind, RunNotificationOrigin, SourceRouteContext,
        ThreadProjectionAccessPolicy, ThreadProjectionAccessRequest,
    };
    use ironclaw_product_adapters::AdapterInstallationId;
    use ironclaw_product_workflow::{RebornOutboundDeliveryTargetId, WebUiAuthenticatedCaller};
    use ironclaw_turns::{ReplyTargetBindingRef, TurnActor, TurnScope};

    use crate::matrix_outbound_targets::{
        MatrixConfiguredRoomRoute, MatrixHostOutboundTargetProvider,
        MatrixHostProductOutboundTargetResolver, MatrixHostReplyTargetPolicy,
        MatrixOutboundTargetProviderConfig,
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

    fn build_provider(installation_id: &str) -> MatrixHostOutboundTargetProvider {
        MatrixHostOutboundTargetProvider::new(provider_config(
            installation_id,
            vec![
                MatrixConfiguredRoomRoute {
                    room_id: ROOM.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                },
                MatrixConfiguredRoomRoute {
                    room_id: OTHER_ROOM.to_string(),
                    subject_user_id: UserId::new(OTHER_USER).expect("other user"),
                },
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
            provider_config(
                INSTALLATION,
                vec![MatrixConfiguredRoomRoute {
                    room_id: ROOM.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                }],
            ),
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
            provider_config(
                INSTALLATION,
                vec![MatrixConfiguredRoomRoute {
                    room_id: ROOM.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                }],
            ),
            provider_config(
                OTHER_INSTALLATION,
                vec![MatrixConfiguredRoomRoute {
                    room_id: ROOM.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                }],
            ),
        ])
        .expect("multi-installation resolver");

        let resolved = resolver
            .resolve_requested_target(&delivery_resolution_request(
                second_target.reply_target_binding_ref,
            ))
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
            provider_config(
                INSTALLATION,
                vec![MatrixConfiguredRoomRoute {
                    room_id: ROOM.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                }],
            ),
            provider_config(
                OTHER_INSTALLATION,
                vec![MatrixConfiguredRoomRoute {
                    room_id: ROOM.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                }],
            ),
        ])
        .expect("multi-installation resolver");

        let resolved = resolver
            .resolve_requested_target(&live_source_route_resolution_request(
                second_target.reply_target_binding_ref,
            ))
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
            vec![MatrixConfiguredRoomRoute {
                room_id: ROOM.to_string(),
                subject_user_id: UserId::new(USER).expect("user"),
            }],
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
        let first = provider_config(
            installation_id,
            vec![MatrixConfiguredRoomRoute {
                room_id: ROOM.to_string(),
                subject_user_id: UserId::new(USER).expect("user"),
            }],
        );
        let second = MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new(OTHER_TENANT).expect("other tenant"),
            agent_id: AgentId::new(AGENT).expect("agent"),
            project_id: Some(ProjectId::new(PROJECT).expect("project")),
            installation_id: AdapterInstallationId::new(installation_id).expect("installation"),
            configured_room_routes: vec![MatrixConfiguredRoomRoute {
                room_id: OTHER_ROOM.to_string(),
                subject_user_id: UserId::new(USER).expect("user"),
            }],
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
                vec![MatrixConfiguredRoomRoute {
                    room_id: invalid_room_id.to_string(),
                    subject_user_id: UserId::new(USER).expect("user"),
                }],
            ));

            assert!(
                result.is_err(),
                "invalid configured Matrix room id must be rejected before provider use: {invalid_room_id:?}"
            );
        }
    }
}
