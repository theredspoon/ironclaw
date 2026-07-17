use async_trait::async_trait;
use ironclaw_common::hashing::sha256_hex;
use ironclaw_host_api::{AgentId, ProjectId, TenantId, UserId};
use ironclaw_product_adapters::AdapterInstallationId;
use ironclaw_product_workflow::{
    RebornOutboundDeliveryTargetCapabilities, RebornOutboundDeliveryTargetId,
    RebornOutboundDeliveryTargetSummary, RebornServicesError, RebornServicesErrorCode,
    RebornServicesErrorKind, WebUiAuthenticatedCaller,
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
    configured_room_routes: Vec<ValidatedMatrixConfiguredRoomRoute>,
    room_target_id_prefix: String,
    room_binding_ref_prefix: String,
}

#[derive(Debug, Clone)]
struct ValidatedMatrixConfiguredRoomRoute {
    room_id: MatrixRoomId,
    subject_user_id: UserId,
    route_key: String,
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
    let provider_key = matrix_outbound_target_provider_key(&config.installation_id);
    let provider = MatrixHostOutboundTargetProvider::new(config)?;
    registry.register_provider(provider_key, std::sync::Arc::new(provider))
}

fn matrix_outbound_target_provider_key(installation_id: &AdapterInstallationId) -> String {
    format!(
        "matrix:outbound-target-provider:{}",
        installation_id.as_str()
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

#[cfg(test)]
mod tests {
    use ironclaw_host_api::{AgentId, ProjectId, TenantId, UserId};
    use ironclaw_product_adapters::AdapterInstallationId;
    use ironclaw_product_workflow::{RebornOutboundDeliveryTargetId, WebUiAuthenticatedCaller};
    use ironclaw_turns::ReplyTargetBindingRef;

    use crate::matrix_outbound_targets::{
        MatrixConfiguredRoomRoute, MatrixHostOutboundTargetProvider,
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
