use async_trait::async_trait;
use ironclaw_host_api::{AgentId, ProjectId, TenantId, UserId};
use ironclaw_product_adapters::AdapterInstallationId;
use ironclaw_product_workflow::{
    RebornOutboundDeliveryTargetCapabilities, RebornOutboundDeliveryTargetId,
    RebornOutboundDeliveryTargetSummary, RebornServicesError, RebornServicesErrorCode,
    RebornServicesErrorKind, WebUiAuthenticatedCaller,
};
use ironclaw_turns::ReplyTargetBindingRef;

use crate::outbound::OutboundDeliveryTargetProvider;
use crate::outbound::outbound_preferences::OutboundDeliveryTargetEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixConfiguredRoomRoute {
    pub room_id: String,
    pub subject_user_id: UserId,
}

impl MatrixConfiguredRoomRoute {
    pub fn new(room_id: String, subject_user_id: UserId) -> Self {
        Self {
            room_id,
            subject_user_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatrixOutboundTargetProviderConfig {
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub project_id: Option<ProjectId>,
    pub installation_id: AdapterInstallationId,
    pub configured_room_routes: Vec<MatrixConfiguredRoomRoute>,
}

#[derive(Debug, Clone)]
pub struct MatrixHostOutboundTargetProvider {
    tenant_id: TenantId,
    agent_id: AgentId,
    project_id: Option<ProjectId>,
    configured_room_routes: Vec<MatrixConfiguredRoomRoute>,
    room_target_id_prefix: String,
    room_binding_ref_prefix: String,
}

impl MatrixHostOutboundTargetProvider {
    pub fn new(config: MatrixOutboundTargetProviderConfig) -> Self {
        let room_target_id_prefix = format!("matrix:room:{}:", config.installation_id.as_str());
        let room_binding_ref_prefix =
            format!("reply:matrix:room:{}:", config.installation_id.as_str());
        Self {
            tenant_id: config.tenant_id,
            agent_id: config.agent_id,
            project_id: config.project_id,
            configured_room_routes: config.configured_room_routes,
            room_target_id_prefix,
            room_binding_ref_prefix,
        }
    }

    fn caller_matches_provider_context(&self, caller: &WebUiAuthenticatedCaller) -> bool {
        caller.tenant_id == self.tenant_id
            && caller.agent_id.as_ref() == Some(&self.agent_id)
            && caller.project_id == self.project_id
    }

    fn room_id_for_target_id<'a>(
        &self,
        target_id: &'a RebornOutboundDeliveryTargetId,
    ) -> Option<&'a str> {
        target_id.as_str().strip_prefix(&self.room_target_id_prefix)
    }

    fn room_id_for_reply_target_binding_ref<'a>(
        &self,
        target: &'a ReplyTargetBindingRef,
    ) -> Option<&'a str> {
        target.as_str().strip_prefix(&self.room_binding_ref_prefix)
    }

    fn configured_route_for_room(&self, room_id: &str) -> Option<&MatrixConfiguredRoomRoute> {
        self.configured_room_routes
            .iter()
            .find(|route| route.room_id == room_id)
    }

    fn entry_for_room_route(
        &self,
        route: &MatrixConfiguredRoomRoute,
    ) -> Result<OutboundDeliveryTargetEntry, RebornServicesError> {
        let target_id = RebornOutboundDeliveryTargetId::new(format!(
            "{}{}",
            self.room_target_id_prefix, route.room_id
        ))
        .map_err(|_| matrix_target_backend_error())?;
        Ok(OutboundDeliveryTargetEntry {
            summary: RebornOutboundDeliveryTargetSummary::new(
                target_id,
                "matrix",
                "Matrix room",
                Some(format!("Matrix room {}", route.room_id)),
            )
            .map_err(|_| matrix_target_backend_error())?,
            capabilities: RebornOutboundDeliveryTargetCapabilities {
                final_replies: true,
                gate_prompts: false,
                auth_prompts: false,
            },
            reply_target_binding_ref: ReplyTargetBindingRef::new(format!(
                "{}{}",
                self.room_binding_ref_prefix, route.room_id
            ))
            .map_err(|_| matrix_target_backend_error())?,
        })
    }

    fn resolve_for_room_id(
        &self,
        caller: &WebUiAuthenticatedCaller,
        room_id: &str,
    ) -> Result<Option<OutboundDeliveryTargetEntry>, RebornServicesError> {
        if !self.caller_matches_provider_context(caller) {
            return Ok(None);
        }
        let Some(route) = self.configured_route_for_room(room_id) else {
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
        let Some(room_id) = self.room_id_for_target_id(target_id) else {
            return Ok(None);
        };
        self.resolve_for_room_id(caller, room_id)
    }

    async fn resolve_reply_target_binding(
        &self,
        caller: &WebUiAuthenticatedCaller,
        target: &ReplyTargetBindingRef,
    ) -> Result<Option<OutboundDeliveryTargetEntry>, RebornServicesError> {
        let Some(room_id) = self.room_id_for_reply_target_binding_ref(target) else {
            return Ok(None);
        };
        self.resolve_for_room_id(caller, room_id)
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

    use crate::matrix_outbound_targets::{
        MatrixConfiguredRoomRoute, MatrixHostOutboundTargetProvider,
        MatrixOutboundTargetProviderConfig,
    };
    use crate::outbound::OutboundDeliveryTargetProvider;

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

    fn build_provider(installation_id: &str) -> MatrixHostOutboundTargetProvider {
        MatrixHostOutboundTargetProvider::new(MatrixOutboundTargetProviderConfig {
            tenant_id: TenantId::new(TENANT).expect("tenant"),
            agent_id: AgentId::new(AGENT).expect("agent"),
            project_id: Some(ProjectId::new(PROJECT).expect("project")),
            installation_id: AdapterInstallationId::new(installation_id).expect("installation"),
            configured_room_routes: vec![
                MatrixConfiguredRoomRoute::new(ROOM.to_string(), UserId::new(USER).expect("user")),
                MatrixConfiguredRoomRoute::new(
                    OTHER_ROOM.to_string(),
                    UserId::new(OTHER_USER).expect("other user"),
                ),
            ],
        })
    }

    #[tokio::test]
    async fn matrix_room_target_lists_and_resolves_only_authenticated_owner_rooms() {
        let provider = build_provider(INSTALLATION);

        let listed = provider
            .list_outbound_delivery_targets(&caller(USER))
            .await
            .expect("target list");

        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].summary.target_id.as_str(),
            "matrix:room:inst_matrix:!room:example.org"
        );
        assert_eq!(listed[0].summary.channel.as_str(), "matrix");
        assert_eq!(listed[0].summary.display_name.as_str(), "Matrix room");
        assert!(listed[0].capabilities.final_replies);

        let resolved = provider
            .resolve_outbound_delivery_target(
                &caller(USER),
                &RebornOutboundDeliveryTargetId::new("matrix:room:inst_matrix:!room:example.org")
                    .expect("target id"),
            )
            .await
            .expect("target resolve")
            .expect("owned Matrix room target");

        assert_eq!(
            resolved.reply_target_binding_ref,
            listed[0].reply_target_binding_ref
        );
        assert_eq!(
            provider
                .resolve_reply_target_binding(&caller(USER), &resolved.reply_target_binding_ref)
                .await
                .expect("binding resolve")
                .expect("owned Matrix room binding")
                .summary
                .target_id
                .as_str(),
            "matrix:room:inst_matrix:!room:example.org"
        );
    }

    #[tokio::test]
    async fn matrix_room_target_refuses_foreign_tenant_user_and_installation_targets() {
        let provider = build_provider(INSTALLATION);
        let owner_target =
            RebornOutboundDeliveryTargetId::new("matrix:room:inst_matrix:!room:example.org")
                .expect("target id");

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
}
