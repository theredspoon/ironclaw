use crate::config::{self, AuthConfig};
use crate::exports::near::product_adapter::product_adapter::{
    AdapterManifest, AuthRequirement, AuthRequirementKind, DeclaredEgressTarget,
};

pub(crate) fn manifest() -> AdapterManifest {
    let config =
        config::installation_config().expect("host must provide valid installation config");
    AdapterManifest {
        adapter_id: config.adapter_id,
        installation_id: config.installation_id,
        capabilities_json: config.capabilities_json,
        declared_egress_targets: config
            .egress_targets
            .into_iter()
            .map(|target| DeclaredEgressTarget {
                host: target.host,
                credential_handle: target.credential_handle,
            })
            .collect(),
        declared_auth_requirements: vec![auth_requirement(config.auth)],
    }
}

fn auth_requirement(auth: AuthConfig) -> AuthRequirement {
    match auth {
        AuthConfig::RequestSignature {
            header_name,
            timestamp_header_name,
        } => AuthRequirement {
            kind: AuthRequirementKind::RequestSignature,
            header_name: Some(header_name),
            timestamp_header_name,
            cookie_name: None,
        },
        AuthConfig::SharedSecretHeader { header_name } => AuthRequirement {
            kind: AuthRequirementKind::SharedSecretHeader,
            header_name: Some(header_name),
            timestamp_header_name: None,
            cookie_name: None,
        },
        AuthConfig::SessionCookie { name } => AuthRequirement {
            kind: AuthRequirementKind::SessionCookie,
            header_name: None,
            timestamp_header_name: None,
            cookie_name: Some(name),
        },
        AuthConfig::BearerToken => AuthRequirement {
            kind: AuthRequirementKind::BearerToken,
            header_name: None,
            timestamp_header_name: None,
            cookie_name: None,
        },
    }
}
