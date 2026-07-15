use crate::exports::near::product_adapter::product_adapter::{
    AdapterManifest, AuthRequirement, AuthRequirementKind, DeclaredEgressTarget,
};

pub(crate) const ADAPTER_ID: &str = "matrix";
pub(crate) const INSTALLATION_ID: &str = "inst_abc123";
pub(crate) const MATRIX_EGRESS_HOST: &str = "matrix.example.org";
pub(crate) const MATRIX_CREDENTIAL_HANDLE: &str = "matrix_access_token";

pub(crate) fn manifest() -> AdapterManifest {
    AdapterManifest {
        adapter_id: ADAPTER_ID.to_string(),
        installation_id: INSTALLATION_ID.to_string(),
        capabilities_json: capabilities_json(),
        declared_egress_targets: vec![DeclaredEgressTarget {
            host: MATRIX_EGRESS_HOST.to_string(),
            credential_handle: Some(MATRIX_CREDENTIAL_HANDLE.to_string()),
        }],
        declared_auth_requirements: vec![AuthRequirement {
            kind: AuthRequirementKind::SharedSecretHeader,
            header_name: Some("x-matrix-webhook-secret".to_string()),
            timestamp_header_name: None,
            cookie_name: None,
        }],
    }
}

pub(crate) fn capabilities_json() -> String {
    serde_json::json!({
        "flags": [
            "inbound_messages",
            "inbound_commands",
            "inbound_attachments",
            "external_final_reply_push",
            "delivery_status_reporting"
        ]
    })
    .to_string()
}
