use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use ironclaw_wasm::wasm_sandbox_core::SandboxLimits as ProductAdapterComponentLimits;

pub const PRODUCT_ADAPTER_WIT_VERSION: &str = "0.1.0";

pub(crate) const DEFAULT_MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) const MAX_LOGS_PER_EXECUTION: usize = 1_000;
pub(crate) const MAX_LOG_MESSAGE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct ProductAdapterComponentRuntimeConfig {
    pub default_limits: ProductAdapterComponentLimits,
    pub max_component_bytes: usize,
    pub installation_config: ProductAdapterInstallationConfig,
}

impl Default for ProductAdapterComponentRuntimeConfig {
    fn default() -> Self {
        Self {
            default_limits: ProductAdapterComponentLimits::default(),
            max_component_bytes: DEFAULT_MAX_COMPONENT_BYTES,
            installation_config: ProductAdapterInstallationConfig::matrix_fixture(),
        }
    }
}

impl ProductAdapterComponentRuntimeConfig {
    pub fn for_testing() -> Self {
        Self {
            default_limits: ProductAdapterComponentLimits::default()
                .with_memory_bytes(1024 * 1024)
                .with_fuel(100_000)
                .with_timeout(Duration::from_secs(5)),
            max_component_bytes: 512 * 1024,
            installation_config: ProductAdapterInstallationConfig::matrix_fixture(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAdapterInstallationConfig {
    pub adapter_id: String,
    pub installation_id: String,
    pub capabilities_json: String,
    pub auth: ProductAdapterAuthConfig,
    pub egress_targets: Vec<ProductAdapterEgressTargetConfig>,
    pub matrix: MatrixProductAdapterInstallationConfig,
}

impl ProductAdapterInstallationConfig {
    pub fn matrix_fixture() -> Self {
        Self {
            adapter_id: "matrix".to_string(),
            installation_id: "inst_abc123".to_string(),
            capabilities_json: serde_json::json!({
                "flags": [
                    "inbound_messages",
                    "inbound_commands",
                    "inbound_attachments",
                    "external_final_reply_push",
                    "delivery_status_reporting"
                ]
            })
            .to_string(),
            auth: ProductAdapterAuthConfig::SharedSecretHeader {
                header_name: "x-matrix-webhook-secret".to_string(),
            },
            egress_targets: vec![ProductAdapterEgressTargetConfig {
                host: "matrix.example.org".to_string(),
                credential_handle: Some("matrix_access_token".to_string()),
            }],
            matrix: MatrixProductAdapterInstallationConfig {
                allowed_rooms: vec!["!room:example.org".to_string()],
                allowed_senders: vec!["@alice:example.org".to_string()],
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProductAdapterAuthConfig {
    RequestSignature {
        header_name: String,
        timestamp_header_name: Option<String>,
    },
    SharedSecretHeader {
        header_name: String,
    },
    SessionCookie {
        name: String,
    },
    BearerToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAdapterEgressTargetConfig {
    pub host: String,
    pub credential_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixProductAdapterInstallationConfig {
    pub allowed_rooms: Vec<String>,
    pub allowed_senders: Vec<String>,
}
