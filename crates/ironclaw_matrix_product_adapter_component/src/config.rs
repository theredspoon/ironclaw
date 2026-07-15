use crate::near::product_adapter::product_adapter_host;

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct InstallationConfig {
    pub(crate) adapter_id: String,
    pub(crate) installation_id: String,
    pub(crate) capabilities_json: String,
    pub(crate) auth: AuthConfig,
    pub(crate) egress_targets: Vec<EgressTargetConfig>,
    pub(crate) matrix: MatrixConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum AuthConfig {
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

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct EgressTargetConfig {
    pub(crate) host: String,
    pub(crate) credential_handle: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct MatrixConfig {
    pub(crate) allowed_rooms: Vec<String>,
    pub(crate) allowed_senders: Vec<String>,
}

pub(crate) fn installation_config() -> Result<InstallationConfig, String> {
    let json = product_adapter_host::installation_config_json();
    let config: InstallationConfig =
        serde_json::from_str(&json).map_err(|_| "invalid_installation_config".to_string())?;
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &InstallationConfig) -> Result<(), String> {
    require_non_empty("adapter_id", &config.adapter_id)?;
    require_non_empty("installation_id", &config.installation_id)?;
    require_non_empty("capabilities_json", &config.capabilities_json)?;
    if config.egress_targets.is_empty() {
        return Err("missing_egress_targets".to_string());
    }
    for target in &config.egress_targets {
        require_non_empty("egress_host", &target.host)?;
        if let Some(handle) = &target.credential_handle {
            require_non_empty("credential_handle", handle)?;
        }
    }
    if config.matrix.allowed_rooms.is_empty() {
        return Err("missing_allowed_rooms".to_string());
    }
    if config.matrix.allowed_senders.is_empty() {
        return Err("missing_allowed_senders".to_string());
    }
    if config
        .matrix
        .allowed_rooms
        .iter()
        .any(|room| room.trim().is_empty())
    {
        return Err("invalid_allowed_room".to_string());
    }
    if config
        .matrix
        .allowed_senders
        .iter()
        .any(|sender| sender.trim().is_empty())
    {
        return Err("invalid_allowed_sender".to_string());
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("missing_{field}"));
    }
    Ok(())
}
