use super::*;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MatrixOutboundContractError {
    #[error("invalid matrix transaction id")]
    InvalidTransactionId,
    #[error("invalid matrix room id")]
    InvalidRoomId,
    #[error("invalid matrix message body")]
    InvalidMessageBody,
    #[error("unsafe matrix evidence")]
    UnsafeEvidence,
    #[error("unverified matrix evidence")]
    UnverifiedEvidence,
    #[error("matrix metadata serialization failed: {0}")]
    Serialization(String),
    #[error("matrix metadata backend failed: {0}")]
    Backend(String),
}

impl From<serde_json::Error> for MatrixOutboundContractError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<FilesystemError> for MatrixOutboundContractError {
    fn from(value: FilesystemError) -> Self {
        Self::Backend(value.to_string())
    }
}

impl From<OutboundError> for MatrixOutboundContractError {
    fn from(value: OutboundError) -> Self {
        Self::Backend(value.to_string())
    }
}

pub(crate) fn leaks_raw_matrix_value(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    value.starts_with('$')
        || value.starts_with('!')
        || value.starts_with('@')
        || value.contains("://")
        || normalized.contains("access_token")
        || value.contains("Bearer ")
        || normalized.starts_with("secret:")
        || normalized.contains(".secret.")
}

pub(crate) fn is_canonical_sha256_fingerprint(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn is_terminal_delivery_status(status: OutboundDeliveryStatus) -> bool {
    matches!(
        status,
        OutboundDeliveryStatus::Delivered
            | OutboundDeliveryStatus::Failed
            | OutboundDeliveryStatus::DeadLettered
    )
}
