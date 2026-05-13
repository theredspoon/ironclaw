//! Host-port vocabulary contracts.
//!
//! Host ports name mediated host APIs that a capability implementation may use
//! after authorization and obligation preparation. This module only defines the
//! shared vocabulary and scoped view shape; concrete port implementations live in
//! host/runtime service crates.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::HostApiError;

fn valid_segment_char(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
}

fn validate_dotted_host_port_id(value: &str) -> Result<(), HostApiError> {
    if value.is_empty() {
        return Err(HostApiError::invalid_id(
            "host_port",
            value,
            "must not be empty",
        ));
    }
    if value.len() > 128 {
        return Err(HostApiError::invalid_id(
            "host_port",
            value,
            "must be at most 128 bytes",
        ));
    }
    if !value.starts_with("host.") {
        return Err(HostApiError::invalid_id(
            "host_port",
            value,
            "must start with 'host.'",
        ));
    }
    for segment in value.split('.') {
        if segment.is_empty() {
            return Err(HostApiError::invalid_id(
                "host_port",
                value,
                "empty dot segments are not allowed",
            ));
        }
        let first = segment.as_bytes()[0];
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(HostApiError::invalid_id(
                "host_port",
                value,
                "segments must start with lowercase ASCII letter or digit",
            ));
        }
        if segment.bytes().any(|byte| !valid_segment_char(byte)) {
            return Err(HostApiError::invalid_id(
                "host_port",
                value,
                "only lowercase ASCII letters, digits, '_', '-', and '.' are allowed",
            ));
        }
    }
    Ok(())
}

/// Stable identifier for a host-mediated API surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostPortId(String);

impl HostPortId {
    pub fn new(value: impl Into<String>) -> Result<Self, HostApiError> {
        let value = value.into();
        validate_dotted_host_port_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for HostPortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for HostPortId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HostPortId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// One host port granted into a scoped invocation view.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostPortGrant {
    pub id: HostPortId,
}

impl HostPortGrant {
    pub fn new(id: HostPortId) -> Self {
        Self { id }
    }
}

/// Scoped set of host ports available to an invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPortView {
    grants: Vec<HostPortGrant>,
}

impl HostPortView {
    pub fn new(grants: Vec<HostPortGrant>) -> Result<Self, HostApiError> {
        let mut seen = BTreeSet::new();
        for grant in &grants {
            if !seen.insert(grant.id.clone()) {
                return Err(HostApiError::invariant(format!(
                    "duplicate host port grant {}",
                    grant.id
                )));
            }
        }
        Ok(Self { grants })
    }

    pub fn empty() -> Self {
        Self { grants: Vec::new() }
    }

    pub fn grants(&self) -> &[HostPortGrant] {
        &self.grants
    }

    pub fn allows(&self, id: &HostPortId) -> bool {
        self.grants.iter().any(|grant| &grant.id == id)
    }

    pub fn allows_all<'a, I>(&self, required: I) -> bool
    where
        I: IntoIterator<Item = &'a HostPortId>,
    {
        required.into_iter().all(|id| self.allows(id))
    }
}

impl Default for HostPortView {
    fn default() -> Self {
        Self::empty()
    }
}
