use serde::{Deserialize, Serialize};

/// Safe summary text for tool-result transcript references.
///
/// This mirrors the loop safe-summary policy because thread records can be
/// replayed into model-visible context through the transcript adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ToolResultSafeSummary(String);

impl ToolResultSafeSummary {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        validate_tool_result_safe_summary(value.into()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for ToolResultSafeSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResultReferenceEnvelope {
    pub version: u32,
    pub result_ref: String,
    pub safe_summary: ToolResultSafeSummary,
}

impl ToolResultReferenceEnvelope {
    pub fn new(
        result_ref: impl Into<String>,
        safe_summary: ToolResultSafeSummary,
    ) -> Result<Self, String> {
        let result_ref = result_ref.into();
        validate_tool_result_ref(&result_ref)?;
        Ok(Self {
            version: 1,
            result_ref,
            safe_summary,
        })
    }
}

fn validate_tool_result_ref(value: &str) -> Result<(), String> {
    if !value.starts_with("result:") {
        return Err("tool result ref must start with result:".to_string());
    }
    if value.len() > 512 {
        return Err("tool result ref exceeds 512 bytes".to_string());
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
    }) {
        return Err(
            "tool result ref must contain only ASCII letters, digits, _, -, ., or :".to_string(),
        );
    }
    Ok(())
}

fn validate_tool_result_safe_summary(value: String) -> Result<String, String> {
    if value.is_empty() {
        return Err("tool result summary must not be empty".to_string());
    }
    if value.len() > 512 {
        return Err("tool result summary exceeds 512 bytes".to_string());
    }
    if value
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return Err("tool result summary must not contain NUL/control characters".to_string());
    }
    if value.chars().any(|character| {
        matches!(
            character,
            '{' | '}' | '[' | ']' | '`' | '<' | '>' | '/' | '\\'
        )
    }) {
        return Err(
            "tool result summary must not contain raw payload or path delimiters".to_string(),
        );
    }

    let lower = value.to_ascii_lowercase();
    for forbidden in [
        "access token",
        "api key",
        "api_key",
        "apikey",
        "authorization:",
        "bearer ",
        "host path",
        "invalid api key",
        "invalid_api_key",
        "password",
        "passwd",
        "provider error",
        "raw runtime",
        "secret",
        "stack trace",
        "tool input",
        "tool_input",
        "traceback",
    ] {
        if lower.contains(forbidden) {
            return Err(format!(
                "tool result summary must not contain sensitive marker `{forbidden}`"
            ));
        }
    }
    if lower
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .any(|token| token.starts_with("sk-"))
    {
        return Err("tool result summary must not contain API-key-like tokens".to_string());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::ToolResultSafeSummary;

    #[test]
    fn safe_summary_rejects_control_characters() {
        assert!(ToolResultSafeSummary::new("line\u{0}break").is_err());
        assert!(ToolResultSafeSummary::new("line\nbreak").is_err());
    }

    #[test]
    fn safe_summary_api_key_check_is_token_based() {
        assert!(ToolResultSafeSummary::new("sky-high confidence").is_ok());
        assert!(ToolResultSafeSummary::new("completed with sk-live-token").is_err());
    }
}
