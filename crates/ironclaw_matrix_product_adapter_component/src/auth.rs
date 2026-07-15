use serde_json::Value;

pub(crate) fn require_verified_evidence(evidence_json: &str) -> Result<(), String> {
    let evidence: Value =
        serde_json::from_str(evidence_json).map_err(|_| "invalid_auth_evidence".to_string())?;
    match evidence.get("kind").and_then(Value::as_str) {
        Some("verified") => Ok(()),
        Some("failed") => Err("missing_auth_evidence".to_string()),
        _ => Err("invalid_auth_evidence".to_string()),
    }
}
