use serde_json::Value;

pub(crate) const MAX_RAW_PAYLOAD_BYTES: usize = 256 * 1024;
pub(crate) const MAX_OUTBOUND_JSON_BYTES: usize = 256 * 1024;
pub(crate) const MAX_JSON_DEPTH: usize = 64;

pub(crate) fn ensure_input_size(field: &str, len: usize, max: usize) -> Result<(), String> {
    if len > max {
        return Err(format!("{field}_too_large"));
    }
    Ok(())
}

pub(crate) fn ensure_json_depth(value: &Value) -> Result<(), String> {
    if depth(value) > MAX_JSON_DEPTH {
        return Err("json_too_deep".to_string());
    }
    Ok(())
}

fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        _ => 1,
    }
}
