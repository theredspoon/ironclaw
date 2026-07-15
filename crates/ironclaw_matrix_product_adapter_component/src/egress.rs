use serde_json::Value;

pub(crate) fn matrix_send_egress(
    room_id: &str,
    txn_id: &str,
    body: &Value,
) -> Result<String, String> {
    let encoded_room = urlencoding::encode(room_id);
    let encoded_txn = urlencoding::encode(txn_id);
    let body = serde_json::to_vec(body).map_err(|_| "invalid_matrix_body".to_string())?;
    Ok(serde_json::json!({
        "egress_target_index": 0,
        "method": "PUT",
        "path": format!(
            "/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            encoded_room,
            encoded_txn
        ),
        "headers": [
            {"name": "content-type", "value": "application/json"}
        ],
        "body": body
    })
    .to_string())
}
