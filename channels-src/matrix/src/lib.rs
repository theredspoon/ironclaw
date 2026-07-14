//! Matrix channel skeleton for IronClaw Reborn.

wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "../../wit/channel.wit",
});

use exports::near::agent::channel::{
    AgentResponse, ChannelConfig, EndpointPattern, Guest, HttpEndpointConfig, IncomingHttpRequest,
    OutgoingHttpResponse, StatusUpdate,
};
#[cfg(not(target_arch = "wasm32"))]
use ironclaw_matrix_adapter::{MatrixParseInput, MatrixParsePolicy, parse_matrix_event};
#[cfg(all(not(test), not(target_arch = "wasm32")))]
use ironclaw_product_adapters::ProductInboundPayload;
use near::agent::channel_host;
#[cfg(all(not(test), not(target_arch = "wasm32")))]
use near::agent::channel_host::EmittedMessage;
use serde::Deserialize;

const WEBHOOK_PATH: &str = "/webhook/matrix";
const SUPPORTED_CALLBACKS: &[&str] = &[
    "on_start",
    "on_http_request",
    "on_poll",
    "on_status",
    "on_shutdown",
];

#[derive(Debug, Deserialize)]
struct MatrixConfig {
    homeserver_url: String,
    #[allow(dead_code)]
    #[serde(default)]
    user_id: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    polling_enabled: bool,
    #[allow(dead_code)]
    #[serde(default)]
    poll_interval_ms: u32,
}

/// Parse and validate homeserver URL, returning the domain.
///
/// Validation rules:
/// - Must use HTTPS scheme (no HTTP)
/// - Must have a valid host component
/// - Must not have a path component (domain only)
fn parse_homeserver_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed != url {
        return Err("homeserver_url must not contain leading or trailing whitespace".to_string());
    }

    if !trimmed.starts_with("https://") {
        return Err("homeserver_url must use HTTPS".to_string());
    }

    let mut host = &trimmed["https://".len()..];
    if let Some(stripped) = host.strip_suffix('/') {
        host = stripped;
    }

    if host.is_empty() {
        return Err("homeserver_url must include a domain".to_string());
    }

    if host.contains('/') {
        return Err("homeserver_url must be domain only (no path component)".to_string());
    }

    if host
        .chars()
        .any(|ch| matches!(ch, '?' | '#' | '@' | ':' | '[' | ']') || ch.is_whitespace())
    {
        return Err("homeserver_url must be an HTTPS origin host without userinfo, port, query, or fragment".to_string());
    }

    let host = host.to_ascii_lowercase();
    if host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '.')
        || !host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.len() <= 63
        })
    {
        return Err("homeserver_url must contain a valid DNS hostname".to_string());
    }

    if host == "localhost" || host.ends_with(".localhost") {
        return Err("homeserver_url must not point to localhost".to_string());
    }

    if host.contains('.') {
        Ok(host)
    } else {
        Err("homeserver_url must contain a fully qualified hostname".to_string())
    }
}

struct MatrixChannel;

impl Guest for MatrixChannel {
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        let config: MatrixConfig = serde_json::from_str(&config_json)
            .map_err(|e| format!("Failed to parse Matrix config: {}", e))?;

        if config.polling_enabled {
            return Err(
                "Matrix polling is not implemented yet; set polling_enabled to false".to_string(),
            );
        }

        // Parse and validate homeserver URL
        let homeserver_domain = parse_homeserver_url(&config.homeserver_url)?;

        // Construct dynamic HTTP allowlist based on configured homeserver
        let http_allowlist = vec![EndpointPattern {
            host: homeserver_domain,
            path_prefix: Some("/_matrix/".to_string()),
            methods: None, // All HTTP methods allowed
        }];

        host_log(
            channel_host::LogLevel::Info,
            "Matrix channel skeleton starting",
        );

        Ok(ChannelConfig {
            display_name: "Matrix".to_string(),
            http_endpoints: vec![HttpEndpointConfig {
                path: WEBHOOK_PATH.to_string(),
                methods: vec!["POST".to_string()],
                require_secret: true,
            }],
            poll: None,
            http_allowlist: Some(http_allowlist),
        })
    }

    fn on_http_request(req: IncomingHttpRequest) -> OutgoingHttpResponse {
        if req.path != WEBHOOK_PATH {
            return json_response(404, serde_json::json!({"error": "unknown Matrix endpoint"}));
        }

        if !req.method.eq_ignore_ascii_case("POST") {
            return json_response(405, serde_json::json!({"error": "method not allowed"}));
        }

        if !req.secret_validated {
            return json_response(401, serde_json::json!({"error": "webhook secret required"}));
        }

        parse_webhook_request(req.body)
    }

    fn on_poll() {
        host_log(
            channel_host::LogLevel::Debug,
            "Matrix polling callback invoked before sync implementation",
        );
    }

    fn on_respond(_response: AgentResponse) -> Result<(), String> {
        Err(unsupported_callback_error(
            "on_respond",
            "Matrix outbound send is not implemented yet",
        ))
    }

    fn on_status(_update: StatusUpdate) {}

    fn on_broadcast(_user_id: String, _response: AgentResponse) -> Result<(), String> {
        Err(unsupported_callback_error(
            "on_broadcast",
            "Matrix broadcast is not implemented yet",
        ))
    }

    fn on_shutdown() {
        host_log(
            channel_host::LogLevel::Info,
            "Matrix channel skeleton shutting down",
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_webhook_request(body: Vec<u8>) -> OutgoingHttpResponse {
    let raw_event = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return json_response(
                400,
                serde_json::json!({"reason_code": "malformed_matrix_event"}),
            );
        }
    };
    match parse_matrix_event(MatrixParseInput {
        raw_event,
        installation_id: "matrix-wasm".to_string(),
        policy: MatrixParsePolicy::default(),
    }) {
        Ok(parsed) => {
            emit_parsed_message(parsed);
            json_response(202, serde_json::json!({"status": "accepted"}))
        }
        Err(diagnostic) => json_response(
            400,
            serde_json::to_value(diagnostic)
                .unwrap_or_else(|_| serde_json::json!({"reason_code": "malformed_matrix_event"})),
        ),
    }
}

#[cfg(target_arch = "wasm32")]
fn parse_webhook_request(_body: Vec<u8>) -> OutgoingHttpResponse {
    json_response(
        501,
        serde_json::json!({"error": "Matrix webhook intake awaits host product bridge"}),
    )
}

#[cfg(all(not(test), not(target_arch = "wasm32")))]
fn emit_parsed_message(parsed: ironclaw_matrix_adapter::ParsedMatrixInbound) {
    let ProductInboundPayload::UserMessage(payload) = parsed.product.payload else {
        return;
    };
    let metadata_json = serde_json::to_string(&parsed.metadata).unwrap_or_else(|_| "{}".to_string());
    channel_host::emit_message(&EmittedMessage {
        user_id: parsed.facts.sender,
        user_name: None,
        content: payload.text,
        thread_id: parsed.metadata.relation.as_ref().map(|relation| relation.event_id.clone()),
        metadata_json,
        attachments: Vec::new(),
    });
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn emit_parsed_message(_parsed: ironclaw_matrix_adapter::ParsedMatrixInbound) {}

#[cfg(not(test))]
fn host_log(level: channel_host::LogLevel, message: &str) {
    channel_host::log(level, message);
}

#[cfg(test)]
fn host_log(_level: channel_host::LogLevel, _message: &str) {}

fn json_response(status: u16, value: serde_json::Value) -> OutgoingHttpResponse {
    OutgoingHttpResponse {
        status,
        headers_json: serde_json::json!({"content-type": "application/json"}).to_string(),
        body: value.to_string().into_bytes(),
    }
}

fn unsupported_callback_error(callback: &str, reason: &str) -> String {
    format!(
        "{} unsupported: {}. Supported callbacks: {}",
        callback,
        reason,
        SUPPORTED_CALLBACKS.join(", ")
    )
}

export!(MatrixChannel);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn default_config() -> String {
        serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "user_id": null,
            "device_id": null,
            "polling_enabled": false
        })
        .to_string()
    }

    fn request(method: &str, path: &str) -> IncomingHttpRequest {
        IncomingHttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers_json: "{}".to_string(),
            query_json: "{}".to_string(),
            body: Vec::new(),
            secret_validated: true,
        }
    }

    fn body_json(response: &OutgoingHttpResponse) -> Value {
        serde_json::from_slice(&response.body).expect("response body should be JSON")
    }

    #[test]
    fn on_start_registers_matrix_endpoint_without_default_polling() {
        let config = <MatrixChannel as Guest>::on_start(default_config()).expect("valid config");

        assert_eq!(config.display_name, "Matrix");
        assert_eq!(config.http_endpoints.len(), 1);
        assert_eq!(config.http_endpoints[0].path, "/webhook/matrix");
        assert_eq!(config.http_endpoints[0].methods, vec!["POST"]);
        assert!(config.http_endpoints[0].require_secret);
        assert!(config.poll.is_none());
    }

    #[test]
    fn on_start_rejects_polling_until_sync_is_implemented() {
        let config_json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "polling_enabled": true,
            "poll_interval_ms": 45000
        })
        .to_string();

        let err = <MatrixChannel as Guest>::on_start(config_json)
            .expect_err("polling must fail closed until Matrix sync exists");
        assert!(err.contains("polling is not implemented"));
    }

    #[test]
    fn on_start_rejects_invalid_config_json() {
        let err = <MatrixChannel as Guest>::on_start("{".to_string())
            .expect_err("invalid JSON must be rejected");
        assert!(err.contains("Failed to parse Matrix config"));
    }

    #[test]
    fn on_start_ignores_poll_interval_when_polling_disabled() {
        let config_json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "polling_enabled": false,
            "poll_interval_ms": 1000
        })
        .to_string();

        let config = <MatrixChannel as Guest>::on_start(config_json)
            .expect("poll interval is inert while polling is disabled");
        assert!(config.poll.is_none());
    }

    #[test]
    fn on_start_requires_homeserver_url() {
        let config_json = serde_json::json!({
            "polling_enabled": false
        })
        .to_string();

        let err = <MatrixChannel as Guest>::on_start(config_json)
            .expect_err("missing homeserver_url must be rejected");
        assert!(err.contains("homeserver_url") || err.contains("missing field"));
    }

    #[test]
    fn on_start_rejects_http_homeserver() {
        let config_json = serde_json::json!({
            "homeserver_url": "http://matrix.org",
            "polling_enabled": false
        })
        .to_string();

        let err = <MatrixChannel as Guest>::on_start(config_json)
            .expect_err("HTTP homeserver must be rejected");
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn on_start_rejects_homeserver_with_path() {
        let config_json = serde_json::json!({
            "homeserver_url": "https://matrix.org/_matrix/client",
            "polling_enabled": false
        })
        .to_string();

        let err = <MatrixChannel as Guest>::on_start(config_json)
            .expect_err("homeserver with path must be rejected");
        assert!(err.contains("domain only"));
    }

    #[test]
    fn on_start_rejects_homeserver_with_url_bypass_components() {
        for homeserver_url in [
            "https://matrix.org:8448",
            "https://user@matrix.org",
            "https://matrix.org?server=evil.test",
            "https://matrix.org#fragment",
            " https://matrix.org",
        ] {
            let config_json = serde_json::json!({
                "homeserver_url": homeserver_url,
                "polling_enabled": false
            })
            .to_string();

            <MatrixChannel as Guest>::on_start(config_json)
                .expect_err("homeserver URL bypass components must be rejected");
        }
    }

    #[test]
    fn on_start_normalizes_homeserver_host_to_lowercase() {
        let config_json = serde_json::json!({
            "homeserver_url": "https://Matrix.Example",
            "polling_enabled": false
        })
        .to_string();

        let config = <MatrixChannel as Guest>::on_start(config_json).expect("valid homeserver");
        let allowlist = config.http_allowlist.expect("allowlist should be provided");

        assert_eq!(allowlist[0].host, "matrix.example");
    }

    #[test]
    fn on_start_constructs_allowlist_from_homeserver() {
        let config_json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "polling_enabled": false
        })
        .to_string();

        let config = <MatrixChannel as Guest>::on_start(config_json).expect("valid homeserver");
        let allowlist = config.http_allowlist.expect("allowlist should be provided");

        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist[0].host, "matrix.org");
        assert_eq!(allowlist[0].path_prefix, Some("/_matrix/".to_string()));
        assert!(allowlist[0].methods.is_none());
    }

    #[test]
    fn on_start_accepts_homeserver_with_trailing_slash() {
        let config_json = serde_json::json!({
            "homeserver_url": "https://homeserver.test/",
            "polling_enabled": false
        })
        .to_string();

        let config =
            <MatrixChannel as Guest>::on_start(config_json).expect("trailing slash accepted");
        let allowlist = config.http_allowlist.expect("allowlist provided");

        assert_eq!(allowlist[0].host, "homeserver.test");
    }

    #[test]
    fn http_request_rejects_unknown_path() {
        let response = <MatrixChannel as Guest>::on_http_request(request("POST", "/wrong"));

        assert_eq!(response.status, 404);
        assert_eq!(body_json(&response)["error"], "unknown Matrix endpoint");
    }

    #[test]
    fn http_request_rejects_non_post_method() {
        let response = <MatrixChannel as Guest>::on_http_request(request("GET", "/webhook/matrix"));

        assert_eq!(response.status, 405);
        assert_eq!(body_json(&response)["error"], "method not allowed");
    }

    #[test]
    fn http_request_rejects_missing_webhook_secret() {
        let mut req = request("POST", "/webhook/matrix");
        req.secret_validated = false;

        let response = <MatrixChannel as Guest>::on_http_request(req);

        assert_eq!(response.status, 401);
        assert_eq!(body_json(&response)["error"], "webhook secret required");
    }

    #[test]
    fn http_request_rejects_malformed_matrix_json() {
        let mut req = request("POST", "/webhook/matrix");
        req.body = b"{".to_vec();
        let response = <MatrixChannel as Guest>::on_http_request(req);

        assert_eq!(response.status, 400);
        assert_eq!(body_json(&response)["reason_code"], "malformed_matrix_event");
    }

    #[test]
    fn http_request_returns_typed_diagnostic_for_unsupported_event() {
        let mut req = request("POST", "/webhook/matrix");
        req.body = serde_json::json!({
            "type": "m.room.member",
            "event_id": "$event:example.org",
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "content": {"body": "Bearer sk_live_secret"}
        })
        .to_string()
        .into_bytes();
        let response = <MatrixChannel as Guest>::on_http_request(req);

        assert_eq!(response.status, 400);
        let body = body_json(&response);
        assert_eq!(body["reason_code"], "unsupported_event_type");
        assert!(!response.body.windows(b"sk_live".len()).any(|w| w == b"sk_live"));
    }

    #[test]
    fn http_request_parses_matrix_text_event_through_adapter() {
        let mut req = request("POST", "/webhook/matrix");
        req.body = serde_json::json!({
            "type": "m.room.message",
            "event_id": "$event:example.org",
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "origin_server_ts": 1710000000000_i64,
            "content": {"msgtype": "m.text", "body": "hello matrix"}
        })
        .to_string()
        .into_bytes();
        let response = <MatrixChannel as Guest>::on_http_request(req);

        assert_eq!(response.status, 202);
        assert_eq!(body_json(&response)["status"], "accepted");
    }

    #[test]
    fn outbound_callbacks_return_explicit_skeleton_errors() {
        let response = AgentResponse {
            message_id: "m1".to_string(),
            content: "hello".to_string(),
            thread_id: None,
            metadata_json: "{}".to_string(),
            attachments: Vec::new(),
        };

        let respond_err = <MatrixChannel as Guest>::on_respond(response.clone())
            .expect_err("respond should not silently succeed");
        assert!(respond_err.contains("Matrix outbound send is not implemented"));

        let broadcast_err =
            <MatrixChannel as Guest>::on_broadcast("@alice:example.org".to_string(), response)
                .expect_err("broadcast should not silently succeed");
        assert!(broadcast_err.contains("Matrix broadcast is not implemented"));
    }

    #[test]
    fn supported_callbacks_are_declared_as_non_empty_array() {
        assert!(!SUPPORTED_CALLBACKS.is_empty());
        assert_eq!(SUPPORTED_CALLBACKS[0], "on_start");
        assert!(SUPPORTED_CALLBACKS.contains(&"on_http_request"));
        assert!(SUPPORTED_CALLBACKS.contains(&"on_poll"));
    }

    #[test]
    fn unsupported_callback_errors_include_callback_name_and_supported_callbacks() {
        let err = unsupported_callback_error("on_respond", "not implemented");

        assert!(err.contains("on_respond"));
        assert!(err.contains("not implemented"));
        assert!(err.contains("Supported callbacks"));
        assert!(err.contains("on_start"));
        assert!(err.contains("on_http_request"));
    }

    #[test]
    fn manifest_declares_host_managed_matrix_capabilities() {
        let manifest: Value = serde_json::from_str(include_str!("../matrix.capabilities.json"))
            .expect("manifest should parse as JSON");

        assert_eq!(manifest["type"], "channel");
        assert_eq!(manifest["name"], "matrix");
        assert_eq!(manifest["wit_version"], "0.3.2");
        assert_eq!(
            manifest["capabilities"]["http"]["credentials"]["matrix_token"]["secret_name"],
            "matrix_access_token"
        );
        assert_eq!(
            manifest["capabilities"]["channel"]["webhook"]["secret_name"],
            "matrix_webhook_secret"
        );
        assert_eq!(
            manifest["capabilities"]["channel"]["workspace_prefix"],
            "channels/matrix/"
        );
    }

    #[test]
    fn readme_documents_skeleton_non_goals() {
        let readme = include_str!("../README.md");

        assert!(readme.contains("Matrix channel skeleton"));
        assert!(readme.contains("does not implement live sync"));
        assert!(readme.contains("does not contain real credentials"));
        assert!(readme.contains("matrix_webhook_secret"));
        assert!(readme.contains("SSRF"));
    }
}
