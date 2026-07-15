use std::collections::{HashMap, HashSet};

use pulldown_cmark::{Options, Parser, html};
use serde_json::Value;

use crate::egress::matrix_send_egress;
use crate::limits::{MAX_OUTBOUND_JSON_BYTES, ensure_input_size, ensure_json_depth};
use crate::manifest::{ADAPTER_ID, INSTALLATION_ID};

pub(crate) fn render_outbound(outbound_json: String) -> Result<String, String> {
    ensure_input_size(
        "outbound_json",
        outbound_json.len(),
        MAX_OUTBOUND_JSON_BYTES,
    )?;
    let envelope: Value =
        serde_json::from_str(&outbound_json).map_err(|_| "invalid_outbound_json".to_string())?;
    ensure_json_depth(&envelope)?;
    require_match(&envelope, "adapter_id", ADAPTER_ID)?;
    require_match(&envelope, "installation_id", INSTALLATION_ID)?;
    let payload = envelope
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| "unsupported_outbound_payload".to_string())?;
    let final_reply = payload
        .get("final_reply")
        .and_then(Value::as_object)
        .ok_or_else(|| "unsupported_outbound_payload".to_string())?;
    let text = final_reply
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| "invalid_final_reply".to_string())?;
    let room_id = envelope
        .pointer("/target/external_conversation_ref/conversation_id")
        .and_then(Value::as_str)
        .filter(|room| !room.is_empty())
        .ok_or_else(|| "missing_route_metadata".to_string())?;
    if room_id != "!room:example.org" {
        return Err("unauthorized_target_room".to_string());
    }
    let txn_id = envelope
        .get("delivery_attempt_id")
        .and_then(Value::as_str)
        .map(|id| format!("ironclaw-{id}"))
        .ok_or_else(|| "missing_delivery_attempt_id".to_string())?;
    let mut body = serde_json::json!({
        "msgtype": "m.text",
        "body": markdown_to_plaintext(text),
        "format": "org.matrix.custom.html",
        "formatted_body": markdown_to_sanitized_matrix_html(text)
    });
    if let Some(relation) = render_relation(&envelope) {
        body["m.relates_to"] = relation;
    }
    matrix_send_egress(room_id, &txn_id, &body)
}

fn require_match(value: &Value, field: &'static str, expected: &str) -> Result<(), String> {
    match value.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(format!("invalid_{field}")),
        None => Err(format!("missing_{field}")),
    }
}

fn markdown_to_plaintext(markdown: &str) -> String {
    let parser = Parser::new_ext(markdown, Options::empty());
    let mut text = String::new();
    for event in parser {
        match event {
            pulldown_cmark::Event::Text(value) | pulldown_cmark::Event::Code(value) => {
                text.push_str(&value);
            }
            pulldown_cmark::Event::SoftBreak | pulldown_cmark::Event::HardBreak => {
                text.push('\n');
            }
            _ => {}
        }
    }
    if text.is_empty() {
        markdown.to_string()
    } else {
        text
    }
}

fn markdown_to_sanitized_matrix_html(markdown: &str) -> String {
    let mut unsafe_html = String::new();
    let parser = Parser::new_ext(markdown, Options::empty());
    html::push_html(&mut unsafe_html, parser);
    sanitize_matrix_html(&unsafe_html)
}

fn sanitize_matrix_html(raw: &str) -> String {
    let tags: HashSet<&'static str> = [
        "a",
        "b",
        "blockquote",
        "br",
        "code",
        "em",
        "i",
        "li",
        "ol",
        "pre",
        "strong",
        "ul",
    ]
    .into_iter()
    .collect();
    let mut tag_attributes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    tag_attributes.insert("a", ["href"].into_iter().collect());
    let url_schemes: HashSet<&'static str> = ["http", "https"].into_iter().collect();
    let cleaned = ammonia::Builder::new()
        .tags(tags)
        .tag_attributes(tag_attributes)
        .url_schemes(url_schemes)
        .url_relative(ammonia::UrlRelative::Deny)
        .link_rel(None)
        .clean(raw)
        .to_string();
    sanitize_encoded_xss_text(&cleaned)
}

fn sanitize_encoded_xss_text(cleaned: &str) -> String {
    let mut value = cleaned.to_string();
    for pattern in [
        "onerror",
        "onload",
        "javascript:",
        "data:",
        "expression(",
        "&lt;script",
        "&lt;iframe",
        "&lt;object",
        "&lt;embed",
    ] {
        value = replace_ascii_case_insensitive(&value, pattern, "");
    }
    value
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut output = String::new();
    let mut cursor = 0usize;
    while let Some(offset) = lower_input[cursor..].find(&lower_needle) {
        let start = cursor + offset;
        output.push_str(&input[cursor..start]);
        output.push_str(replacement);
        cursor = start + needle.len();
    }
    output.push_str(&input[cursor..]);
    output
}

fn render_relation(envelope: &Value) -> Option<Value> {
    let reply_to = envelope
        .pointer("/target/external_conversation_ref/reply_target_message_id")
        .and_then(Value::as_str);
    let thread_root = envelope
        .pointer("/target/external_conversation_ref/topic_id")
        .and_then(Value::as_str);
    if reply_to.is_none() && thread_root.is_none() {
        return None;
    }
    let mut relation = serde_json::Map::new();
    if let Some(reply_to) = reply_to {
        relation.insert(
            "m.in_reply_to".to_string(),
            serde_json::json!({ "event_id": reply_to }),
        );
    }
    if let Some(thread_root) = thread_root {
        relation.insert("rel_type".to_string(), serde_json::json!("m.thread"));
        relation.insert("event_id".to_string(), serde_json::json!(thread_root));
        relation.insert("is_falling_back".to_string(), serde_json::json!(true));
    }
    Some(Value::Object(relation))
}
