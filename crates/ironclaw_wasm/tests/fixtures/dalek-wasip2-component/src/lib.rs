#![allow(clippy::missing_panics_doc)]

wit_bindgen::generate!({
    world: "sandboxed-tool",
    path: "../../../../../wit/tool.wit",
});

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, OlmMessage, SessionConfig};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

struct DalekWasip2Validation;

impl exports::near::agent::tool::Guest for DalekWasip2Validation {
    fn execute(req: exports::near::agent::tool::Request) -> exports::near::agent::tool::Response {
        match execute_case(&req.params) {
            Ok(result) => exports::near::agent::tool::Response {
                output: Some(result),
                error: None,
            },
            Err(error) => exports::near::agent::tool::Response {
                output: None,
                error: Some(error),
            },
        }
    }

    fn schema() -> String {
        PARAM_SCHEMA.to_string()
    }

    fn description() -> String {
        "Dalek WASI Preview 2 validation fixture for dalek-family and vodozemac wasm32-wasip2 execution through the Reborn sandboxed-tool ABI. This is non-production test infrastructure.".to_string()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ValidationRequest {
    case: ValidationCase,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ValidationCase {
    Metadata,
    RngSuccess,
    RngDenied,
    RngAllZero,
    RngRepeatedBlock,
    RngBiased,
    RngShortRead,
    DalekPositive,
    DalekNegative,
    VodozemacRoundtrip,
    VodozemacNegative,
    ResourceSuccess,
    ResourceTooLow,
    Benchmark,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    schema_version: u8,
    validation_name: &'static str,
    validation_package: &'static str,
    case: &'static str,
    status: &'static str,
    error_code: Option<&'static str>,
    error_class: Option<&'static str>,
    message: &'static str,
    iteration_count: u32,
}

fn execute_case(params: &str) -> Result<String, String> {
    touch_reborn_host_imports_if_requested(params);
    let request: ValidationRequest =
        serde_json::from_str(params).map_err(|error| format!("invalid request: {error}"))?;
    let result = match request.case {
        ValidationCase::Metadata => metadata(),
        ValidationCase::RngSuccess => rng_success()?,
        ValidationCase::RngDenied => deterministic_failure("rng-denied", "host_entropy_denied"),
        ValidationCase::RngAllZero => deterministic_failure("rng-all-zero", "weak_rng_sample"),
        ValidationCase::RngRepeatedBlock => {
            deterministic_failure("rng-repeated-block", "weak_rng_sample")
        }
        ValidationCase::RngBiased => deterministic_failure("rng-biased", "weak_rng_sample"),
        ValidationCase::RngShortRead => {
            deterministic_failure("rng-short-read", "host_entropy_denied")
        }
        ValidationCase::DalekPositive => dalek_positive()?,
        ValidationCase::DalekNegative => dalek_negative()?,
        ValidationCase::VodozemacRoundtrip => vodozemac_roundtrip()?,
        ValidationCase::VodozemacNegative => vodozemac_negative()?,
        ValidationCase::ResourceSuccess => resource_success(),
        ValidationCase::ResourceTooLow => {
            deterministic_failure("resource-too-low", "resource_limit_exceeded")
        }
        ValidationCase::Benchmark => benchmark()?,
    };
    serde_json::to_string(&result).map_err(|error| format!("result serialization failed: {error}"))
}

fn touch_reborn_host_imports_if_requested(params: &str) {
    if !params.contains("__dalek_wasip2_touch_host_imports__") {
        return;
    }

    near::agent::host::log(
        near::agent::host::LogLevel::Info,
        "Dalek WASI Preview 2 host import retention probe",
    );
    let _ = near::agent::host::now_millis();
    let _ = near::agent::host::workspace_read("dalek-wasip2/nonexistent");
    let _ = near::agent::host::http_request("GET", "https://example.invalid", "{}", None, Some(1));
    let _ = near::agent::host::tool_invoke("dalek-wasip2-nonexistent", "{}");
    let _ = near::agent::host::secret_exists("dalek-wasip2-nonexistent");
}

fn metadata() -> CaseResult {
    pass(
        "metadata",
        "canonical Reborn ABI metadata exports are available",
        1,
    )
}

fn rng_success() -> Result<CaseResult, String> {
    let mut seen: [[u8; 32]; 32] = [[0; 32]; 32];
    let mut one_bits = 0u32;
    for block_index in 0..32 {
        let mut block = [0u8; 32];
        getrandom::fill(&mut block).map_err(|error| format!("getrandom failed: {error}"))?;
        if block == [0; 32] {
            return Ok(fail("rng-success", "weak_rng_sample", "all-zero RNG block"));
        }
        if seen[..block_index]
            .iter()
            .any(|previous| previous == &block)
        {
            return Ok(fail("rng-success", "weak_rng_sample", "repeated RNG block"));
        }
        one_bits += block.iter().map(|byte| byte.count_ones()).sum::<u32>();
        seen[block_index] = block;
    }
    let total_bits = 32 * 32 * 8;
    if !(total_bits * 45 / 100..=total_bits * 55 / 100).contains(&one_bits) {
        return Ok(fail(
            "rng-success",
            "weak_rng_sample",
            "RNG one-bit ratio outside smoke bounds",
        ));
    }
    Ok(pass(
        "rng-success",
        "WASI Preview 2 getrandom path produced non-catastrophic entropy sample",
        32,
    ))
}

fn dalek_positive() -> Result<CaseResult, String> {
    let signing_key = signing_key_from_seed(7);
    let verifying_key = signing_key.verifying_key();
    let message = b"dalek-positive";
    let signature = signing_key.sign(message);
    verifying_key
        .verify(message, &signature)
        .map_err(|error| format!("ed25519 verify failed: {error}"))?;

    let alice_secret = StaticSecret::from([11u8; 32]);
    let bob_secret = StaticSecret::from([29u8; 32]);
    let alice_shared = alice_secret.diffie_hellman(&X25519PublicKey::from(&bob_secret));
    let bob_shared = bob_secret.diffie_hellman(&X25519PublicKey::from(&alice_secret));
    if alice_shared.as_bytes() != bob_shared.as_bytes() {
        return Ok(fail(
            "dalek-positive",
            "crypto_negative_case_failed",
            "x25519 shared secrets differed",
        ));
    }
    Ok(pass(
        "dalek-positive",
        "Ed25519 and X25519 dalek operations succeeded",
        2,
    ))
}

fn dalek_negative() -> Result<CaseResult, String> {
    let signing_key = signing_key_from_seed(13);
    let verifying_key = signing_key.verifying_key();
    let message = b"dalek-negative";
    let mut signature_bytes = signing_key.sign(message).to_bytes();
    signature_bytes[0] ^= 0x01;
    let signature = Signature::from_bytes(&signature_bytes);
    if verifying_key.verify(message, &signature).is_ok() {
        return Ok(fail(
            "dalek-negative",
            "crypto_negative_case_failed",
            "bit-flipped Ed25519 signature verified",
        ));
    }
    let wrong_key = VerifyingKey::from_bytes(&signing_key_from_seed(14).verifying_key().to_bytes())
        .map_err(|error| format!("wrong public key construction failed: {error}"))?;
    let valid_signature = signing_key.sign(message);
    if wrong_key.verify(message, &valid_signature).is_ok() {
        return Ok(fail(
            "dalek-negative",
            "crypto_negative_case_failed",
            "wrong Ed25519 public key verified",
        ));
    }
    Ok(pass(
        "dalek-negative",
        "Ed25519 negative cases failed closed",
        2,
    ))
}

fn vodozemac_roundtrip() -> Result<CaseResult, String> {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);
    let bob_otk = *bob
        .one_time_keys()
        .values()
        .next()
        .ok_or_else(|| "vodozemac did not generate one-time key".to_string())?;
    let mut alice_session = alice
        .create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), bob_otk)
        .map_err(|error| format!("outbound session failed: {error}"))?;
    bob.mark_keys_as_published();

    let message = "dalek-wasip2 synthetic olm message";
    let alice_msg = alice_session
        .encrypt(message)
        .map_err(|error| format!("initial encrypt failed: {error}"))?;
    let OlmMessage::PreKey(pre_key) = alice_msg else {
        return Ok(fail(
            "vodozemac-roundtrip",
            "vodozemac_api_mismatch",
            "first message was not a pre-key message",
        ));
    };
    let inbound = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &pre_key)
        .map_err(|error| format!("inbound session failed: {error}"))?;
    if inbound.plaintext != message.as_bytes() {
        return Ok(fail(
            "vodozemac-roundtrip",
            "crypto_negative_case_failed",
            "initial plaintext mismatch",
        ));
    }
    let mut bob_session = inbound.session;
    let reply = "dalek-wasip2 synthetic olm reply";
    let encrypted_reply = bob_session
        .encrypt(reply)
        .map_err(|error| format!("reply encrypt failed: {error}"))?;
    let decrypted = alice_session
        .decrypt(&encrypted_reply)
        .map_err(|error| format!("reply decrypt failed: {error}"))?;
    if decrypted != reply.as_bytes() {
        return Ok(fail(
            "vodozemac-roundtrip",
            "crypto_negative_case_failed",
            "reply plaintext mismatch",
        ));
    }
    Ok(pass(
        "vodozemac-roundtrip",
        "vodozemac Olm account/session/encrypt/decrypt round trip succeeded",
        2,
    ))
}

fn vodozemac_negative() -> Result<CaseResult, String> {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);
    let bob_otk = *bob
        .one_time_keys()
        .values()
        .next()
        .ok_or_else(|| "vodozemac did not generate one-time key".to_string())?;
    let mut alice_session = alice
        .create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), bob_otk)
        .map_err(|error| format!("outbound session failed: {error}"))?;
    let mut msg = alice_session
        .encrypt("negative")
        .map_err(|error| format!("encrypt failed: {error}"))?;
    let (message_type, mut ciphertext) = msg.clone().to_parts();
    if let Some(byte) = ciphertext.first_mut() {
        *byte ^= 0x80;
    }
    msg = OlmMessage::from_parts(message_type, &ciphertext)
        .map_err(|error| format!("mutated message rejected during parse: {error}"))?;
    if bob
        .create_inbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            match &msg {
                OlmMessage::PreKey(pre_key) => pre_key,
                OlmMessage::Normal(_) => {
                    return Ok(pass(
                        "vodozemac-negative",
                        "mutated pre-key became non-pre-key and failed closed",
                        1,
                    ));
                }
            },
        )
        .is_ok()
    {
        return Ok(fail(
            "vodozemac-negative",
            "crypto_negative_case_failed",
            "mutated pre-key message established a session",
        ));
    }
    Ok(pass(
        "vodozemac-negative",
        "mutated vodozemac pre-key message failed closed",
        1,
    ))
}

fn resource_success() -> CaseResult {
    let mut checksum = 0u64;
    for index in 0..256u64 {
        checksum ^= index.rotate_left(7);
    }
    if checksum == u64::MAX {
        fail(
            "resource-success",
            "resource_limit_exceeded",
            "impossible checksum guard",
        )
    } else {
        pass(
            "resource-success",
            "bounded CPU and memory smoke loop completed",
            256,
        )
    }
}

fn benchmark() -> Result<CaseResult, String> {
    let key = signing_key_from_seed(31);
    for index in 0..32u8 {
        let message = [index; 32];
        let signature = key.sign(&message);
        key.verifying_key()
            .verify(&message, &signature)
            .map_err(|error| format!("benchmark verification failed: {error}"))?;
    }
    Ok(pass(
        "benchmark",
        "32 Ed25519 sign/verify iterations completed",
        32,
    ))
}

fn signing_key_from_seed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn deterministic_failure(case: &'static str, error_code: &'static str) -> CaseResult {
    fail(case, error_code, "deterministic fixture failure injection")
}

fn pass(case: &'static str, message: &'static str, iteration_count: u32) -> CaseResult {
    CaseResult {
        schema_version: 1,
        validation_name: "Dalek WASI Preview 2",
        validation_package: "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component",
        case,
        status: "pass",
        error_code: None,
        error_class: None,
        message,
        iteration_count,
    }
}

fn fail(case: &'static str, error_code: &'static str, message: &'static str) -> CaseResult {
    CaseResult {
        schema_version: 1,
        validation_name: "Dalek WASI Preview 2",
        validation_package: "crates/ironclaw_wasm/tests/fixtures/dalek-wasip2-component",
        case,
        status: "fail",
        error_code: Some(error_code),
        error_class: Some("validation"),
        message,
        iteration_count: 1,
    }
}

export!(DalekWasip2Validation);

const PARAM_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "required": ["case"],
  "properties": {
    "case": {
      "type": "string",
      "enum": [
        "metadata",
        "rng-success",
        "rng-denied",
        "rng-all-zero",
        "rng-repeated-block",
        "rng-biased",
        "rng-short-read",
        "dalek-positive",
        "dalek-negative",
        "vodozemac-roundtrip",
        "vodozemac-negative",
        "resource-success",
        "resource-too-low",
        "benchmark"
      ]
    }
  }
}"#;
