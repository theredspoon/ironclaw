use ironclaw_product_adapters::mark_bearer_token_verified;
use ironclaw_wasm_product_adapters::{
    ProductAdapterComponentRuntime, ProductAdapterComponentRuntimeConfig, RuntimeError,
};
use wit_component::{ComponentEncoder, StringEncoding, embed_component_metadata};
use wit_parser::Resolve;

const FIXTURE_ADAPTER_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))
  (data (i32.const 1024) "fixture_adapter")
  (data (i32.const 1056) "install_1")
  (data (i32.const 1088) "{\22flags\22:[]}")
  (data (i32.const 1120) "{\22payload\22:\22parsed\22}")
  (data (i32.const 1152) "{\22egress_target_index\22:0}")
  (data (i32.const 1184) "api.example.com")

  (func $manifest (result i32)
    ;; adapter-id
    i32.const 16
    i32.const 1024
    i32.store
    i32.const 20
    i32.const 15
    i32.store
    ;; installation-id
    i32.const 24
    i32.const 1056
    i32.store
    i32.const 28
    i32.const 9
    i32.store
    ;; capabilities-json
    i32.const 32
    i32.const 1088
    i32.store
    i32.const 36
    i32.const 12
    i32.store
    ;; declared-egress-targets: [ { host: "api.example.com", credential-handle: none } ]
    i32.const 1216
    i32.const 1184
    i32.store
    i32.const 1220
    i32.const 15
    i32.store
    i32.const 1224
    i32.const 0
    i32.store
    i32.const 1228
    i32.const 0
    i32.store
    i32.const 1232
    i32.const 0
    i32.store
    i32.const 40
    i32.const 1216
    i32.store
    i32.const 44
    i32.const 1
    i32.store
    ;; declared-auth-requirements: empty list
    i32.const 48
    i32.const 0
    i32.store
    i32.const 52
    i32.const 0
    i32.store
    i32.const 16)

  (func $parse_inbound (param $raw_ptr i32) (param $raw_len i32) (param $evidence_ptr i32) (param $evidence_len i32) (result i32)
    ;; ok(parsed-inbound { parsed-json })
    i32.const 128
    i32.const 0
    i32.store
    i32.const 132
    i32.const 1120
    i32.store
    i32.const 136
    i32.const 20
    i32.store
    i32.const 128)

  (func $render_outbound (param $outbound_ptr i32) (param $outbound_len i32) (result i32)
    ;; ok(outbound-render { egress-request-json })
    i32.const 144
    i32.const 0
    i32.store
    i32.const 148
    i32.const 1152
    i32.store
    i32.const 152
    i32.const 25
    i32.store
    i32.const 144)

  (func $post (param i32))
  (func $realloc (param $old i32) (param $old_align i32) (param $new_size i32) (param $new_align i32) (result i32)
    (local $ret i32)
    global.get $heap
    local.set $ret
    global.get $heap
    local.get $new_size
    i32.add
    global.set $heap
    local.get $ret)
  (func $_initialize)

  (export "near:product-adapter/product-adapter@0.1.0#manifest" (func $manifest))
  (export "cabi_post_near:product-adapter/product-adapter@0.1.0#manifest" (func $post))
  (export "near:product-adapter/product-adapter@0.1.0#parse-inbound" (func $parse_inbound))
  (export "cabi_post_near:product-adapter/product-adapter@0.1.0#parse-inbound" (func $post))
  (export "near:product-adapter/product-adapter@0.1.0#render-outbound" (func $render_outbound))
  (export "cabi_post_near:product-adapter/product-adapter@0.1.0#render-outbound" (func $post))
  (export "cabi_realloc" (func $realloc))
  (export "_initialize" (func $_initialize))
)
"#;

fn product_adapter_component(wat_src: &str) -> Vec<u8> {
    let mut module = wat::parse_str(wat_src).expect("fixture WAT must parse");
    let mut resolve = Resolve::default();
    let package = resolve
        .push_str(
            "product_adapter.wit",
            include_str!("../wit/product_adapter.wit"),
        )
        .expect("product adapter WIT must parse");
    let world = resolve
        .select_world(&[package], Some("product-adapter-component"))
        .expect("product adapter world must exist");

    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
        .expect("component metadata must embed");

    ComponentEncoder::default()
        .module(&module)
        .expect("fixture module must decode")
        .validate(true)
        .encode()
        .expect("component must encode")
}

#[test]
fn prepares_manifest_from_product_adapter_component() {
    let runtime =
        ProductAdapterComponentRuntime::new(ProductAdapterComponentRuntimeConfig::for_testing())
            .expect("runtime");
    let prepared = runtime
        .prepare("fixture", &product_adapter_component(FIXTURE_ADAPTER_WAT))
        .expect("prepare");

    assert_eq!(prepared.name(), "fixture");
    assert_eq!(prepared.manifest().adapter_id.as_str(), "fixture_adapter");
    assert_eq!(prepared.manifest().installation_id.as_str(), "install_1");
    assert_eq!(prepared.manifest().capabilities_json, r#"{"flags":[]}"#);
    assert_eq!(prepared.manifest().declared_egress_targets.len(), 1);
    assert_eq!(
        prepared.manifest().declared_egress_targets[0].host.as_str(),
        "api.example.com"
    );
    assert_eq!(prepared.egress_policy().declared_hosts().count(), 1);
}

#[test]
fn calls_parse_and_render_exports() {
    let runtime =
        ProductAdapterComponentRuntime::new(ProductAdapterComponentRuntimeConfig::for_testing())
            .expect("runtime");
    let prepared = runtime
        .prepare("fixture", &product_adapter_component(FIXTURE_ADAPTER_WAT))
        .expect("prepare");

    let evidence = mark_bearer_token_verified("alice");
    let parsed = runtime
        .parse_inbound(&prepared, br#"{"hello":true}"#, &evidence)
        .expect("parse");
    assert_eq!(parsed.parsed_json, r#"{"payload":"parsed"}"#);

    let rendered = runtime
        .render_outbound(&prepared, r#"{"payload":"out"}"#)
        .expect("render");
    assert_eq!(rendered.egress_request_json, r#"{"egress_target_index":0}"#);
}

#[test]
fn render_rejects_egress_target_not_declared_by_manifest() {
    let runtime =
        ProductAdapterComponentRuntime::new(ProductAdapterComponentRuntimeConfig::for_testing())
            .expect("runtime");
    let undeclared_target_wat = FIXTURE_ADAPTER_WAT.replace(
        "    i32.const 44\n    i32.const 1\n    i32.store\n",
        "    i32.const 44\n    i32.const 0\n    i32.store\n",
    );
    let prepared = runtime
        .prepare(
            "fixture",
            &product_adapter_component(&undeclared_target_wat),
        )
        .expect("prepare");

    let err = runtime
        .render_outbound(&prepared, r#"{"payload":"out"}"#)
        .expect_err("undeclared render target");
    assert!(
        matches!(err, RuntimeError::InvalidJson { field, ref message }
            if field == "outbound-render.egress-request-json"
                && message.contains("egress_target_index 0 is not declared")),
        "{err:?}"
    );
}

#[test]
fn malformed_component_bytes_are_rejected() {
    let runtime =
        ProductAdapterComponentRuntime::new(ProductAdapterComponentRuntimeConfig::for_testing())
            .expect("runtime");
    let err = runtime
        .prepare("bad", b"not wasm")
        .expect_err("bad component");
    assert!(matches!(err, RuntimeError::CompilationFailed(_)), "{err:?}");
}

#[test]
fn component_without_product_adapter_exports_is_rejected() {
    let runtime =
        ProductAdapterComponentRuntime::new(ProductAdapterComponentRuntimeConfig::for_testing())
            .expect("runtime");
    let err = runtime
        .prepare(
            "empty",
            &wat::parse_str("(component)").expect("component wat"),
        )
        .expect_err("missing exports");
    assert!(
        matches!(err, RuntimeError::InstantiationFailed(_)),
        "{err:?}"
    );
}
