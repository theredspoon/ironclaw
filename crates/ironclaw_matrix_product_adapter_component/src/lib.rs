wit_bindgen::generate!({
    world: "product-adapter-component",
    path: "../ironclaw_wasm_product_adapters/wit/product_adapter.wit",
});

mod auth;
mod config;
mod egress;
mod inbound;
mod limits;
mod manifest;
mod outbound;

struct MatrixProductAdapterComponent;

impl exports::near::product_adapter::product_adapter::Guest for MatrixProductAdapterComponent {
    fn manifest() -> exports::near::product_adapter::product_adapter::AdapterManifest {
        manifest::manifest()
    }

    fn parse_inbound(
        raw_payload: Vec<u8>,
        evidence: exports::near::product_adapter::product_adapter::AuthEvidence,
    ) -> Result<exports::near::product_adapter::product_adapter::ParsedInbound, String> {
        inbound::parse_inbound(raw_payload, evidence.evidence_json).map(|parsed_json| {
            exports::near::product_adapter::product_adapter::ParsedInbound { parsed_json }
        })
    }

    fn render_outbound(
        envelope: exports::near::product_adapter::product_adapter::OutboundEnvelope,
    ) -> Result<exports::near::product_adapter::product_adapter::OutboundRender, String> {
        outbound::render_outbound(envelope.outbound_json).map(|egress_request_json| {
            exports::near::product_adapter::product_adapter::OutboundRender {
                egress_request_json,
            }
        })
    }
}

export!(MatrixProductAdapterComponent);
