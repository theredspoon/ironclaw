# ironclaw_product_workflow

Product-facing workflow facade for IronClaw Reborn (issue #3280).

## Purpose

Sits between product adapters and host-layer Reborn services. Owns the product
action orchestration so adapters (Web, API, CLI, Telegram, etc.) do not each
reimplement binding resolution, message staging, idempotency, busy/deferred
handling, gate routing, mission routing, and redacted acknowledgements.

## Key types

| Type | Role |
|------|------|
| `DefaultProductWorkflow` | Top-level orchestrator implementing `ProductWorkflow` trait |
| `InboundTurnService` / `DefaultInboundTurnService` | User-message turn submission path |
| `ConversationBindingService` | Resolves external adapter refs → canonical Reborn identifiers |
| `IdempotencyLedger` | Durable action deduplication port |
| `ProductInboundAction` | Durable ledger record for inbound actions |
| `WebUiService` / `DefaultWebUiService` | Native WebChat v2 facade (#3611) — typed surface for browser route handlers; routes the 4 mutation commands to thread service + turn coordinator and the 2 timeline reads to the event projection service, without exposing any of them to handlers |

## Dependencies

- `ironclaw_product_adapters` — trait definitions, envelope/ack types
- `ironclaw_turns` — turn coordinator, scope, IDs
- `ironclaw_threads` — session thread service contract
- `ironclaw_host_api` — canonical identifiers (TenantId, UserId, etc.)
- `ironclaw_event_projections` — read-model boundary for WebUI timeline (#3611)
- `ironclaw_events` — `EventStreamKey` / `ReadScope` used to assemble projection requests

## Boundary rules

Must NOT depend on: `ironclaw_dispatcher`, `ironclaw_extensions`,
`ironclaw_host_runtime`, `ironclaw_mcp`, `ironclaw_wasm`, `ironclaw_scripts`,
`ironclaw_network`, `ironclaw_engine`, `ironclaw_gateway`.

## Test support

Enable `test-support` feature for in-memory fakes:
- `FakeConversationBindingService`
- `FakeIdempotencyLedger`
- `FakeInboundTurnService`
- `FakeWebUiService`
