# Matrix channel skeleton

This is the Matrix channel skeleton for IronClaw Reborn. It establishes the
WASM component shape, capability manifest, build path, and host callback
contract that later Matrix work will extend.

This skeleton intentionally does not implement live sync, polling, message
sending, E2EE, homeserver discovery, media, or session restore. HTTP callbacks,
polling requests, and outbound responses fail closed with explicit skeleton
errors until those features are implemented in follow-up work.

## Security boundary

The component does not contain real credentials, user IDs, device IDs, access
tokens, or cryptographic keys. `matrix_access_token` is an optional
host-managed secret reserved for follow-up sync/send work. This skeleton does
not use it because no Matrix API calls are implemented.

The `/webhook/matrix` callback is protected by a host-managed
`matrix_webhook_secret` using the `X-Matrix-Webhook-Secret` header. The skeleton
requires the host to validate that secret before the callback reaches WASM.

The channel accepts a single configured `homeserver_url`, requires an HTTPS
origin hostname, and returns a per-instance HTTP allowlist limited to that host
under `/_matrix/`. The host validates that dynamic allowlist before it can
affect outbound HTTP egress. Wildcards, userinfo, ports, query strings,
fragments, paths other than a trailing slash, IP literals, and localhost names
are rejected.

Federated homeserver discovery remains intentionally out of scope. Follow-up
work must define the full SSRF boundary, including DNS rebinding handling,
redirect policy, private/link-local IP rejection, and per-homeserver credential
scoping before enabling discovery or broader Matrix egress.

## Limitations

- No live sync or polling loop. `polling_enabled: true` is rejected by `on_start`.
- No outbound Matrix send or broadcast.
- No E2EE, media, session persistence, or homeserver discovery.
- No access-token use yet; credentials stay host-owned for future work.

## Persistence

The skeleton stores no Matrix session and performs no session refresh. Access
tokens remain in the host secret store, and no Matrix session material is
written to the channel workspace or WASI filesystem.

On component restart, Matrix starts from the same static host-provided config
and has no resumable sync cursor, device state, or refresh-token state to
restore. Follow-up session restore work should use host-owned encrypted
credential/session storage, or an equivalent host-managed keyvalue service,
rather than plaintext WASM workspace files.

## Future interface evolution

The skeleton does not change the shared WIT records for E2EE. Follow-up E2EE
additions should be additive by using optional fields or metadata keys for
sender device identity, encrypted-message content variants, undecryptable event
state, and room/device provenance. They should not require existing plaintext
channels to change their callback signatures.

## Supported callbacks

The skeleton supports the following WIT callbacks as entry points:

- `on_start`
- `on_http_request`
- `on_poll`
- `on_status`
- `on_shutdown`

`on_respond` and `on_broadcast` return descriptive unsupported-callback errors
until Matrix outbound delivery exists.

## Build and test

```bash
cargo test --manifest-path channels-src/matrix/Cargo.toml
cargo build --manifest-path channels-src/matrix/Cargo.toml --target wasm32-wasip2 --release
```

The build output is
`channels-src/matrix/target/wasm32-wasip2/release/matrix_channel.wasm`.
