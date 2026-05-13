# How to port v1 auth and onboarding flows to Reborn

This guide helps maintainers decide how an IronClaw v1 authentication, credential, setup, or onboarding flow should move onto Reborn.

The important distinction is that v1 spread auth and setup behavior across CLI setup, gateway auth, extension managers, tool capability JSON, channel setup, OAuth helpers, settings, and secrets. Reborn should keep those categories separate and connect them through typed settings, scoped secrets, extension lifecycle state, product-surface auth evidence, and run-state gates.

> Status note: this guide describes the Reborn target shape. Some pieces are already implemented as contracts or compatibility shims, while durable `BlockedAuth` resume and manifest-v2 auth metadata are still follow-on work. Do not port new flows by expanding v1 side tables when a Reborn owner already exists.

## Quick decision tree

Ask first: **what is being authenticated or onboarded?**

| v1 source | Examples | Reborn target |
| --- | --- | --- |
| Host access auth | Web gateway bearer token, OIDC, DB-backed user/API tokens, TUI/local session | Native host-surface auth in gateway/TUI/platform code |
| First-run setup | `ironclaw onboard`, quick mode, DB choice, master key, profile, model, heartbeat | Bootstrap config + typed settings repositories + scoped secrets |
| LLM/provider auth | Anthropic/OpenAI/OpenRouter API keys, GitHub Copilot OAuth, NEAR AI session/API key | Provider setup flow that writes provider settings and `SecretHandle`-backed credentials |
| Extension/tool auth | WASM tool OAuth/API key, MCP OAuth, manual token, extension setup schemas | Extension lifecycle/readiness + scoped secret handles + auth gate/resume path |
| Channel/protocol auth | Telegram webhook secret, Slack signature, bearer/session webhook auth | ProductAdapter `AuthRequirement` verified by host; adapter receives sealed `ProtocolAuthEvidence` |
| Pairing/owner binding | Telegram owner binding, channel pairing approval, setup continuation | Unified onboarding states: `setup_required`, `auth_required`, `pairing_required`, `ready`, `failed` |
| Secret storage/migration | API tokens, OAuth access/refresh tokens, webhook secrets, master key | `ironclaw_secrets` typed encrypted store; settings reference handles only |

Rule of thumb:

- If it controls who may use IronClaw, keep it in the host surface.
- If it configures IronClaw before services start, keep it in bootstrap/setup.
- If it configures a provider/extension, use typed settings plus secret handles.
- If it authenticates an external protocol payload, verify in host glue before `ProductAdapter` parsing.
- If it pauses a capability because credentials are missing, model it as an auth gate, not as a tool error.

## Why Reborn separates auth surfaces

V1 frequently mixed these concerns:

```text
capabilities.json / setup wizard / AuthManager / channel setup
  -> raw credential names
  -> sidecar OAuth URLs and setup strings
  -> direct secret-store checks
  -> ad hoc pending auth UI
  -> runtime-specific retry behavior
```

Reborn should use explicit owners:

```text
Host access auth        -> gateway/TUI/platform auth middleware
Bootstrap setup         -> setup service writes bootstrap config
Runtime settings        -> typed settings repository
Credentials            -> SecretHandle + scoped encrypted secret store + one-shot leases
Extension readiness     -> extension lifecycle/config state
Capability invocation   -> CapabilityHost authorization + run-state auth/approval gates
Protocol auth           -> ProductAdapter AuthRequirement + host-minted ProtocolAuthEvidence
User-facing UX          -> onboarding_state / gate projections, not backend secret names
```

This keeps raw secrets out of settings, keeps protocol verification out of adapters, and keeps web/TUI auth out of external ProductAdapter concepts.

## Source-of-truth split

Do not create one new `auth` blob to replace all v1 behavior. Port each datum to the owner that needs query semantics for it.

| Data | Reborn source of truth | Notes |
| --- | --- | --- |
| DB URL/backend, profile, master-key source, first-run completion | Bootstrap config | Needed before DB/settings are available. Current v1 writes `~/.ironclaw/.env`; Reborn may project or import it but must preserve startup ordering. |
| Provider selection, model, embeddings, heartbeat, extension enablement | Typed settings repository | Use schema validation and scoped precedence. |
| API keys, OAuth tokens, webhook secrets | `ironclaw_secrets` | Store encrypted material only; settings/config reference `SecretHandle`. |
| Extension non-secret config | Extension config repository | Validate against extension-declared schema when present. |
| Extension readiness | Extension lifecycle state | Minimum phases: discovered/installed/authentication_required/authenticated/configured/active/disabled/failed. |
| Pending auth/approval work | Run state + gate stores | Target auth blockers are `BlockedAuth`; current compatibility uses engine authentication gates. |
| User-visible status | Events/projections/SSE/onboarding state | Redacted, scoped, and stable for UI resume. |

## Path A: port host access auth

Use this path for the web gateway, local UI, API tokens, OIDC, and any auth that decides whether a user may access IronClaw itself.

### Target shape

```text
incoming host request
  -> gateway/TUI/platform auth middleware
  -> user/session/tenant resolution
  -> native Reborn surface handler
  -> ProductWorkflow or capability host path
```

### What to preserve

- Bearer auth and DB-backed token checks.
- OIDC/session validation when configured.
- Admin/user role checks for management routes.
- CSRF/origin checks for browser WebSocket and state-changing endpoints.
- Query-string token exceptions only for browser SSE/WebSocket endpoints that cannot set headers.
- CORS, body limits, rate limits, panic guards, and static security headers.

### What not to do

- Do not wrap browser sessions as `ExternalActorRef`.
- Do not mint `ProtocolAuthEvidence` for gateway bearer tokens.
- Do not route protected host APIs through ProductAdapter protocol auth.
- Do not expose credential names in web request/response DTOs.

### Host access checklist

- [ ] Identify the user/session/tenant source.
- [ ] Identify which routes are public, protected, admin-only, SSE, or WebSocket.
- [ ] Preserve all body limit, CORS/origin, rate-limit, and auth-token invariants.
- [ ] Keep `ExtensionName` at web setup boundaries; keep `CredentialName` backend-only.
- [ ] Add handler-level tests for unauthorized, wrong-role, malformed identity, and allowed query-token paths.

## Path B: port first-run setup and onboarding

Use this path for `ironclaw onboard`, quick mode, auto-onboard on first run, DB setup, master-key setup, provider/model selection, channel/tool installation, and heartbeat/background defaults.

### Target shape

```text
process start
  -> load bootstrap config / env projections
  -> detect first-run or explicit onboard command
  -> setup service writes bootstrap-only values
  -> setup service writes typed settings
  -> setup service writes scoped secrets
  -> app startup resolves settings after secrets are available
```

### What to preserve from v1

- `.env`/bootstrap config loads before runtime config resolution.
- Auto-onboard triggers only when no usable DB/bootstrap config exists and is suppressible.
- Quick mode asks only high-value local choices and defaults the rest.
- Database setup creates/runs migrations before settings are persisted.
- Master-key setup prefers keychain when available and avoids repeated prompts.
- Incremental persistence after successful setup steps prevents re-entry after partial failures.
- Re-onboarding preserves user-added bootstrap variables.
- LLM/provider config is re-resolved after secrets are stored.

### Target storage rules

- Bootstrap config contains only chicken-and-egg startup values: DB backend/URL/path, local profile, master-key source, first-run completion.
- DB-backed settings contain provider choice, model, embeddings, heartbeat, extension/channel selections, sandbox settings, and other runtime config.
- Secret material goes only to encrypted secret storage.
- Setup may cache secret material in process only long enough to validate and fetch models; do not write it to settings or logs.

### Setup checklist

- [ ] Classify every v1 setting as bootstrap, typed setting, extension config, or secret.
- [ ] Preserve DB-before-settings ordering.
- [ ] Preserve `.env`/bootstrap upsert behavior instead of overwriting unrelated operator vars.
- [ ] Avoid keychain probes in read-only/status commands.
- [ ] Re-resolve provider config after secret writes.
- [ ] Add tests for bootstrap parsing, settings round-trip, partial setup recovery, and no-secret-leak errors.

## Path C: port LLM/provider auth

Use this path for model provider API keys, OAuth providers, local no-auth providers, NEAR AI session/API-key split, and model-list fetchers.

### Target shape

```text
provider setup UI / CLI
  -> choose provider + model settings
  -> collect API key or launch OAuth if needed
  -> store credential as SecretHandle-scoped material
  -> validate/fetch models with bounded secret access
  -> save provider settings that reference handles
```

### Provider categories

| Provider auth style | Reborn treatment |
| --- | --- |
| No auth | typed provider setting only |
| API key | encrypted secret + provider setting referencing handle |
| Browser OAuth | OAuth descriptor + state/PKCE + callback + encrypted access/refresh token storage |
| Device/login flow | interactive login record + encrypted token storage |
| Environment/bootstrap key | import or project as bootstrap fallback; do not silently override DB settings after setup |
| Cloud/hosted session token | host/session auth owner decides validity; treat as credential material if persisted |

### OAuth rules

- Generate and validate state for CSRF protection.
- Use PKCE when the provider supports public-client flows.
- Accept only HTTPS authorization/setup URLs when surfacing links to users.
- Validate token exchange URLs with SSRF/redirect hardening before sending code, verifier, or client secret.
- Truncate and redact provider error bodies before logs, SSE, or user-visible errors.
- Store refresh tokens separately when needed and scope them to the same resource owner.

### Provider checklist

- [ ] Map provider choice/model/base URL to typed settings.
- [ ] Map each credential to a `SecretHandle` and provider metadata.
- [ ] Preserve API-key-required vs optional-key behavior.
- [ ] Preserve model fetch fallback when provider API is unavailable.
- [ ] Avoid mutating environment variables as a runtime credential cache.
- [ ] Add tests for invalid tokens, timeout/fallback, redacted OAuth errors, and post-secret config resolution.

## Path D: port extension/tool auth

Use this path for WASM tools, MCP servers, script integrations with credentials, manual token flows, and extension setup schemas.

### Target shape

```text
Extension Manifest v2 + extension config
  -> declares capability surface and setup/auth needs
  -> extension lifecycle derives readiness
  -> capability invocation checks credential availability
  -> missing credential raises auth gate
  -> user completes OAuth/manual token/setup by extension name
  -> secret store records material under approved handle
  -> same invocation resumes with host-mediated secret lease/injection
```

### Current v1 inputs to mine

- `*.capabilities.json` `auth` and `setup` blocks.
- `AuthDescriptor` records for OAuth/manual token setup.
- `SharedCredentialRegistry` host/path credential mappings.
- `Tool::required_credentials()` declarations.
- MCP server OAuth metadata.
- Skill credential specs.
- Extension setup schemas and setup instructions.

Treat those as migration inputs, not as the final Reborn source of truth.

### Identity invariant

Keep two identities distinct:

| Identity | Meaning | Where visible |
| --- | --- | --- |
| `ExtensionName` / extension ID | User-facing installed integration, route/setup identity | Web/TUI/onboarding/events |
| `CredentialName` / `SecretHandle` | Backend credential storage and injection identity | Auth manager, secret store, runtime injection |

Rules:

- Web setup routes take extension names, not credential names.
- Auth gates should carry or resolve the owning extension name for UI routing.
- Credential handles may appear in redacted backend metadata and audit, not in browser routing as a substitute for extension identity.
- If a new flow needs credential-to-extension mapping, centralize it in the auth manager/resolver rather than deriving names in handlers.

### Readiness mapping

| v1 readiness | Reborn phase/state |
| --- | --- |
| installed but disabled | `inactive` / `disabled` |
| setup schema missing required non-secret config | `setup_required` / `NeedsSetup` |
| OAuth or manual token missing | `auth_required` / `NeedsAuth` |
| token present but owner binding pending | `pairing_required` |
| configured, authenticated, active | `ready` |
| malformed config, failed validation, activation error | `failed` with redacted diagnostic |

### Auth gate target

Durable Reborn auth gates should converge on:

```text
CapabilityHost invocation
  -> auth/credential obligation cannot be satisfied
  -> RunStatus::BlockedAuth with scoped request
  -> user resolves by extension setup/OAuth/manual token
  -> resume validates same scope + request/fingerprint
  -> host stages one-shot secret material
  -> runtime dispatch continues
```

Current compatibility code may still use engine `ResumeKind::Authentication` and pending gate stores. New ports should document that bridge as temporary and avoid adding new no-request-id or credential-name-only UI paths.

### Extension/tool auth checklist

- [ ] Identify every required credential and whether it is manual token, API key, OAuth, no-auth, or admin setup.
- [ ] Map non-secret setup fields to extension config, not secret storage.
- [ ] Map secret fields to `SecretHandle` values and one-shot lease/injection plans.
- [ ] Keep OAuth/setup URLs HTTPS-only before surfacing.
- [ ] Preserve provider-extension ownership for auth gates.
- [ ] Prove missing credentials fail closed before network/runtime dispatch.
- [ ] Prove successful auth resumes the same scoped invocation, not a fresh unscoped action.
- [ ] Add redaction tests for setup errors, OAuth failures, and runtime-visible HTTP errors.

## Path E: port channel/protocol auth and pairing

Use this path for Telegram, Slack, Discord, webhook channels, external callbacks, and any protocol where a third-party sends payloads into IronClaw.

### Target shape

```text
external protocol payload
  -> host verifier checks signature/header/session/bearer evidence
  -> host mints sealed ProtocolAuthEvidence::Verified
  -> ProductAdapter::parse_inbound(raw_payload, auth_evidence)
  -> ProductWorkflow
  -> outbound AuthPrompt/GatePrompt/Projection payloads as needed
```

### Protocol auth rules

- Adapter declares `AuthRequirement`; host glue enforces it before parse.
- Adapter code may inspect evidence but cannot fabricate `Verified` evidence.
- Webhook secrets stay in host secret storage and verifier code, never in adapter DTOs.
- Signature/HMAC verification must be constant-time where applicable.
- Authentication failure returns protocol-appropriate 401/403 before workflow submission.
- Authenticated ignored events should become `ProductInboundPayload::NoOp`.

### Pairing and owner binding

Pairing is not the same as protocol auth:

- Protocol auth proves the payload came from the platform/bot installation.
- Pairing/owner binding proves which IronClaw user should control or claim that external actor/conversation.

Port owner-binding flows to typed onboarding state:

```text
setup_required -> auth_required -> pairing_required -> ready
```

Pairing prompts/resolutions should carry request/action refs, not raw secret material or protocol tokens. ProductAdapter placeholder DTOs already include `AuthPrompt`, `GatePrompt`, `AuthResolution`, and `ApprovalResolution` shapes for future interaction UX.

### Channel/protocol checklist

- [ ] Declare exact protocol auth requirement.
- [ ] Keep verifier in trusted host glue, outside adapter code.
- [ ] Store webhook/bot secrets as scoped secret handles.
- [ ] Keep external refs structured and separate from canonical user/thread IDs.
- [ ] Represent pairing/owner binding as onboarding state, not activation success.
- [ ] Add tests for bad signature, missing secret, replay/malformed payload, pairing denial, and redacted diagnostics.

## Path F: port skills and personal onboarding notes

Most skills do not need a separate auth system port. Copy `SKILL.md` and related assets mostly as-is, then update tool/action names to Reborn capability IDs.

If a skill declares credentials:

- Convert credential specs into extension/auth metadata or provider setup metadata.
- Store credential material in `ironclaw_secrets`.
- Surface missing credentials through the same extension/tool auth gate path as other capabilities.

Personal first-run onboarding is content/setup state, not credential auth. Keep it as user-scoped memory/profile behavior unless it touches provider credentials or extension setup.

## Mapping from v1 concepts

| v1 concept | Reborn target |
| --- | --- |
| `ONBOARD_COMPLETED` | bootstrap first-run completion marker or imported setup state |
| `DATABASE_BACKEND`, `DATABASE_URL`, `LIBSQL_PATH` | bootstrap config needed before settings repository |
| `SECRETS_MASTER_KEY` / keychain master key | bootstrap/key-management setup; secret store readiness gate |
| `settings` table dotted keys | typed settings repository with schema validation |
| `secrets` table rows | typed encrypted secret repository, adapted where schema-compatible |
| `AuthDescriptor` | migration input for extension/provider auth metadata |
| OAuth pending flow registry | scoped auth request/gate state + callback verifier |
| `AuthManager::check_action_auth` | compatibility auth preflight; target is capability auth/obligation gate |
| `ResumeKind::Authentication` | compatibility pending gate; target is durable `BlockedAuth` |
| `ChannelOnboardingState` | user-facing onboarding projection state |
| `CredentialName` in setup UI | backend-only; resolve to `ExtensionName` before web/TUI routing |
| `capabilities.json setup.required_secrets` | secret handles plus extension config schema |
| `capabilities.json auth.oauth` | extension auth metadata + OAuth descriptor |
| webhook token in channel setup | ProductAdapter auth requirement + host verifier secret handle |
| NEAR AI session token file | provider/session credential source; preserve precedence and migration behavior |

## Current gaps to call out in porting PRs

- Manifest v2 auth/setup schema is not fully frozen. Until then, porting reports should list auth metadata explicitly instead of inventing new manifest keys.
- `RunStatus::BlockedAuth` is reserved but not the complete production auth-resume path yet.
- Some gateway compatibility paths still accept legacy auth prompts without gate `request_id`; do not expand them.
- ProductAdapter auth/gate UX DTOs exist, but full external-surface interaction rendering is follow-on work.
- Secrets support one-shot leases and staged injection, but OAuth refresh/rotation policy remains domain-specific.

## Security checklist

- [ ] Secret material never appears in settings, manifests, errors, logs, SSE, DTOs, or projections.
- [ ] Settings reference `SecretHandle`, not `SecretMaterial`.
- [ ] OAuth authorization/setup URLs surfaced to users are HTTPS-only and control-character-free.
- [ ] OAuth token exchange rejects SSRF/redirect hazards and validates state/PKCE.
- [ ] Webhook signatures use constant-time comparison where applicable.
- [ ] Runtime callers cannot supply their own `Authorization`, cookie, API-key header, or credential-shaped URL/body fields when host credential injection is expected.
- [ ] Credential injection is derived from declared capability/extension needs plus caller authority, never from guest/runtime input alone.
- [ ] Auth gates and secret reads are tenant/user/agent/project scoped.
- [ ] Web handlers validate extension route names at the boundary and reject path traversal/malformed slugs with 400.
- [ ] Read-only/status commands do not trigger keychain dialogs.
- [ ] Provider and OAuth error bodies are bounded and redacted.

## Testing checklist

For each ported auth/onboarding flow, add the narrowest caller-level tests that prove:

- missing auth fails closed before side effects;
- invalid credentials produce redacted actionable errors;
- successful setup writes the right owner-scoped settings and secrets;
- re-running setup preserves unrelated bootstrap/settings values;
- auth UI uses extension identity, not credential identity;
- auth resolution resumes only the matching scoped pending request;
- cross-tenant/cross-user secret or gate lookup fails closed;
- web/protocol auth rejects malformed headers, signatures, callback states, and path identities;
- both PostgreSQL and libSQL storage paths preserve existing production data where compatibility requires it.

## Suggested PR split

1. **Inventory PR:** document v1 flow inventory and target owners for each auth/setup surface.
2. **Storage PR:** adapt secrets/settings/bootstrap data without changing runtime behavior.
3. **Lifecycle PR:** move extension readiness/setup/auth state to typed lifecycle projections.
4. **Gate PR:** replace compatibility auth prompts with scoped `BlockedAuth` resume semantics.
5. **Protocol PR:** port channel/webhook auth to ProductAdapter host verifiers.
6. **Cleanup PR:** remove legacy credential-name UI paths and no-request-id auth shims once consumers have migrated.
