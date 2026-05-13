# WS-15 — Prompt Context Assembly: Identity-File Surface

**Workstream:** WS-15 (follow-up; not in the skeleton WS-0..WS-8 set)
**Crates touched:** `ironclaw_loop_support` + `ironclaw_reborn`
(no `ironclaw_turns` change — the slot already exists)
**Depends on:** WS-8 (skeleton landed and green)
**Parallel with:** WS-9..WS-14
**Master doc:** [`../agent-loop-skeleton.md`](../agent-loop-skeleton.md) §11–§12

---

## 1. Scope

`LoopContextBundle.identity_messages: Vec<LoopContextMessage>`
([`crates/ironclaw_turns/src/run_profile/host.rs`](../../../crates/ironclaw_turns/src/run_profile/host.rs)
near line 583) is the slot for identity-style content — `AGENTS.md`,
`SOUL.md`, `USER.md`, `IDENTITY.md`, `HEARTBEAT.md`, `TOOLS.md`,
`BOOTSTRAP.md`, `context/assistant-directives.md`. Today it is
populated with `Vec::new()` unconditionally by
`ThreadBackedLoopContextPort::load_loop_context()` in
[`crates/ironclaw_loop_support/src/lib.rs`](../../../crates/ironclaw_loop_support/src/lib.rs).

This brief adds a `HostIdentityContextSource` trait — analogous to the
existing `HostSkillContextSource` in
[`crates/ironclaw_loop_support/src/skill_context.rs`](../../../crates/ironclaw_loop_support/src/skill_context.rs) —
and wires it through the context port so identity files actually reach
the prompt.

This brief does **not** change any contract types in `ironclaw_turns`.
The `identity_messages` slot, `LoopContextMessage` shape, and
`LoopPromptBundleRequest` are unchanged. The assembly order in
`HostManagedLoopPromptPort` (in
[`crates/ironclaw_turns/src/run_profile/prompt.rs`](../../../crates/ironclaw_turns/src/run_profile/prompt.rs))
is already `identity_messages` → `instruction_snippets` → `messages`;
populating the first slot is the only behavior change.

## 2. Files

### NEW
- `crates/ironclaw_loop_support/src/identity_context.rs` —
  `HostIdentityContextSource` trait, `HostIdentityContextCandidate`
  value type, `HostIdentityContextBuildError`, and
  `build_identity_messages(...)` helper. Mirrors `skill_context.rs`
  shape.

### MODIFIED
- `crates/ironclaw_turns/src/run_profile/host.rs` —
  `LoopContextMessage.message_ref` becomes
  `Option<LoopMessageRef>` (additive contract change in turns).
  `None` means "this entry is summary-only — the prompt port MUST NOT
  attempt to resolve content; use `safe_summary` verbatim instead."
  Mirrors the skill pattern: `SkillTrustLevel::Installed` carries
  `prompt_content: None`. Call-site updates: the existing nine
  consumers wrap their writes in `Some(...)` and pattern-match on
  reads. See §3.2's `IdentityTrustLevel` invariant for the
  Installed-trust attenuation enforced via this field. Counts as
  an additive `ironclaw_turns` contract extension per master doc
  §12 crate-ownership rule.
- `crates/ironclaw_loop_support/src/lib.rs` —
  - Add `pub mod identity_context;` and re-exports.
  - `ThreadBackedLoopContextPort` gains an
    `Option<Arc<dyn HostIdentityContextSource>>` field on construction.
  - `load_loop_context()` calls
    `build_identity_messages(source, run_context)` when set; otherwise
    `Vec::new()` (today's behavior).
- `crates/ironclaw_reborn/src/text_loop_driver.rs` —
  - `TextOnlyModelReplyDriverConfig` gains
    `pub identity_source: Option<Arc<dyn HostIdentityContextSource>>`,
    default `None`.
  - Pass-through to `ThreadBackedLoopContextPort` constructor inside
    the driver's host composition.
- `crates/ironclaw_reborn/src/planned_driver.rs` (this lands with WS-7
  / WS-15 together) — same pass-through. Identity source is hosted at
  driver-composition level, not inside the framework.

### NOT TOUCHED
- `crates/ironclaw_turns/src/run_profile/host.rs` —
  `LoopContextBundle.identity_messages: Vec<LoopContextMessage>` slot
  is unchanged in shape (the inner `LoopContextMessage` gains
  the `Option<...>` field above, but the bundle itself is unaffected).
- `crates/ironclaw_turns/src/run_profile/prompt.rs` —
  `HostManagedLoopPromptPort` already concatenates
  `identity_messages` first when assembling the model message list.
  No code change.
- The actual identity-file *producer* — where files are read from disk,
  how the workspace store resolves them, how trust is decided. This
  brief defines only the trait surface and the adapter wiring. A
  concrete `WorkspaceIdentityContextSource` impl lands as a separate
  PR scoped against `src/workspace/`.

## 3. Specification

### 3.1 `HostIdentityContextSource` trait

```rust
//! crates/ironclaw_loop_support/src/identity_context.rs

use async_trait::async_trait;
use ironclaw_turns::run_profile::{
    AgentLoopHostError, LoopContextMessage, LoopRunContext, PromptMode,
};
use thiserror::Error;

/// Host-owned source for identity-style context that the model receives
/// as system messages before the conversation transcript.
///
/// Identity files canonically include: `AGENTS.md`, `SOUL.md`, `USER.md`,
/// `IDENTITY.md`, `HEARTBEAT.md`, `TOOLS.md`, `BOOTSTRAP.md`,
/// `context/assistant-directives.md`. The canonical filename list is
/// owned by `ironclaw_memory::safety::DEFAULT_PROMPT_PROTECTED_PATHS`
/// (kept singular so the write-protection policy and the prompt-loader
/// agree on what counts as identity content).
///
/// Implementations own storage lookups, trust resolution, and content
/// safety filtering. This trait returns host-approved candidates — raw
/// file content for trusted candidates, refs+summary only for installed
/// (read-only) candidates — so `ironclaw_loop_support` stays a thin
/// adapter that doesn't open files itself.
#[async_trait]
pub trait HostIdentityContextSource: Send + Sync {
    async fn load_identity_candidates(
        &self,
        run_context: &LoopRunContext,
        mode: PromptMode,
    ) -> Result<Vec<HostIdentityContextCandidate>, HostIdentityContextBuildError>;
}
```

### 3.2 `HostIdentityContextCandidate`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentityContextCandidate {
    /// Canonical filename — e.g. "AGENTS.md", "SOUL.md".
    /// Validated against `DEFAULT_PROMPT_PROTECTED_PATHS` so unknown
    /// files cannot inject content under the identity banner.
    pub name: IdentityFileName,

    /// Stable host ref the model port resolves to the file's content
    /// at stream-build time. Identity content is NEVER passed as a
    /// raw string through `LoopContextMessage.safe_summary` — the
    /// ironclaw_turns crate's "no raw prompt content in contracts"
    /// rule prohibits it.
    ///
    /// **Trust-attenuation invariant** (mirrors the skill pattern in
    /// `SkillContextService` — `Installed` skills carry
    /// `prompt_content: None`):
    /// - `Trusted` trust level: `message_ref` MUST be `Some(...)` —
    ///   content resolves to verbatim file bytes
    /// - `Installed` trust level: `message_ref` MUST be `None` —
    ///   only the `safe_summary` reaches the prompt; the candidate
    ///   structurally cannot leak content
    ///
    /// The invariant is enforced at candidate construction (see
    /// `HostIdentityContextCandidate::new_trusted` /
    /// `new_installed_summary_only` constructors below) so a
    /// downstream bug in `build_identity_messages` cannot resolve
    /// an Installed candidate's ref — the ref doesn't exist.
    pub message_ref: Option<LoopMessageRef>,

    /// Short host-redacted summary for prompt-milestone telemetry.
    /// Same role as `LoopContextSnippet.safe_summary`. Must not
    /// contain raw file content.
    // telemetry only — never injected into the model prompt; identity content flows through message_ref
    pub safe_summary: String,

    /// Trust level — drives the same Trusted-vs-Installed attenuation
    /// rules that govern SKILL.md content (see
    /// `.claude/rules/skills.md`). Installed-trust identity content
    /// is summary-only; Trusted content carries through verbatim.
    pub trust_level: IdentityTrustLevel,

    /// Mode gate — `Always`, `OnTextOnly`, or `OnCodeAct`. A
    /// `OnCodeAct` candidate is filtered out before assembly when the
    /// request mode is `TextOnly`. The three variants cover the
    /// skeleton's `PromptMode` enum exactly.
    pub applies_when: IdentityApplicability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityTrustLevel { Installed, Trusted }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityApplicability {
    Always,
    OnTextOnly,
    OnCodeAct,
}

impl HostIdentityContextCandidate {
    /// Constructs a Trusted candidate — content is resolvable via the
    /// supplied `message_ref`. Verbatim file bytes reach the model at
    /// stream-build time.
    pub fn new_trusted(
        name: IdentityFileName,
        message_ref: LoopMessageRef,
        safe_summary: String,
        applies_when: IdentityApplicability,
    ) -> Self {
        Self {
            name,
            message_ref: Some(message_ref),
            safe_summary,
            trust_level: IdentityTrustLevel::Trusted,
            applies_when,
        }
    }

    /// Constructs an Installed candidate — summary-only, no content
    /// ref. The structural absence of `message_ref` makes it impossible
    /// for `build_identity_messages` to resolve verbatim content for
    /// this candidate. Mirrors `SkillTrustLevel::Installed` carrying
    /// `prompt_content: None` in `SkillContextService`.
    pub fn new_installed_summary_only(
        name: IdentityFileName,
        safe_summary: String,
        applies_when: IdentityApplicability,
    ) -> Self {
        Self {
            name,
            message_ref: None,
            safe_summary,
            trust_level: IdentityTrustLevel::Installed,
            applies_when,
        }
    }
}
```

Loop-family-scoped applicability (e.g. an `OnFamilyId(LoopFamilyId)` variant) is
deliberately omitted from this brief: the skeleton ships only
`families::default()` (WS-3.5), so the variant would have nothing to scope
against. `LoopFamilyId` IS a defined type as of WS-3.5; once a second family
ships and per-family identity scoping becomes useful, this enum can grow the
variant in a strictly additive change.

`IdentityFileName` is a newtype per `.claude/rules/types.md` —
construction validates against the canonical filename list, so the
trait surface cannot smuggle arbitrary filenames in.

### 3.3 `build_identity_messages` helper

```rust
pub async fn build_identity_messages(
    source: &(dyn HostIdentityContextSource + Send + Sync),
    run_context: &LoopRunContext,
    mode: PromptMode,
    budget: IdentityBudget,
) -> Result<Vec<LoopContextMessage>, AgentLoopHostError> {
    let candidates = source
        .load_identity_candidates(run_context, mode)
        .await
        .map_err(HostIdentityContextBuildError::into_host_error)?;

    let mut out = Vec::with_capacity(candidates.len());
    let mut used = 0u32;
    for c in candidates {
        if !applies(&c.applies_when, mode, run_context) { continue; }
        let cost = estimate_cost(&c);
        if used.saturating_add(cost) > budget.token_ceiling {
            // Soft drop on budget — telemetry-only, not an error. The
            // host has decided ordering; later entries are lower
            // priority. Mirrors skill-budget behavior.
            break;
        }
        used += cost;
        // Trust attenuation by structural absence: Installed candidates
        // carry `message_ref: None`, so `LoopContextMessage.message_ref`
        // is also None for them — the prompt port has no token to
        // resolve and only `safe_summary` reaches the prompt prefix.
        // Trusted candidates carry `Some(ref)` which resolves to
        // verbatim file bytes.
        out.push(LoopContextMessage {
            message_ref: c.message_ref,
            role: "system".to_string(),
            safe_summary: c.safe_summary,
        });
    }
    Ok(out)
}
```

`IdentityBudget` is local to `ironclaw_loop_support`; default 8K
tokens, configurable via the driver config. Identity messages share
the prompt's overall token budget with `instruction_snippets`
(SKILL.md) but are accounted separately for telemetry.

#### Deterministic ordering contract

Anthropic prompt caching only hits when `identity_messages` bytes are
identical across iterations. Iteration order from the source is the
load-bearing contributor:

- `HostIdentityContextSource::load_identity_candidates` MUST return
  candidates in a canonical deterministic order. Recommended: a fixed
  precedence list keyed off the `DEFAULT_PROMPT_PROTECTED_PATHS`
  ordering already defined in
  [`crates/ironclaw_memory/src/safety.rs`](../../../crates/ironclaw_memory/src/safety.rs)
  near line 153 (`SOUL.md, AGENTS.md, USER.md, IDENTITY.md, SYSTEM.md,
  MEMORY.md, TOOLS.md, HEARTBEAT.md, BOOTSTRAP.md,
  context/assistant-directives.md`). Alphabetical-by-`IdentityFileName.as_str()`
  is an acceptable alternative as long as the impl picks one and is
  consistent across calls.
- `build_identity_messages` MUST preserve the source-provided order
  and MUST NOT re-sort by name inside the helper — re-sorting would
  mask source-side ordering bugs and decouple the helper from the
  canonical filename ordering owned by `ironclaw_memory`.

### 3.3.5 Cache stability: stable vs. volatile identity content

`HostManagedLoopPromptPort` assembles the prompt in the order
`identity_messages → instruction_snippets → messages` (see §3.4 and
[`crates/ironclaw_turns/src/run_profile/prompt.rs`](../../../crates/ironclaw_turns/src/run_profile/prompt.rs)).
Anthropic prompt caching requires the prefix — `identity_messages` —
to be byte-stable across iterations of a single run for cache hits.

The canonical identity files
([`crates/ironclaw_memory/src/safety.rs`](../../../crates/ironclaw_memory/src/safety.rs)
near line 153) split into two buckets:

- **Stable** (byte-stable across the run): `AGENTS.md`, `SOUL.md`,
  `USER.md`, `IDENTITY.md`, `TOOLS.md`, `BOOTSTRAP.md`,
  `context/assistant-directives.md`. These land in `identity_messages`.
- **Volatile** (may change mid-run): `HEARTBEAT.md`. This holds
  timestamped, frequently-changing proactive findings and must NOT
  land in `identity_messages` — every turn's prefix would otherwise
  differ and the prompt cache would miss every turn. Volatile content
  is appended to `instruction_snippets` (after SKILL.md content)
  instead, which sits *after* the cache-sealed identity prefix in the
  `identity → instruction → messages` assembly order.

`HEARTBEAT.md` injection remains gated by `LoopRunContext` to
heartbeat-initiated runs only — see §4 for the run-kind gating in the
concrete `WorkspaceIdentityContextSource` impl.

### 3.4 Adapter wiring

```rust
//! crates/ironclaw_loop_support/src/lib.rs (delta)

pub struct ThreadBackedLoopContextPort {
    // ... existing fields ...
    identity_source: Option<Arc<dyn HostIdentityContextSource>>,
    identity_budget: IdentityBudget,
}

#[async_trait]
impl LoopContextPort for ThreadBackedLoopContextPort {
    async fn load_loop_context(
        &self,
        request: LoopContextRequest,
    ) -> Result<LoopContextBundle, AgentLoopHostError> {
        let messages = self.thread_service.load_context_window(...).await?;
        let instruction_snippets = match self.skill_source.as_ref() {
            Some(src) => build_skill_instruction_snippets(src.as_ref(), &self.run_ctx).await?,
            None => Vec::new(),
        };
        let identity_messages = match self.identity_source.as_ref() {
            Some(src) => build_identity_messages(
                src.as_ref(),
                &self.run_ctx,
                self.prompt_mode_hint,        // see §3.5
                self.identity_budget,
            ).await?,
            None => Vec::new(),
        };
        Ok(LoopContextBundle {
            identity_messages,
            messages,
            instruction_snippets,
            memory_snippets: Vec::new(),    // out of scope here
        })
    }
}
```

### 3.4.5 Per-run caching

Without explicit caching, `ThreadBackedLoopContextPort::load_loop_context()`
re-reads identity files on every iteration. Anthropic prompt caching
still hits on byte-stable content, but the per-tick disk read is
wasteful and opens a race window where a file changes mid-run and the
prefix flips. Required behavior:

- For **stable** files (per §3.3.5), `ThreadBackedLoopContextPort`
  MUST cache the raw `Vec<HostIdentityContextCandidate>` for the run
  on first `load_loop_context()` call and reuse it on subsequent calls.
  Recommended representation: `Arc<OnceLock<Vec<HostIdentityContextCandidate>>>`
  keyed off `LoopRunContext.run_id`. **Per-call filtering MUST happen
  after cache retrieval** — `build_identity_messages` re-applies
  `applies_when` against the request's `PromptMode` on every call.
  *Why not cache the filtered `Vec<LoopContextMessage>`:* `PromptMode`
  can change between iterations (a `PlannedDriver`'s `ContextStrategy`
  may switch from `TextOnly` to `CodeAct` or vice versa per turn).
  Caching the filtered result locks in the first iteration's mode and
  silently produces wrong identity content for subsequent iterations
  with a different mode. Caching candidates (which are mode-independent)
  preserves the cache's purpose (avoid disk re-reads) without freezing
  the mode-dependent filter.
- For **volatile** files (HEARTBEAT.md), the source MUST be
  re-invoked each call; the volatile bucket is appended to
  `instruction_snippets` per §3.3.5 rather than cached as part of the
  stable identity prefix.
- Implementations MUST NOT install file watchers in v1 — file
  changes mid-run are explicitly out of scope under the master doc §5
  layer-1 immutability rule.

### 3.5 Mode plumbing note

`LoopContextPort::load_loop_context` does not currently see the
`PromptMode`. `HostManagedLoopPromptPort::build_prompt_bundle` calls
the context port without forwarding `request.mode`. Three options,
recommended in order:

1. **(Recommended)** Add a `LoopContextRequest.mode: PromptMode` field
   in a one-line `ironclaw_turns` follow-up. Strictly additive; no
   downstream breakage. Brief author should land this micro-PR before
   WS-15's main code, or fold it into WS-15 as a single-line touch in
   the contracts crate.
2. **Driver-time hint** — `ThreadBackedLoopContextPort` is built per
   driver; pass mode at construction. Works for `TextOnlyModelReplyDriver`
   (single mode) but breaks for `PlannedDriver` where
   `ContextStrategy` can return different modes per iteration.
3. **Filter at the prompt port** — `HostManagedLoopPromptPort` does
   the `applies_when` filtering after receiving the bundle. Wastes
   work on candidates that won't apply; correctness identical.

WS-15 ships option 1.

### 3.6 Driver-level plumbing

```rust
//! crates/ironclaw_reborn/src/text_loop_driver.rs (delta)

pub struct TextOnlyModelReplyDriverConfig {
    // ... existing fields ...
    pub identity_source: Option<Arc<dyn HostIdentityContextSource>>,
    pub identity_budget: IdentityBudget,
}
```

`PlannedDriver` (WS-7) takes the same config shape. The identity source
is composed in at driver-build time and held by the host facade — it
is not visible to strategies or the framework crate, consistent with
the §9 "message projection stays host-side" rule from the master doc.

## 4. Concrete WorkspaceIdentityContextSource (deferred to follow-up PR)

The first concrete implementation will live in `src/workspace/` — out
of scope for this brief but worth sketching so reviewers can see the
intended landing point:

- Reads from `~/.ironclaw/projects/<user>/<project>/` (or the workspace
  root path resolved by `LoopRunContext.scope`).
- Filenames pulled from
  `ironclaw_memory::safety::DEFAULT_PROMPT_PROTECTED_PATHS`.
- Trust: identity files placed by the user (workspace root) →
  `Trusted`; files seeded from a registry extension → `Installed`.
- `HEARTBEAT.md` is a **volatile** identity file (see §3.3.5) and
  MUST NOT be returned in the stable identity bundle. The concrete
  impl emits it into `instruction_snippets` (appended after SKILL.md
  content), gated by `LoopRunContext.scope` / `run_kind` so it only
  surfaces on heartbeat-initiated runs. This aligns with the per-run
  caching contract in §3.4.5: the stable identity bundle is cached
  once per run, and HEARTBEAT.md flows through a separate
  re-evaluated-per-call path.
- `applies_when`: most files use `Always`; `TOOLS.md` should use
  `OnCodeAct` (it's irrelevant in `TextOnly` mode where no tools are
  visible).

TOOLS.md is intended for *narrative tool guidance* (e.g. "prefer
`shell` over `file_read` when…"), not for re-declaring the concrete
tool surface — that surface flows through `LoopCapabilityPort::visible_capabilities()`
in WS-9. Workspace authors should not duplicate tool-surface metadata
(names, parameters, JSON schemas) in TOOLS.md prose; if a future
deduplication pass is needed, it lives in the concrete
`WorkspaceIdentityContextSource` impl, not in `build_identity_messages`
(which is content-agnostic).

## 5. Verification

Unit tests (in `crates/ironclaw_loop_support`):
- `identity_context::tests::filters_by_applies_when` — mock source
  returns `[Always, OnCodeAct]`; `TextOnly` request returns one
  message.
- `identity_context::tests::respects_budget` — three large candidates;
  ceiling 1000 tokens; only first two land.
- `identity_context::tests::installed_trust_summary_only` — content
  for `Installed`-trust candidate not exposed; `safe_summary` only.
- `identity_context::tests::ordering_is_deterministic` — invoking the
  source twice with the same `LoopRunContext` produces identical
  `Vec<LoopContextMessage>` (compare byte-equal serialization).
  Guards the §3.3 ordering contract.
- `lib::tests::context_port_populates_identity_when_source_set` —
  `ThreadBackedLoopContextPort` with a mock identity source returns
  non-empty `identity_messages`.
- `lib::tests::context_port_empty_identity_when_source_unset` —
  baseline; identity_messages stays `Vec::new()`.
- `lib::tests::context_port_caches_stable_identity_within_run` —
  invoke `load_loop_context()` twice on the same port; the mock
  identity source is called exactly once and both returned bundles
  are byte-equal. Guards the §3.4.5 per-run caching contract.

Integration test (in `crates/ironclaw_reborn`):
- `text_loop_driver_with_identity` — drives a `TextOnlyModelReplyDriver`
  with a fake identity source returning two candidates. Asserts:
  - `prompt_bundle_built` milestone payload includes the identity
    filenames in its metadata block.
  - The model port receives a message list whose first two entries
    have role `"system"` and resolve to the identity refs.
  - With the source unset, the same test produces a bundle with zero
    leading identity messages (regression guard for the "stays empty"
    baseline).

## 6. Compatibility & rollout

- No `ironclaw_turns` contract change beyond the
  `LoopContextRequest.mode` field in §3.5. Additive, no migration.
- `Option<Arc<dyn HostIdentityContextSource>> = None` is the new
  default for both drivers — existing tests, smoke runs, and the
  skeleton WS-8 integration suite all continue to pass with empty
  `identity_messages`.
- The concrete `WorkspaceIdentityContextSource` lands in a separate PR
  scoped against `src/workspace/`. It can ship in the same release as
  WS-15 or later.

## 7. Out of scope (for this brief)

- Wiring memory_snippets (the fourth `LoopContextBundle` slot). Same
  shape, different source (vector search results), tracked separately.
- Token-counting infrastructure changes — uses the host's existing
  estimator.
- Identity-file authoring tools, CLI commands to seed `SOUL.md`, etc.
- Per-thread / per-run identity overrides — the first cut treats
  identity as workspace-scoped, not run-scoped.
