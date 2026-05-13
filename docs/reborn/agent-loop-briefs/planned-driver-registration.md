# WS-14 — `PlannedDriver` Registration + Run-Profile Selection

**Workstream:** WS-14 (follow-up; not in the skeleton WS-0..WS-8 set)
**Crates touched:** `ironclaw_reborn` (sole owner per master doc §12)
**Depends on:** WS-7 (`PlannedDriver` adapter), WS-8 (skeleton green),
**and hard-gated on all five parallel follow-ups**: WS-9
([capability-host-wiring](capability-host-wiring.md)), WS-10
([checkpoint-store-and-resume](checkpoint-store-and-resume.md)),
WS-11 ([loop-input-port](loop-input-port.md)), WS-12
([loop-progress-port](loop-progress-port.md)), WS-13
([host-cancellation-accessor](host-cancellation-accessor.md))
**Parallel with:** WS-15 ([prompt-context-assembly](prompt-context-assembly.md))
only (`identity_messages = Vec::new()` is a valid empty surface for
the smoke test)
**Master doc:** [`../agent-loop-skeleton.md`](../agent-loop-skeleton.md) §11–§12

---

## 1. Scope

After the skeleton (WS-0..WS-8) lands, `PlannedDriver` exists but is
unreachable from a real submitted turn — `TurnRunner` looks up
drivers in `DriverRegistry`
([`crates/ironclaw_reborn/src/driver_registry.rs:164`](../../../crates/ironclaw_reborn/src/driver_registry.rs))
by the `(driver_id, version, checkpoint_schema_id, schema_version)`
key, and only `TextOnlyModelReplyDriver` is registered there today
([`crates/ironclaw_reborn/src/text_loop_driver.rs:20`](../../../crates/ironclaw_reborn/src/text_loop_driver.rs)).
Profiles emitted by `InMemoryRunProfileResolver`
([`crates/ironclaw_turns/src/run_profile/resolver.rs:115`](../../../crates/ironclaw_turns/src/run_profile/resolver.rs))
all point at `reborn:text-only-model-reply`.

WS-14 closes the loop:

1. **Stable `LoopDriverId` constants** for the default planned driver
   and the v1 checkpoint schema id reserved by WS-0.
2. **Factory** `default_planned_driver()` that composes a
   non-generic `PlannedDriver` (holding `families::default()` resolved
   via `Arc<LoopFamilyRegistry>` plus `Arc<CanonicalAgentLoopExecutor>`)
   from a fully-wired `PlannedDriverConfig`.
3. **Registration helper** `register_default_planned_driver(registry,
   config)` that calls `DriverRegistry::register_driver` with the
   right `DriverRequirements` flags.
4. **Profile resolver entry** — a new builtin profile
   `reborn-planned-default` that resolves to the new driver, with a
   sensible default capability-surface profile id.
5. **Coexistence** — `TextOnlyModelReplyDriver` stays registered;
   profiles opt in by name; no global switch.

This is the **first real end-to-end run through the framework**: the
new driver is reachable via a submitted turn, the executor's
canonical tick fires, the host adapters from WS-9 / WS-11 / WS-12 /
WS-13 actually execute, and `LoopExit::Completed` carries a real
assistant message ref.

## 2. Files

### NEW
- `crates/ironclaw_reborn/src/planned_driver_factory.rs` —
  `default_planned_driver()`, `register_default_planned_driver()`,
  driver-id / checkpoint-schema-id constants.
- `crates/ironclaw_reborn/tests/planned_driver_e2e.rs` — the smoke
  tests in §5.

### MODIFIED
- `crates/ironclaw_reborn/src/lib.rs` — module declaration +
  re-export of the constants.
- `crates/ironclaw_reborn/src/planned_driver.rs` (WS-7 file) — no
  type alias needed; `PlannedDriver` is non-generic. The factory
  returns `PlannedDriver` directly.
- Wherever `InMemoryRunProfileResolver` seeds its builtin profiles
  (per the resolver layout near
  [`resolver.rs:115`](../../../crates/ironclaw_turns/src/run_profile/resolver.rs))
  — registration of the `reborn-planned-default` profile happens in
  `ironclaw_reborn` (not `ironclaw_turns`), via a `register_default_profiles(resolver)`
  helper that lives next to the registration helper above.

### MODIFIED (additive trait extension)
- `crates/ironclaw_turns/src/run_profile/resolver.rs` —
  `InMemoryRunProfileRegistry` gains a public mutator
  `pub fn register(&mut self, definition: RunProfileDefinition) -> Result<(), …>`.
  Today the registry's `with_builtin_profiles()` constructor at
  [`resolver.rs:115`](../../../crates/ironclaw_turns/src/run_profile/resolver.rs)
  is the only way to populate it, and the field is private. The
  follow-up cannot register a new builtin from `ironclaw_reborn`
  without this small contract addition. Strictly additive; existing
  `default()` constructor stays unchanged.

### NOT TOUCHED
- `crates/ironclaw_turns/src/run_profile/host.rs`,
  `driver.rs`, `refs.rs` — the contract surface for the trait /
  descriptor / id types is unchanged.
- `crates/ironclaw_reborn/src/text_loop_driver.rs` — TextOnly stays
  registered as-is. The constants at lines 20–56 are read-only for
  this brief.

## 3. Specification

### 3.1 Driver-id and checkpoint-schema constants

```rust
//! crates/ironclaw_reborn/src/planned_driver_factory.rs

use ironclaw_turns::run_profile::{CheckpointSchemaId, LoopDriverId, RunProfileVersion};

/// Stable id for the default planned driver.
///
/// Format follows the existing convention at
/// `crates/ironclaw_reborn/src/text_loop_driver.rs:20` —
/// `"reborn:"` prefix, lowercase + dashes. Persisted in
/// `LoopDriverRegistryKey`; do NOT rename without a migration.
pub const PLANNED_DRIVER_DEFAULT_ID: &str = "reborn:planned-default";

pub const PLANNED_DRIVER_DEFAULT_VERSION: RunProfileVersion = RunProfileVersion::new(1);

/// Reserved by WS-0 (`agent-loop-briefs/state-and-checkpoints.md:127`).
/// `LoopExecutionState::from_checkpoint_payload` decodes only this
/// schema id today.
pub const PLANNED_DRIVER_CHECKPOINT_SCHEMA_ID: &str = "reborn:default-loop-v1";

pub const PLANNED_DRIVER_CHECKPOINT_SCHEMA_VERSION: RunProfileVersion = RunProfileVersion::new(1);

pub fn planned_driver_default_id() -> LoopDriverId {
    // newtype constructor validates the static literal
    LoopDriverId::from_trusted_static(PLANNED_DRIVER_DEFAULT_ID)
}

pub fn planned_driver_checkpoint_schema_id() -> CheckpointSchemaId {
    CheckpointSchemaId::from_trusted_static(PLANNED_DRIVER_CHECKPOINT_SCHEMA_ID)
}
```

`LoopDriverId` and `CheckpointSchemaId` are newtypes generated by the
`profile_ref!` macro at
[`crates/ironclaw_turns/src/run_profile/refs.rs:54`](../../../crates/ironclaw_turns/src/run_profile/refs.rs).
`from_trusted_static` is the existing legacy constructor used by
TextOnly at `text_loop_driver.rs:51`; per `.claude/rules/types.md`
"Legacy exception" note, it is acceptable for these existing
identity types.

### 3.2 Factory `default_planned_driver`

```rust
//! crates/ironclaw_reborn/src/planned_driver_factory.rs

use std::sync::Arc;
use ironclaw_agent_loop::{
    canonical_executor::CanonicalAgentLoopExecutor,
    default_planner::DefaultPlanner,
};
use ironclaw_turns::run_profile::{
    AgentLoopDriverDescriptor, CheckpointSchemaIdOptional, RunProfileVersionOptional,
};
use crate::planned_driver::{PlannedDriver, PlannedDriverConfig};
use ironclaw_agent_loop::family::{LoopFamilyId, LoopFamilyRegistry};

pub struct DefaultPlannedDriverBuild {
    pub driver: Arc<dyn ironclaw_turns::run_profile::AgentLoopDriver>,
    pub descriptor: AgentLoopDriverDescriptor,
}

pub fn default_planned_driver(
    config: PlannedDriverConfig,
    family_registry: Arc<LoopFamilyRegistry>,
) -> DefaultPlannedDriverBuild {
    let family = family_registry
        .get(&LoopFamilyId::DEFAULT)
        .expect("LoopFamilyRegistry::builtin always binds DEFAULT");
    let executor = Arc::new(CanonicalAgentLoopExecutor::default());
    let driver = PlannedDriver::from_family(family, executor, PLANNED_DRIVER_DEFAULT_VERSION)
        .expect("default family + framework checkpoint schema validate");

    let descriptor = AgentLoopDriverDescriptor::from_trusted_static_with_checkpoint(
        planned_driver_default_id(),
        PLANNED_DRIVER_DEFAULT_VERSION,
        Some(planned_driver_checkpoint_schema_id()),
        Some(PLANNED_DRIVER_CHECKPOINT_SCHEMA_VERSION),
    );

    DefaultPlannedDriverBuild {
        driver: Arc::new(driver) as Arc<dyn _>,
        descriptor,
    }
}
```

`AgentLoopDriverDescriptor::from_trusted_static_with_checkpoint` is
the four-arg variant of the existing `from_trusted_static` at
`crates/ironclaw_turns/src/run_profile/driver.rs:13`. The brief
spells out the constructor in case the actual codebase uses a
builder shape — the implementer matches the API at PR time.

### 3.3 Registration helper

```rust
//! crates/ironclaw_reborn/src/planned_driver_factory.rs

use ironclaw_reborn::driver_registry::{
    DriverKind, DriverRegistry, DriverRegistryError, DriverRequirements,
    LoopDriverRegistryKey,
};

pub fn register_default_planned_driver(
    registry: &mut DriverRegistry,
    config: PlannedDriverConfig,
) -> Result<LoopDriverRegistryKey, DriverRegistryError> {
    let build = default_planned_driver(config);
    // DriverRequirements uses RequirementLevel — Required / Optional /
    // Unsupported — not booleans. See
    // `crates/ironclaw_reborn/src/driver_registry.rs:56,64`.
    // PlannedDriver consults every port the canonical tick touches,
    // so every dimension is Required.
    //
    // Note: there is no `cancellation` dimension on DriverRequirements
    // today. WS-13's cancellation observation is wired below the
    // registry-readiness contract — `RebornLoopDriverHost` always
    // exposes the `LoopCancellationPort` once WS-13 lands, so the
    // driver simply assumes it. If the existing `DriverRequirements`
    // surface ever grows a `cancellation` field, this constructor
    // gains a matching `RequirementLevel::Required` line in a strict
    // follow-up.
    let requirements = DriverRequirements {
        model: RequirementLevel::Required,
        prompt: RequirementLevel::Required,
        transcript: RequirementLevel::Required,
        checkpoint: RequirementLevel::Required,
        input_polling: RequirementLevel::Required,
        capabilities: RequirementLevel::Required,
        progress_events: RequirementLevel::Required,
    };
    registry.register_driver(build.driver, requirements, DriverKind::Production)
}
```

Each dimension is explicit `RequirementLevel::Required` rather than
the equivalent `DriverRequirements::all_required()` helper at
[`driver_registry.rs:87`](../../../crates/ironclaw_reborn/src/driver_registry.rs)
to keep the rationale visible at the call site. Future tightening
(e.g. `progress_events: RequirementLevel::Optional` once we accept
that drop-on-fail is acceptable) becomes a one-line change with
clear blame.

### 3.4 Profile registry entry

```rust
//! crates/ironclaw_reborn/src/planned_driver_factory.rs

use ironclaw_turns::run_profile::{
    CapabilitySurfaceProfileId, InMemoryRunProfileRegistry, ModelProfileId,
    RunProfileDefinition, RunProfileId,
};

pub const PLANNED_DEFAULT_PROFILE_ID: &str = "reborn-planned-default";

pub fn register_default_planned_profile(
    registry: &mut InMemoryRunProfileRegistry,
) -> Result<(), RunProfileRegistryError> {
    // The builder/constructor shape for RunProfileDefinition matches
    // whatever the helpers `interactive_profile()` / `long_running_mission_profile()`
    // at the bottom of `crates/ironclaw_turns/src/run_profile/resolver.rs` use.
    // The implementer mirrors the existing builtin's construction.
    let definition = RunProfileDefinition::builder()
        .profile_id(RunProfileId::from_trusted_static(PLANNED_DEFAULT_PROFILE_ID))
        .profile_version(PLANNED_DRIVER_DEFAULT_VERSION)
        .loop_driver(AgentLoopDriverDescriptor::from_trusted_static_with_checkpoint(
            planned_driver_default_id(),
            PLANNED_DRIVER_DEFAULT_VERSION,
            Some(planned_driver_checkpoint_schema_id()),
            Some(PLANNED_DRIVER_CHECKPOINT_SCHEMA_VERSION),
        ))
        .checkpoint_schema_id(planned_driver_checkpoint_schema_id())
        .checkpoint_schema_version(PLANNED_DRIVER_CHECKPOINT_SCHEMA_VERSION)
        // Match the surface profile id used by TextOnly's builtin
        // (interactive_profile) so the first E2E run is apples-to-apples.
        // WS-9's CapabilitySurfaceProfileResolver decides the actual surface.
        .capability_surface_profile_id(default_text_capability_surface())
        .model_profile_id(default_text_model_profile())
        // Steering/cancellation/checkpoint/budget policies and
        // required_privileges all match interactive_profile()'s
        // defaults; copy them at PR time.
        .build()?;
    // `register` is the new public mutator added to
    // InMemoryRunProfileRegistry in `ironclaw_turns` per §2 MODIFIED.
    registry.register(definition)
}
```

`InMemoryRunProfileResolver` is constructed from a registry via
`InMemoryRunProfileResolver::new(registry)`; startup wiring (§3.6)
builds the registry first, registers both the builtin profiles and
the new `reborn-planned-default`, then wraps it in the resolver.

### 3.5 Coexistence with `TextOnlyModelReplyDriver`

The TextOnly driver stays registered. Two profiles co-exist:

- `interactive_default` (the existing builtin at
  [`crates/ironclaw_turns/src/run_profile/resolver.rs:210`](../../../crates/ironclaw_turns/src/run_profile/resolver.rs))
  → `reborn:text-only-model-reply` v1, no checkpoint schema. Also
  the implicit default when no profile is requested
  ([`resolver.rs:85`](../../../crates/ironclaw_turns/src/run_profile/resolver.rs)).
- `reborn-planned-default` (this brief) → `reborn:planned-default` v1,
  `reborn:default-loop-v1` v1.

`LoopDriverRegistryKey` includes the checkpoint schema id+version,
so the two keys are distinct even though both pin driver version 1.
No collision risk.

Migration policy is **explicit opt-in**: a profile chooses by name
when submitting a turn (via `RunProfileRequest`). No automated
shimming, no environment-flag switch. The brief lists which
downstream profiles exist today and notes that *none* are migrated
automatically — operators decide.

### 3.6 Startup wiring

The brief documents the startup-time call sequence so a reviewer
can trace the bring-up:

```rust
// at IronClaw app startup (composition root)

// Driver registry — register both drivers.
let mut driver_registry = DriverRegistry::default();
register_default_text_only_driver(&mut driver_registry, text_only_config)?;  // existing
register_default_planned_driver(&mut driver_registry, planned_driver_config)?; // NEW

// Profile registry — start with the existing builtins, then add ours.
let mut profile_registry = InMemoryRunProfileRegistry::with_builtin_profiles();
register_default_planned_profile(&mut profile_registry)?;                     // NEW
let resolver = InMemoryRunProfileResolver::new(profile_registry);

let coordinator = TurnCoordinator::new(/* … */).with_resolver(resolver);
let runner = TurnRunner::new(/* … */).with_registry(driver_registry);
```

`planned_driver_config: PlannedDriverConfig` is composed at startup
from the parallel-follow-up adapters:

- WS-9: `capability_dispatcher`, `surface_resolver`
- WS-10: `checkpoint_state_store`, `checkpoint_metadata_store`
- WS-11: `input_queue`
- WS-12: `event_sink: Some(...)`
- WS-13: `cancellation_factory`
- WS-15 (optional): `identity_source`, `identity_budget`

WS-14's hard-gate dependency on WS-9/10/11/12/13 (declared in the
header) means the brief assumes all four config fields point at
real adapters. WS-15 is optional; `identity_source = None` is fine.

## 4. Composition diagram

```text
                 TurnCoordinator
                       │
                       ▼
                   TurnRunner ── DriverRegistry
                       │              │
                       ▼              ▼
              ResolvedRunProfile   LoopDriverRegistryKey lookup
                       │              │
                       ▼              ▼
                  RunProfileResolver   ┌─────────────────────────┐
                       │               │   PlannedDriver         │
                       └──────────────►│   (DefaultPlanner +     │
                                       │    CanonicalExecutor)   │
                                       └────────────┬────────────┘
                                                    ▼
                                    AgentLoopDriverHost facade
                                       │
                  ┌────────────────────┼──────────────────────────┐
                  ▼                    ▼                          ▼
       HostRuntimeLoopCapabilityPort  HostManagedLoopProgressPort   RunStateLoopCancellationPort
       + CapabilitySurfaceProfileFilter   (extended match, WS-12)            (WS-13)
                  (WS-9)
                  ▼
            HostQueueLoopInputPort
                  (WS-11)
                  ▼
       HostManagedLoopCheckpointPort
         (extended with load_checkpoint_payload, WS-10)
                  ▼
             (skeleton ports for context/prompt/model/transcript stay)
```

## 5. Verification

Unit tests (in `crates/ironclaw_reborn`):

- `planned_driver_factory::tests::register_default_planned_driver_uses_v1_schema`
  — assert `LoopDriverRegistryKey` matches the four constants in
  §3.1.
- `planned_driver_factory::tests::descriptor_carries_checkpoint_schema`
  — assert
  `descriptor.checkpoint_schema_id() == Some("reborn:default-loop-v1")`.
- `planned_driver_factory::tests::key_collision_with_textonly_is_impossible`
  — register both drivers; assert both `LoopDriverRegistryKey`s are
  distinct.
- `planned_driver_factory::tests::profile_resolves_to_planned_driver`
  — register the profile; resolve `RunProfileId("reborn-planned-default")`;
  assert resolved `driver_id == "reborn:planned-default"` v1.

Integration tests (the **hard-gate merge criterion** for WS-14, in
`crates/ironclaw_reborn/tests/planned_driver_e2e.rs`):

- `planned_driver_real_host_smoke` — composes the **real** adapters
  from all five parallel follow-ups (no mocks):
  - WS-9: `HostRuntimeLoopCapabilityPort` over a test fixture
    `CapabilityDispatcher` that registers one allowed tool
    (`echo_payload`) returning a fixed result, plus
    `CapabilitySurfaceProfileFilter` with that tool's id in the
    allowlist.
  - WS-10: `HostManagedLoopCheckpointPort` (extended with WS-10's
    `load_checkpoint_payload`) over `InMemoryCheckpointStateStore` +
    `InMemoryLoopCheckpointStore`.
  - WS-11: `HostQueueLoopInputPort` over `InMemoryHostInputQueue`.
  - WS-12: `HostManagedLoopProgressPort` (extended with WS-12's
    match-expansion) routing into an in-memory `LoopHostMilestoneSink`
    capturing milestones.
  - WS-13: `RunStateLoopCancellationPort` over a never-fired
    `RunCancellationHandle`.
  Submits a turn under `reborn-planned-default` whose model emits
  one capability call to `echo_payload` and then a reply.
  Asserts:
  - `LoopExit::Completed`
  - `reply_message_refs.len() == 1`
  - `result_refs.len() == 1`
  - milestone sink captured a `LoopHostMilestoneKind::IterationStarted`
    and a `LoopHostMilestoneKind::Completed`.
- `planned_driver_real_host_cancellation` — same setup, but flip
  the `RunCancellationHandle` after `BeforeSideEffect` checkpoint;
  assert `LoopExit::Cancelled { reason_kind: UserRequested }` and
  that `WS-10`'s `load_checkpoint_payload` against the `Final`
  checkpoint resolves to a payload whose decoded
  `LoopExecutionState.iteration == 0` (cancellation happened before
  the iteration completed).
- `planned_driver_text_only_profile_still_resolves_textonly` —
  regression guard: registering both drivers does not affect the
  TextOnly profile's resolution.

The two real-host smoke tests cannot compile or pass until WS-9 /
WS-11 / WS-12 / WS-13 are all merged. That is the hard-gate.

## 6. Out of scope (for this brief)

- **Migrating existing profiles** to the new driver. Each profile
  picks its driver by name; operators decide when to flip.
- **Driver kill-switch / rollout flags.** Registry membership is
  the toggle; deregister the planned driver to disable. No additional
  flag plumbing.
- **Loop-family planners** (`coding`, `routine`, …) — master doc
  §11/§12 / §12.5 explicitly defers; WS-14 ships `families::default()`
  only, resolved via the `LoopFamilyRegistry` (WS-3.5).
- **Versioning the family separately from the driver.** `LoopFamily.version`
  (`ComponentIdentity`) lands in the checkpoint payload metadata (WS-0
  §3.2), not in the registry key. A new family shape (or a strategy
  composition change inside an existing family) bumps `ComponentIdentity.digest`
  and may ship under a new driver id.
- **Schema migration from `reborn:default-loop-v1` → `v2`.** Strict
  schema match per WS-10 §6; v2 is a future PR.
- **Smoke tests against WS-15** (`identity_messages` populated). The
  WS-14 smoke runs with `identity_source = None`. Once WS-15 lands,
  a separate WS-15 smoke covers identity-file injection.
- **Tracing / OpenTelemetry beyond `RuntimeEvent`.** WS-12 ships the
  loop progress surface; metric exporters are sink-side concerns.
