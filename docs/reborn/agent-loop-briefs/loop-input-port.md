# WS-11 — `LoopInputPort` Implementation

**Workstream:** WS-11 (follow-up; not in the skeleton WS-0..WS-8 set)
**Crates touched:** `ironclaw_loop_support` (adapter) + host-runtime PR
(concrete `HostInputQueue` backing — out of scope here)
**Depends on:** WS-7 (`PlannedDriver` adapter), WS-8 (skeleton green)
**Parallel with:** WS-9, WS-10, WS-12, WS-13, WS-15
**Master doc:** [`../agent-loop-skeleton.md`](../agent-loop-skeleton.md) §11–§12

---

## 1. Scope

The skeleton today composes a stub `LoopInputPort` (the unnamed
`EmptyLoopInputPort` equivalent — today routed through the
`unsupported_host_method` default at
[`crates/ironclaw_turns/src/run_profile/host.rs:1189`](../../../crates/ironclaw_turns/src/run_profile/host.rs))
into `AgentLoopDriverHost`, so `host.poll_inputs(...)` is unavailable
and the executor's steering-drain step (master doc §8 step 2) is a
no-op. `TextOnlyModelReplyDriver` never polls, so the gap is invisible
for the first slice. `PlannedDriver` (WS-7) does — but until WS-11
lands, every drain returns empty.

WS-11 ships the adapter that bridges the `LoopInputPort` trait to a
host-owned queue substrate:

- A neutral `HostInputQueue` trait owned by `ironclaw_loop_support`,
  modeled on the existing in-memory test fixture at
  [`crates/ironclaw_reborn/tests/loop_driver_host.rs:3360`](../../../crates/ironclaw_reborn/tests/loop_driver_host.rs).
- A `HostQueueLoopInputPort` adapter that implements the
  `LoopInputPort` trait from
  [`host.rs:698`](../../../crates/ironclaw_turns/src/run_profile/host.rs)
  by translating `(LoopInputCursor, limit)` → queue lookup →
  `LoopInputBatch`.

WS-11 does **not** ship the concrete queue backing. The host runtime
already routes user/steering/followup messages through its own
substrate (channels, threads, gateway); plugging that into the
neutral `HostInputQueue` trait is a host-side PR and is intentionally
out of scope. This brief defines only the seam.

Crate ownership (per master doc §12 follow-up rule):

- **Trait + adapter** — `ironclaw_loop_support`. The existing
  adapters there (`ThreadBackedLoopContextPort`,
  `ThreadBackedLoopTranscriptPort`, `ThreadBackedLoopModelPort`,
  `EmptyLoopCapabilityPort` in
  [`crates/ironclaw_loop_support/src/lib.rs`](../../../crates/ironclaw_loop_support/src/lib.rs)) are the templates.
- **Composition wiring** — `ironclaw_reborn` (just a config field on
  `PlannedDriverConfig`).
- **Contract crate** — `ironclaw_turns` is **untouched**. Every type
  the adapter needs (`LoopInputCursor`, `LoopInput*`, `LoopInputBatch`,
  `LoopInputCursorToken`) already exists at `host.rs:623-706`.

## 2. Files

### NEW
- `crates/ironclaw_loop_support/src/input_port.rs` — `HostQueueLoopInputPort`
  adapter implementing `LoopInputPort`.
- `crates/ironclaw_loop_support/src/input_queue.rs` — `HostInputQueue`
  trait, `HostInputBatch` value type, `HostInputQueueError`.

### MODIFIED
- `crates/ironclaw_loop_support/src/lib.rs` — module declarations and
  re-exports.
- `crates/ironclaw_reborn/src/planned_driver.rs` (WS-7 file) —
  `PlannedDriverConfig` gains `Arc<dyn HostInputQueue>`; the driver's
  host-build hook composes `HostQueueLoopInputPort` in.

### NOT TOUCHED
- `crates/ironclaw_turns/**` — contract crate stays clean per its
  CLAUDE.md ("Stay above the Reborn kernel facade").
- `crates/ironclaw_reborn/tests/loop_driver_host.rs` — the in-memory
  fixture stays as a unit-test convenience; new prod code uses the
  adapter from `ironclaw_loop_support`.

## 3. Specification

### 3.1 `HostInputQueue` trait

```rust
//! crates/ironclaw_loop_support/src/input_queue.rs

use async_trait::async_trait;
use ironclaw_turns::run_profile::{LoopInput, LoopInputCursorToken};
use ironclaw_turns::TurnRunId;
use thiserror::Error;

/// Host-owned input queue surface. The host runtime exposes one
/// implementation backed by its actual user-input / steering /
/// followup substrate (channels, threads, gateway). `HostQueueLoopInputPort`
/// adapts this surface to the `LoopInputPort` contract the loop calls.
///
/// Cursor semantics:
///
/// - Tokens are opaque to the loop. Implementations may use a
///   monotonically increasing sequence, a UUID-based generation, or a
///   compound key — the only requirement is that `next_after(run_id,
///   cursor, _)` returns the first input strictly after `cursor` (or
///   an equivalent point if `cursor` was returned by
///   [`origin_input_cursor_token`](../../../crates/ironclaw_turns/src/run_profile/host.rs:635)
///   as the run-start origin).
/// - `ack_through(run_id, cursor)` MUST be at-most-once: acking the
///   same cursor twice is a no-op. The host queue may drop acked
///   inputs from physical storage, but does not have to.
///
/// Lifetime: implementations are per-host-process. Each adapter binds
/// to one `run_id` at host-build time. Cross-run polls are explicitly
/// not supported — the executor only ever consumes its own run's
/// inputs.
#[async_trait]
pub trait HostInputQueue: Send + Sync {
    async fn next_after(
        &self,
        run_id: TurnRunId,
        after: LoopInputCursorToken,
        limit: usize,
    ) -> Result<HostInputBatch, HostInputQueueError>;

    async fn ack_through(
        &self,
        run_id: TurnRunId,
        cursor: LoopInputCursorToken,
    ) -> Result<(), HostInputQueueError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInputBatch {
    pub inputs: Vec<LoopInput>,
    pub next_cursor: LoopInputCursorToken,
}

#[derive(Debug, Error)]
pub enum HostInputQueueError {
    #[error("input queue unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("cursor invalid for run: {reason}")]
    InvalidCursor { reason: String },
    #[error("input queue internal error")]
    Internal,
}
```

`HostInputBatch` mirrors the contract crate's `LoopInputBatch` (at
[`host.rs:665`](../../../crates/ironclaw_turns/src/run_profile/host.rs))
but uses the raw `LoopInputCursorToken` instead of the full
`LoopInputCursor`. The adapter wraps the token in a `LoopInputCursor`
bound to the run context.

### 3.2 Adapter `HostQueueLoopInputPort`

```rust
//! crates/ironclaw_loop_support/src/input_port.rs

use std::sync::Arc;
use async_trait::async_trait;
use ironclaw_turns::run_profile::{
    AgentLoopHostError, AgentLoopHostErrorKind, LoopInputBatch, LoopInputCursor,
    LoopInputPort, LoopRunContext, LoopRunInfoPort,
};
use crate::input_queue::{HostInputQueue, HostInputQueueError};

pub struct HostQueueLoopInputPort {
    queue: Arc<dyn HostInputQueue>,
    run_context: LoopRunContext,    // frozen at host-build time
}

impl HostQueueLoopInputPort {
    pub fn new(queue: Arc<dyn HostInputQueue>, run_context: LoopRunContext) -> Self {
        Self { queue, run_context }
    }
}

#[async_trait]
impl LoopInputPort for HostQueueLoopInputPort {
    async fn poll_inputs(
        &self,
        after: LoopInputCursor,
        limit: usize,
    ) -> Result<LoopInputBatch, AgentLoopHostError> {
        if !after.is_for_run(&self.run_context) {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::Invalid,
                "cursor scope/run_id does not match port's run".to_string(),
            ));
        }

        let host_batch = self
            .queue
            .next_after(self.run_context.run_id, after.token().clone(), limit)
            .await
            .map_err(host_queue_error_into_host_error)?;

        Ok(LoopInputBatch {
            inputs: host_batch.inputs,
            next_cursor: LoopInputCursor::from_host_token(
                &self.run_context,
                host_batch.next_cursor,
            ),
        })
    }

    async fn ack_inputs(&self, cursor: LoopInputCursor) -> Result<(), AgentLoopHostError> {
        if !cursor.is_for_run(&self.run_context) {
            return Err(AgentLoopHostError::new(
                AgentLoopHostErrorKind::Invalid,
                "ack cursor scope/run_id does not match port's run".to_string(),
            ));
        }
        self.queue
            .ack_through(self.run_context.run_id, cursor.token().clone())
            .await
            .map_err(host_queue_error_into_host_error)
    }
}

fn host_queue_error_into_host_error(e: HostInputQueueError) -> AgentLoopHostError {
    match e {
        HostInputQueueError::Unavailable { reason } =>
            AgentLoopHostError::new(AgentLoopHostErrorKind::Unavailable, reason),
        HostInputQueueError::InvalidCursor { reason } =>
            AgentLoopHostError::new(AgentLoopHostErrorKind::Invalid, reason),
        HostInputQueueError::Internal =>
            AgentLoopHostError::new(
                AgentLoopHostErrorKind::Internal,
                "input queue internal error".to_string(),
            ),
    }
}
```

The error-mapping helper is the channel-edge boundary required by
`.claude/rules/error-handling.md`: raw queue errors are collapsed
into the typed `AgentLoopHostError` variants the executor knows how
to consult `RecoveryStrategy` against.

### 3.3 Variant routing

The port emits **every** `LoopInput` variant returned by the queue —
including the four control variants:

- `Interrupt { kind }` (UserInterrupt | HostShutdown)
- `Cancel { reason_kind }` (UserRequested | Superseded | Policy)
- `GateResolved { gate_ref }`
- `CapabilitySurfaceChanged { version }`

The executor (master doc §8 step 2) filters by kind in the steering
drain — only `UserMessage`, `FollowUp`, `Steering` are appended to
state; the four control kinds are observed elsewhere (cancel via
WS-13's cancellation port; capability surface via the per-iteration
surface re-pin; gate resolution via the blocked-run resumer in
§3.3.5).

The port does **not** filter. Stateless about loop policy keeps the
adapter testable and keeps the policy decision in one place.

### 3.3.5 `GateResolved` wakeup path for blocked runs

`GateResolved` is not a steering message. A run that returned
`LoopExit::Blocked` is no longer inside the executor's steering drain,
so filtering the event out of step 2 is only correct if the host has a
separate wakeup path for blocked runs. WS-11 defines that path:

1. Approval/auth/resource subsystems enqueue
   `LoopInput::GateResolved { gate_ref }` for the blocked run when
   the gate clears.
2. The same enqueue operation notifies a host-owned
   `BlockedRunResumer` (name illustrative; the implementation can
   live in the run scheduler / turn coordinator layer).
3. `BlockedRunResumer` claims the blocked run, verifies the cleared
   `gate_ref` matches `LoopExit::Blocked.gate_ref` / the latest
   `BeforeBlock` checkpoint metadata, loads the checkpoint payload via
   WS-10's `load_checkpoint_payload`, and calls `PlannedDriver::resume`.
4. The `GateResolved` cursor is acked only after the resume claim is
   durable. If resume fails before claim, the unacked input is
   redelivered and the resumer retries. If resume starts and later
   returns another `LoopExit::Blocked`, that new blocked exit owns the
   next gate.

This keeps the executor single-purpose: active runs poll inputs during
iteration; blocked runs are re-entered by the host scheduler in
response to a control input. `GateResolved` may still appear in a
normal poll if a gate clears before the executor returns `Blocked`;
the steering drain ignores it because the active capability path has
already observed the capability outcome.

### 3.4 Idempotency contract

Three rules that adapters and queue implementations both honor:

1. **Monotonic cursors per run** — for any sequence of
   `next_after(run_id, c, _)` calls, the returned `next_cursor` is
   either strictly after `c` or equal to `c` if no new inputs are
   available. Never moves backwards.
2. **Polled-but-unacked inputs are redeliverable.** If
   `next_after(run_id, c0, n)` returns `(inputs, c1)` and the caller
   does not ack before crashing, the next call to
   `next_after(run_id, c0, n)` MUST return the same `inputs` (modulo
   later arrivals). Acks are advisory eviction; reads are
   re-runnable. This matches the master doc's resume guarantee.
3. **Ack is at-most-once.** `ack_through(run_id, c)` on a cursor
   already fully acked is a no-op, not an error. Implementations
   typically take `max(stored_ack_cursor, c)` and persist.

These rules are documented on `HostInputQueue` so substrate
implementations have a contract to satisfy. Brief verification
includes explicit tests for each.

### 3.5 Construction binding

`HostQueueLoopInputPort` is constructed **once per claimed run** by
`PlannedDriver` and embeds the `LoopRunContext` for cursor scope
validation. Reusing a port across runs is a programming error — the
scope/run_id check in `poll_inputs`/`ack_inputs` rejects it
defensively.

## 4. Composition in `PlannedDriverConfig`

```rust
//! crates/ironclaw_reborn/src/planned_driver.rs (delta)

pub struct PlannedDriverConfig {
    // ... fields from WS-7, WS-9, WS-10, WS-15 ...
    pub input_queue: Arc<dyn HostInputQueue>,
}

impl PlannedDriver {
    async fn build_input_port(
        &self,
        run_context: &LoopRunContext,
    ) -> Result<Arc<dyn LoopInputPort>, AgentLoopHostError> {
        Ok(Arc::new(HostQueueLoopInputPort::new(
            self.config.input_queue.clone(),
            run_context.clone(),
        )))
    }
}
```

The host runtime's queue implementation is constructed at app-startup
time (it's a singleton across the process) and passed into every
`PlannedDriverConfig`. Per-run binding happens inside the driver's
host build.

## 5. Verification

Unit tests (in `crates/ironclaw_loop_support`):

- `input_port::tests::poll_returns_inputs_in_order` — fake queue with
  three inputs (UserMessage, Steering, FollowUp); poll from origin,
  assert inputs are returned in that order.
- `input_port::tests::poll_after_ack_returns_empty` — poll, ack the
  returned cursor, poll again from the same cursor; assert empty
  batch with the same `next_cursor`.
- `input_port::tests::polled_unacked_input_is_redelivered` — poll
  without acking; poll again from the same `after` cursor; assert
  the same inputs come back. Guards §3.4 rule 2.
- `input_port::tests::ack_idempotent` — ack twice; assert second call
  returns `Ok(())`. Guards §3.4 rule 3.
- `input_port::tests::cursor_for_different_run_is_rejected` — build
  port for `run_id_a`, poll with a cursor scoped to `run_id_b`;
  assert `Invalid` error and that the queue is not touched.
- `input_port::tests::control_inputs_pass_through_unfiltered` — fake
  queue returns `[Cancel, CapabilitySurfaceChanged, Interrupt,
  GateResolved]`; assert all four reach the caller; the port does
  not strip them. Locks §3.3.
- `input_port::tests::host_queue_unavailable_maps_to_unavailable_host_error`
  — fake queue returns `HostInputQueueError::Unavailable`; assert
  `AgentLoopHostErrorKind::Unavailable` on the port.

Integration tests (in `crates/ironclaw_reborn`, gated behind
`ironclaw_agent_loop/test-support` from WS-8):

- `planned_driver_consumes_steering_message_mid_loop` — enqueue
  Steering before iteration 2's `plan_context_request`; drive;
  assert the model port receives a `LoopPromptBundle` whose
  `messages` includes the steering message ref.
- `planned_driver_followup_restarts_after_natural_stop` — first
  iteration emits assistant reply; second iteration's followup drain
  picks up a queued FollowUp; assert a second model call happens
  and the run exits `Completed` only after that drain returns empty.
- `planned_driver_gate_resolved_resumes_blocked_run` — first run
  returns `LoopExit::Blocked` with a `gate_ref` and `BeforeBlock`
  checkpoint; enqueue `GateResolved { gate_ref }`; drive the
  `BlockedRunResumer`; assert it loads the WS-10 checkpoint, calls
  `PlannedDriver::resume`, acks the cursor after claiming resume, and
  reaches `LoopExit::Completed` once the capability succeeds.
- `planned_driver_drains_when_iteration_caps` — queue all 33 inputs;
  assert `LoopFailureKind::IterationLimit` exits cleanly, no panic
  on the unconsumed input cursor.

## 6. Out of scope (for this brief)

- **Concrete queue substrate.** The host's actual implementation
  (probably a `tokio::sync::mpsc`-backed per-thread store, or a
  durable queue in `src/agent/`) is a host-runtime PR. The brief
  defines only the seam.
- **Cross-channel fan-in.** Gateway, CLI, HTTP, Telegram, Slack all
  produce inputs; merging them into a single queue is the substrate's
  job, not the adapter's.
- **Durable replay across host restart.** If `HostInputQueue` is
  in-memory only, a host restart loses unacked inputs. Persistent
  queue impls are encouraged but optional — the loop honors at-most-
  once delivery either way.
- **Priority ordering.** Inputs are FIFO per run; no priority lanes.
  If steering should "jump" in some loop family, the substrate
  inserts at head; the adapter is order-preserving.
- **Backpressure / quotas.** The `limit` parameter on `poll_inputs`
  is advisory; queues may return fewer. Capping the producer is
  substrate concern.
- **Cross-run delivery.** Inputs are addressed to one `run_id`; if a
  user re-submits after a run terminates, the runner promotes the
  new submission into a new run via `TurnCoordinator`. Inputs do
  not move between runs.
