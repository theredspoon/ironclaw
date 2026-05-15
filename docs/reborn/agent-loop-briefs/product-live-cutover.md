# WS-17 — Product Cutover + Live Readiness Evidence

**Workstream:** WS-17
**Crates touched:** `ironclaw_host_runtime` + product entrypoint crates that submit normal turns + `ironclaw_product_workflow` tests
**Depends on:** WS-16
**Master doc:** [`../agent-loop-skeleton.md`](../agent-loop-skeleton.md) §12

---

## 1. Goal

WS-17 is the point where the agent loop becomes live for the product
default path. A normal user-submitted turn, with no explicit run
profile, must enter the WS-16 Reborn runtime composition and run the
planned loop by default.

WS-16 proves the runtime can do this. WS-17 wires the product to do it.

## 2. Scope

1. Wire the product-facing turn submission path to the WS-16 default
   planned runtime composition.
2. Add a readiness check that fails closed when required pieces are
   missing: driver registry entries, implicit planned profile,
   capability surface resolver, model routing, checkpoint stores,
   input queue, progress sink, cancellation source, and identity
   context source.
3. Preserve an explicit text-only or legacy profile path for rollback
   and controlled comparison.
4. Emit enough run evidence to prove the planned loop handled the turn:
   selected run profile, selected driver id, milestone/progress events,
   checkpoint writes, capability execution evidence when a tool is
   requested, and final assistant message persistence.
5. Keep feature-flag or rollout branching at the product composition
   boundary. Do not scatter planned-loop conditionals through host
   adapters or the runner.

## 3. Non-goals

- No removal of legacy text-only runtime support.
- No migration of every named run profile.
- No new capability family or tool policy model.
- No new database schema unless a required readiness or evidence record
  cannot be represented by existing event/checkpoint tables.

## 4. Verification

WS-17 needs product-facing tests because this is the live cutover point.

Required coverage:

1. A normal product turn with no explicit profile uses
   `reborn-planned-default`, runs the planned driver, and persists the
   assistant reply in the product-visible turn/thread state.
2. A tool-using planned-loop turn executes through the host capability
   path and records progress/evidence events.
3. Startup/readiness fails closed when a required adapter is absent or
   misconfigured.
4. An explicit legacy/text-only profile still routes to the legacy
   driver.
5. If the cutover stores new persistent state or config, cover both
   PostgreSQL and libSQL. If it only consumes existing persistence,
   use the existing product-workflow persistence test matrix.

After WS-17 lands with this evidence, it is accurate to say the Reborn
agent loop is live on the default product path.
