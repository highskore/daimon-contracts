# RateLimitSigil

A stateful per-call **action-frequency cap**. An `IActionSigil` that bounds how OFTEN a guarded action may
fire: at most `maxActions` per rolling `windowSeconds`, plus an optional `minCooldownSeconds` minimum gap
between consecutive actions.

## What it gates

The **rate** (count over time) at which a guarded action may execute — not its value or its arguments. It is
the frequency counterpart to the value caps (`SpendSigil`, `NativeValueLimitSigil`): those bound how MUCH an
agent moves; this bounds how OFTEN it acts. It closes the gap where a looping or compromised agent stays under
the value cap yet fires unbounded actions — burning gas, churning positions, or repeatedly probing a slippage
edge. Composed alongside the value/arg sigils so a mandate can bound an action's cadence, e.g.
`[OmniSigil(...) + RateLimitSigil(maxActions, windowSeconds, cooldown)]`.

Fail-closed by default: an unconfigured entry has `windowSeconds == 0`, so `checkAction` reverts
`PolicyNotInitialized` — an action is denied until a real config is bound.

## Window semantics (read this)

This is a **fixed / tumbling window**, anchored at the **first action** in each window — **not** a true
sliding window. After the first action at `t0`, the window is `[t0, t0 + windowSeconds)`; the first action at
or after `t0 + windowSeconds` opens a fresh window (count reset to 0, anchor re-set to `now`). The honest cost:
up to `2·maxActions` actions can occur across a single `windowSeconds`-length span that straddles a boundary
(the tail of one window plus the head of the next). A true sliding window would need unbounded per-action
timestamp storage — out of scope. This mirrors `SpendSigil`'s reset-on-rollover model. The
`minCooldownSeconds` gap is the complementary control that smooths bursts WITHIN a window.

## Config shape

`RateLimitConfig` (abi-decoded from `initData`):

- `maxActions` (`uint32`) — max actions permitted per rolling window. MUST be non-zero (a zero cap would deny
  everything); rejected at config time with `InvalidMaxActions`.
- `windowSeconds` (`uint32`) — rolling window length in seconds. MUST be non-zero; rejected with
  `InvalidWindow`.
- `minCooldownSeconds` (`uint32`) — minimum seconds between two consecutive permitted actions. `0` disables
  the cooldown (only the per-window count applies).

Stored per `(configId, multiplexer, account)`; a re-init overwrites the prior config but does **not** reset
the rolling state (so a re-bind can't clear an exhausted window — a fresh window is reached only by time
elapsing).

## State

`RateLimitState` per `(configId, multiplexer, account)`, persisted across executions:

- `windowStart` (`uint32`) — unix-seconds anchor of the current window (the first action's time in it).
- `count` (`uint32`) — actions charged within the current window.
- `lastActionAt` (`uint32`) — unix-seconds timestamp of the last permitted action (drives the cooldown).

## Check semantics

- `checkAction(id, account, target, value, data)` — after rolling the window when
  `now ≥ windowStart + windowSeconds`, returns `VALIDATION_SUCCESS` iff `count < maxActions` AND
  (`minCooldownSeconds == 0` || `now − lastActionAt ≥ minCooldownSeconds`). On a pass it charges the action
  (`++count`, `lastActionAt = now`); on a reject it returns `VALIDATION_FAILED` **without** mutating state (a
  denied action is not counted, so probing the limit can't burn the budget). Reads none of `target` / `value`
  / `data` — only the action's occurrence matters. Reverts `PolicyNotInitialized` for an unconfigured entry.
- `initializeWithMultiplexer(account, configId, initData)` — decodes `RateLimitConfig`, rejects a zero
  `maxActions`/`windowSeconds`, stores it for `(configId, msg.sender, account)`, emits `SigilSet`.

View helpers: `configs(id, multiplexer, account)`, `states(id, multiplexer, account)`.

## Conformance

Implements `IActionSigil` (`checkAction` + the shared `ISigilBase` config surface). `supportsInterface`
returns true for `IERC165`, `ISigilBase`, and `IActionSigil` only — a per-call action gate with no ERC-1271
(`I1271Sigil`) or outcome (`IOutcomeSigil`) tier. A signature carries no notion of an executed action, so a
frequency cap cannot gate signing.

## Layout

- `RateLimitSigil.sol` — the sigil contract (the rolling-window + cooldown gate; writes state in `checkAction`).
- `lib/RateLimitConfigLib.sol` — owns the per-`(configId, multiplexer, account)` `RateLimitConfig` +
  `RateLimitState` storage plus the decode/write + read paths; declares `RateLimitConfig` and `RateLimitState`.
