# NativeValueLimitSigil

A composable per-call **native-value (ETH) cap**. A pure `IActionSigil` action gate that enforces only
`value <= limit` on a guarded action — it reads no calldata and runs no argument logic.

## What it gates

The native value (wei) a single guarded action may carry. It is the value-only counterpart to the
argument sigils (OmniSigil): instead of constraining calldata, it caps the ETH attached to the call.
Composed alongside other action sigils so a mandate can bound ETH spend per call without baking a value
limit into each one — e.g. "this action may move at most 0.1 ETH."

Fail-closed by default: an unconfigured entry has `limit == 0`, so it permits only `value == 0` —
identical to the SudoSigil's value behavior for a never-configured instance.

## Config shape

`NativeValueLimitConfig` (abi-decoded from `initData`):

- `limit` — the maximum native value (wei) one guarded action may carry. `0` permits only `value == 0`
  (no ETH).

Stored per `(configId, multiplexer, account)`; a re-init overwrites the prior limit.

## Check semantics

- `checkAction(id, account, target, value, data)` — returns `VALIDATION_SUCCESS` iff `value <= limit`
  for `(id, msg.sender, account)`. Reads no `data` — native value is the only constraint.
- `initializeWithMultiplexer(account, configId, initData)` — decodes `NativeValueLimitConfig` (a single
  `uint256 limit`), stores it for `(configId, msg.sender, account)`, emits `SigilSet`.

View helper: `limitOf(id, multiplexer, account)`.

## Conformance

Implements `IActionSigil` (`checkAction` + the shared `ISigilBase` config surface). `supportsInterface`
returns true for `IERC165`, `ISigilBase`, and `IActionSigil` only — a stateless per-call action gate
with no ERC-1271 (`I1271Sigil`) or outcome (`IOutcomeSigil`) tier. A signature carries no native value,
so it does not gate signing.

## Layout

- `NativeValueLimitSigil.sol` — the sigil contract (the `value <= limit` gate).
- `lib/NativeValueLimitConfigLib.sol` — owns the per-`(configId, multiplexer, account)` `NativeValueLimitConfig`
  storage plus the decode/write + read paths; declares `NativeValueLimitConfig`.
