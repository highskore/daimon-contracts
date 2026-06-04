# TimeFrameSigil

The time-window sigil. An `IActionSigil` + `I1271Sigil` (the one sigil that serves both tiers) that
permits its `(target, selector)` action — and gates the ERC-1271 signing path — only while
`block.timestamp` is inside a configured `[validAfter, validUntil]` window, reading no calldata.

## What it gates

The validity window of a mandate's action. In Daimon "everything is a sigil": time bounds are just
another sigil attached to the action(s), enforced per-action at check time rather than as a special
field in the mandate-bind digest. It is the sigil-shaped replacement for the old baked-in mandate
`validUntil` field.

## Config shape

`TimeFrameConfig` (abi-decoded from `initData`):

- `validAfter` (`uint48`) — earliest `block.timestamp` (inclusive) the action is allowed at. `0` means
  no lower bound.
- `validUntil` (`uint48`) — latest `block.timestamp` (inclusive) the action is allowed at. `0` is the
  sentinel for no upper bound — the action never expires.

Stored per `(configId, msg.sender, account)`. The engine is baked into the account, so at runtime
`msg.sender == account`.

A window with `validAfter > validUntil` (and `validUntil != 0`) is unsatisfiable — it would permit the
action at no timestamp. Such a config is **rejected at init** (`initializeWithMultiplexer` reverts
`UnsatisfiableWindow`) rather than binding a permanently-inert mandate. `validUntil == 0` is the
open-ended sentinel and is always accepted.

## Check semantics

- `checkAction(id, account, target, value, data)` — `view`. Returns `VALIDATION_SUCCESS` iff
  `block.timestamp >= validAfter` and (`validUntil == 0` or `block.timestamp <= validUntil`);
  otherwise `VALIDATION_FAILED`. Reads no `data`, enforces no `value` cap.
- `check1271(id, account, content)` — `view`. Mirrors `checkAction` on the ERC-1271 path: a signed
  message authorized under this policy is only valid inside the window. Reads no `content`.
- `initializeWithMultiplexer(account, configId, initData)` — decodes `TimeFrameConfig`, stores it for
  `(configId, msg.sender, account)`, emits `SigilSet`. Accepts any satisfiable window, including the
  open-ended `(0, 0)` and any `validUntil == 0`; reverts `UnsatisfiableWindow` on `validAfter > validUntil`
  with a real `validUntil`.

## Conformance

Implements BOTH `IActionSigil` (`checkAction`) and `I1271Sigil` (`check1271`), plus the shared
`ISigilBase` config surface. `supportsInterface` returns true for `IERC165`, `ISigilBase`,
`IActionSigil`, and `I1271Sigil`. Not an `IOutcomeSigil` — no pre/post hooks.

## Layout

- `TimeFrameSigil.sol` — the sigil contract.
- `lib/TimeFrameConfigLib.sol` — owns the per-`(configId, multiplexer, account)` `TimeFrameConfig`
  storage plus the decode/write (`initialize`) and read (`get`) paths the sigil calls; also declares
  `TimeFrameConfig`.
