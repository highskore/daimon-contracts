# OmniSigil

The generic calldata-argument sigil. Validates a function's calldata arguments against a tree of
rules combined with AND / OR / NOT, with arbitrary nesting. It is the most expressive `IActionSigil`: each
leaf rule checks one calldata argument against a condition and may enforce a cumulative usage limit.
This is what a mandate's recipient-locks, amount caps, and allowlists compile to.

## What it gates

A single `(target, selector)` action (or an ERC-1271 content blob shaped like calldata). Each leaf
rule reads a fixed 32-byte word at `4 + offset` (skipping the selector) and compares it with a
condition. The leaves are wired into a boolean expression tree, so a mandate can require, for
example, `recipient == self AND amountIn <= cap`.

Rule offsets are static: a rule targets a top-level statically-typed argument. It does not reach
values nested inside dynamic ABI data (e.g. the recipient inside a Uniswap UniversalRouter
`execute(bytes,bytes[])` payload), which would need ABI/dynamic-type awareness.

## Config shape

`ActionConfig` (see `lib/OmniSigilTypes.sol`):

- `valueLimitPerUse` — maximum ETH value allowed per action.
- `paramRules` — a `ParamRules` bundle holding the rule set and its expression tree:
  - `rootNodeIndex` — index of the tree's root node.
  - `rules` — the `ParamRule[]` referenced by leaf nodes. Each rule carries a `ParamCondition`
    (EQUAL, GREATER_THAN, LESS_THAN, GREATER_THAN_OR_EQUAL, LESS_THAN_OR_EQUAL, NOT_EQUAL,
    IN_RANGE), a calldata `offset`, an `isLimited` flag, a `ref` value (for IN_RANGE, `ref` packs
    `min << 128 | max`), and a `LimitUsage` (`limit`, `used`) for cumulative accrual.
  - `packedNodes` — the bit-packed tree nodes (RULE / NOT / AND / OR).

Config is stored per `(configId, msg.sender, account)`. The engine is baked into the account, so at
runtime `msg.sender == account`.

## Check semantics

- `checkAction(id, account, target, value, data)` — reverts `PolicyNotInitialized` when the
  `(id, msg.sender, account)` instance has no rules/nodes (default-deny). Reverts `ValueLimitExceeded`
  when `value > valueLimitPerUse`. Otherwise evaluates the expression tree over `data` and returns
  `VALIDATION_SUCCESS` or `VALIDATION_FAILED`. Limited rules accrue usage (an SSTORE).
- `initializeWithMultiplexer(account, configId, initData)` — decodes `ActionConfig`, validates the
  expression tree (`OmniSigilTreeLib.validateExpressionTree`), and replaces the stored config for
  `(configId, msg.sender, account)`. Emits `SigilSet`.

## Conformance

Implements `IActionSigil` (`checkAction` + the shared `ISigilBase` config surface). `supportsInterface`
returns true for `IERC165`, `ISigilBase`, and `IActionSigil` only — it is a pure action sigil with no
ERC-1271 (`I1271Sigil`) or outcome (`IOutcomeSigil`) tier, so placing it in a mandate's signature or
outcome slot reverts `UnsupportedSigil` at bind.

## Layout

- `OmniSigil.sol` — the sigil contract.
- `lib/OmniSigilConfigLib.sol` — owns the per-`(configId, multiplexer, account)` `ActionConfig`
  storage plus the decode/validate/write (`initialize`) and read (`get`) paths the sigil calls.
- `lib/OmniSigilTreeLib.sol` — rule evaluation, tree validation, and node-packing helpers.
- `lib/OmniSigilTypes.sol` — `ActionConfig`, `ParamRules`, `ParamRule`, `LimitUsage`, `ParamCondition`.
