# SudoSigil

The unconditional allow-all sigil. The minimal `IActionSigil`: it permits the configured
`(target, selector)` action with any arguments and any ETH value, reading no calldata and holding no
state.

## What it gates

Nothing beyond the action's `(target, selector)` scope itself. A no-policy action is denied (the
engine treats an empty policy list as deny), so even an unconstrained action still needs a policy
attached. The SudoSigil is that policy — the on-chain expression of a no-constraint mandate.

`OmniSigil` could express "any args" with an always-true rule, but every OmniSigil rule reads a fixed
calldata word via a reverting slice, which reverts for a zero-argument call (4-byte calldata). The
SudoSigil sidesteps that: it returns success without ever touching calldata, so it supports
zero-argument functions and any "allow with any args" policy without padding the calldata.

## Config shape

None. The SudoSigil stores no configuration.

## Check semantics

- `checkAction(...)` — always returns `VALIDATION_SUCCESS`. Reads no `data`, enforces no `value` cap.
- `initializeWithMultiplexer(account, configId, data)` — a no-op that emits `SigilSet` so the
  configure step is observable on-chain like any other sigil. Accepts (and ignores) any `initData`,
  including empty `0x`. Because there is nothing to store, an uninitialized and an initialized
  SudoSigil behave identically (always allow) — it has no `PolicyNotInitialized` guard.

## Conformance

Implements `IActionSigil` (`checkAction` + the shared `ISigilBase` config surface). `supportsInterface`
returns true for `IERC165`, `ISigilBase`, and `IActionSigil` only — a pure action sigil with no ERC-1271
(`I1271Sigil`) or outcome (`IOutcomeSigil`) tier.
