# SpendSigil

A stateful, rolling-window spend cap. A PURE per-execution `IOutcomeSigil` that meters one ERC-20's
net outflow from the account against a cap that resets on a rolling window.

## What it gates

The cumulative outflow of one budgeted ERC-20 over a rolling period, plus the approval surface on
that token. It closes the approval-bypass gap: `postCheck` itemizes EVERY executed call (the ERC-7579
set it is handed) and sums each transfer/approve outflow of the budgeted token GLOBALLY, and, as a
backstop, the real balance delta is charged via `max(calldata-sum, balanceBefore - balanceAfter)`, so
an outflow the calldata parse undercounts (an unparsed target, a flash-loan trick) is still metered.
Approvals named by the calls must net back to zero by the end of the execution — an approval is
charged to the budget yet can never dangle to be pulled out-of-band.

Because the calldata sum is computed globally from the executed call set, it is complete for DIRECT
budgeted-token outflows regardless of which action sigils gate the calls — this is a PURE outcome sigil.
The prior model built the sum from a per-call `checkAction` attached to each value-bearing action; an
ungated value-bearing action could then leave the sum incomplete and a same-execution inflow could mask
the resulting outflow in the balance delta. Itemizing the whole call set in `postCheck` closes that gap
for direct outflows, so attachment is irrelevant.

Residual (by design): an outflow routed through an UNPARSED path — a non-token target that moves the
budgeted token (e.g. a pre-approved pull sink) — is metered only by the maskable balance delta, not the
calldata sum. This is fundamental (two balance snapshots give only the net for flows the parse can't see)
and matches the prior model. It is bounded outside the meter: a bounded agent cannot establish the pull
authority such a sink needs (an in-batch grant is parsed + charged here; blanket grants revert; a dangling
allowance reverts), so it requires a ROOT-granted standing allowance — and ROOT is unconstrained by design.

It is accordingly a PURE outcome sigil (`IOutcomeSigil` only): it implements neither the per-call action gate
nor the ERC-1271 signature gate and advertises only the outcome tier, so placing it in a mandate's action or
signature slot reverts `UnsupportedSigil` at bind. It must only ever be installed in the OUTCOME tier.

## Config shape

`SpendConfig` (abi-decoded from `initData`):

- `token` — the budgeted ERC-20 whose outflow is metered (zero address rejected at config time).
- `cap` — maximum cumulative outflow of `token` per `period`.
- `period` — the rolling window the cap resets on (`Minute`, `Hour`, `Day`, `Week`, `Month`, `Year`,
  `Forever`; `Forever` never resets).
- `spenders` — a reserved approve-allowlist field. It is currently INERT on-chain: it formerly gated the
  `approve` spender on the stateless ERC-1271 (`check1271`) ceiling, which this sigil no longer exposes (it is
  a pure outcome sigil). It is retained in the config struct (storage + SDK encoding shape unchanged) and may
  be re-consumed by a future tier. On the execution path `approve`/`increaseAllowance` are metered +
  dangling-scanned (bounded by the cap), not spender-allowlisted.

Persistent `SpendState` (`spent`, `lastUpdated`) tracks the rolling accounting per
`(configId, msg.sender, account)`. The only per-execution transient state is the pre-execution balance
snapshot, in EIP-1153 transient storage keyed by `(account, msg.sender, token)` — the budgeted token.
The calldata-summed outflow and the approve-spender set are computed in `postCheck` directly from the
executed call set (no transient accumulation).

## Check semantics

- `preCheck(id, account)` — snapshots the pre-execution balance (re-snapshotted each call, so two
  executions bracketed in one transaction never leak). Reverts `PolicyNotInitialized` if the token is
  unset.
- `postCheck(id, account, mode, executionData)` — decodes the executed ERC-7579 call set and itemizes
  it GLOBALLY: it sums each call's budgeted-token outflow by selector (`transfer`, `transferFrom` from
  the account, `approve`, `increaseAllowance`) and reverts on grants that escape the meter: a Permit2-approve
  of the budgeted token (`Permit2GrantBlocked`) and the blanket-grant primitives `permit` /
  `setApprovalForAll` / `authorizeOperator` on the budgeted token (`BlanketGrantBlocked`) — each grants pull
  authority the ERC-20 `allowance` dangling-scan cannot see. It then computes
  `outflow = max(calldata-sum, balance delta)`, rolls the period, accrues into `SpendState`, and
  reverts `SpendCapExceeded` if it would breach the cap. Finally it scans every spender the calls
  approved and reverts `DanglingAllowance` if any allowance is non-zero.
- `initializeWithMultiplexer(account, configId, initData)` — decodes `SpendConfig`, rejects a zero
  token (`InvalidToken`), stores it for `(configId, msg.sender, account)`, emits `SigilSet`.
- `startOfPeriod(period, ts)` — rounds `ts` down to the start of its window (the boundary the cap
  resets on); returns 0 for `Forever`.

## Conformance

Implements `IOutcomeSigil`, which extends `ISigilBase`. `supportsInterface` returns true for `IERC165`,
`ISigilBase`, and `IOutcomeSigil` only. It carries the per-execution `preCheck`/`postCheck` outcome hooks
and is a PURE outcome sigil — no action (`IActionSigil`) or signature (`I1271Sigil`) tier.

## Layout

- `SpendSigil.sol` — the sigil contract (outcome hooks, global call-set itemizer, balance snapshot, period math).
- `lib/SpendSigilConfigLib.sol` — owns the per-`(configId, multiplexer, account)` `SpendConfig` and
  rolling `SpendState` storage plus the decode/write (`initialize`) and read (`getConfig`, `getState`)
  paths the sigil calls; also declares `Period`, `SpendConfig`, `SpendState`. The per-execution
  balance snapshot (transient) stays in the sigil.
