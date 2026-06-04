# Symbolic verification (Halmos) — issue #106

Machine-proven **∀-input** safety for the sigil gate layer, using
[Halmos](https://github.com/a16z/halmos) (bounded symbolic execution, Foundry-flavored). Halmos
runs `forge build`, then symbolically executes every function named `check_*`: each parameter is a
symbolic value and Halmos proves the body's `assert`s hold for **all** inputs (or returns a concrete
counterexample). This is stronger than fuzzing — there is no sampling; a `[PASS]` means *no input
exists* that violates the property, within the documented bounds.

The toolchain landing added the two simplest gate proofs + a non-blocking CI job. A follow-up added
the next wave of ∀-input proofs (SudoSigil, the Eip3009/Attestation 1271 anchors, a RESTRICTED OmniSigil
arg-policy proof, and the SpendSigil meter bound), worked easiest→hardest. This wave DEEPENS the
SpendSigil coverage — the most security-critical sigil, the cumulative spend cap that contains a runaway
agent across MANY actions — with three new machine-proven properties beyond the single-call meter bound:
the **cross-execution cumulative bound** (the cap bites across executions, both success and revert
directions), **multi-call metering** (a batch's outflows are summed against the cap), and the
**Day window rollover** (the meter resets in a new period).

## Pinned tool + invocation

- **Halmos `0.3.3`** (pinned). Install with either:
  ```sh
  uv tool install 'halmos==0.3.3'      # preferred
  pipx install 'halmos==0.3.3'
  ```
  Halmos brings its own SMT solvers (z3, yices). Confirm with `halmos --version` → `halmos 0.3.3`.

- Run the suite from `contracts/`:
  ```sh
  halmos --match-contract 'Symbolic_Test' --function check_
  ```
  Run a single proof, e.g.:
  ```sh
  halmos --contract TimeFrameSigil_Symbolic_Test --function check_checkAction_iff_inWindow
  ```

Halmos reuses this repo's `foundry.toml` + `remappings.txt`, so the `@sigils/`, `@interfaces/`
aliases resolve exactly as in `forge`. The `check_*` functions are **invisible to `forge test`**
(they are not `test*`-prefixed), so they never run in the normal Foundry suite — only under Halmos.

## Symbolic bounds chosen (and why)

The two original gate sigils (TimeFrame, NativeValueLimit) and SudoSigil read **no calldata, no loops, no
arrays** — the symbolic surface is a handful of scalars, so the global `--loop` / `--array-lengths`
bounds do not bite. Explicit bounds per proof:

- **TimeFrame — `block.timestamp` constrained to `uint48`** (`vm.assume(nowTs <= type(uint48).max)`).
  The config bounds `validAfter` / `validUntil` are `uint48` (the real field width), and the sigil only
  ever compares `now` against those `uint48` bounds. A `now` above `2**48 - 1` is uninteresting (it
  is strictly greater than every possible bound, so always "after the window") and would only bloat
  the solver. `2**48` seconds is ~8.9 million years past the unix epoch — far beyond any real timestamp.

- **Sudo / Attestation / Eip3009 — `bytes` payloads.** The opaque `data`/`content`/`inner` blobs are
  bounded by Halmos's global `--default-bytes-lengths` ({0, 32, 1024}). SudoSigil reads NONE of its
  calldata, so the bound is irrelevant to its always-allow property. For the 1271 sigils the
  semantically-meaningful fields are recovered from FIXED-WIDTH symbolic scalars (see each file), so
  the dynamic-length bound never gates the property.

- **Eip3009 — fields-not-bytes modelling.** The EIP-3009 `inner` blob is, by the sigil's own contract,
  EXACTLY six static words (`_CONTENT_LEN == 0xc0`; any other length is rejected before decode). The
  proof makes the six FIELDS symbolic scalars and rebuilds `inner` in-harness — a faithful 1:1 model of
  every decodable authorization (malformed/short blobs hit the fail-closed length deny, covered by the
  unit suite). The payee allowlist is bounded to ONE symbolic payee (a larger set only adds disjuncts).

- **Attestation — single-entry allowlists.** Each allowlist is bounded to one symbolic entry (`length
  == 1`); one entry proves the membership gate (`x == entry ⇔ allowed`). Reserved zero-sentinels are
  excluded via `vm.assume` (an unaddable value the sigil guards explicitly).

- **OmniSigil — FIXED-SHAPE calldata + single-leaf tree (RESTRICTED).** Calldata is fixed at 36 bytes
  (concrete 4-byte selector ++ one SYMBOLIC 32-byte word) and the rule tree is a single leaf. The arg
  word is fully symbolic (2^256 values); only the length is concrete so the static `data[4:36]` slice
  is well-defined. The general N-rule AND/OR/NOT tree over fully symbolic dynamic-length calldata is
  DEFERRED (see below) — it blows up the solver.

- **SpendSigil — NATIVE budget, single call, `Period.Forever`, fresh state.** A native budget avoids
  the ERC-20 `balanceOf` parse, the dangling scan, and the allowlist read; a single fixed-shape call
  (`abi.encodePacked(to, value, "")`, only `value` symbolic) keeps LibERC7579's decode from branching
  on length; `Forever` skips the calendar math. This isolates the accrual+cap logic the meter bound is
  about. See the caveat in the proven table.

- **SpendSigil — cross-execution & multi-call bounds (NATIVE budget).** The cumulative-containment
  proofs (`check_postCheck_crossExecution_*`) establish a genuinely SYMBOLIC in-period prior spend by
  running a FIRST `postCheck` with a symbolic outflow (its non-revert constrains `prior <= cap`), then
  meter a second symbolic `postCheck` in the SAME block — so the cap is proven to bite ACROSS
  executions, not only on a fresh meter. The multi-call proof (`check_postCheck_batch_metersSum`)
  bounds the batch to **2 native calls** with symbolic per-call values: two calls already exercise the
  global itemizer's cross-call summation loop; a larger batch only adds more identical addends (and
  bloats LibERC7579's symbolic batch decode) without strengthening the property. All native, so the
  ERC-20 parse/dangling-scan/allowlist stay out of scope; `prior + value` (and `v0 + v1`) are
  `vm.assume`d not to overflow so a non-revert is attributable to the CAP, not to checked-arith.

- **SpendSigil — window rollover bounded to `Period.Day`.** The rollover-reset proof
  (`check_postCheck_windowRollover_resets`) is bounded to **`Period.Day`**, whose `startOfPeriod` is the
  pure-modular `ts - (ts % 86400)` (no civil-calendar conversion) — tractable for the solver while
  still exercising the REAL window-boundary comparison `lastUpdated < startOfPeriod(period, now)`.
  Timestamps are bounded to `uint48` (the real block.timestamp field width; ~8.9M years). It accrues a
  symbolic `prior` at a symbolic `t1`, warps to a symbolic `t2` constrained to a strictly later Day
  window, and proves the meter RESETS (persisted spend becomes `value`, not `prior + value`). The
  Month/Year rollover (Howard-Hinnant civil-calendar arithmetic) is a far larger symbolic surface and
  remains DEFERRED (see below).

Solve time is sub-second per proof (see `paths:` in the Halmos output).

## What is machine-PROVEN here

| Proof (`check_*`) | Sigil | Property proven (∀ symbolic inputs) |
|---|---|---|
| `check_checkAction_iff_inWindow(uint48 validAfter, uint48 validUntil, uint256 now)` | `TimeFrameSigil` | `checkAction` SUCCESS **⇔** `(now >= validAfter) AND (validUntil == 0 OR now <= validUntil)`. Both directions of the iff, both config sentinels: `validUntil == 0` = no upper bound; `validAfter > validUntil` (validUntil ≠ 0) = unsatisfiable window (deny at every `now`). Return is strictly two-valued. |
| `check_checkAction_success_implies_underCap(uint256 limit, uint256 value)` | `NativeValueLimitSigil` | A configured cap permits the action **⇔** `value <= limit` (headline `SUCCESS ⟹ value <= limit` + converse). Return is strictly two-valued. |
| `check_checkAction_default_denies_nonzeroValue(uint256 value)` | `NativeValueLimitSigil` | Fail-closed default: a **never-configured** entry (`limit == 0`) permits **only** `value == 0`. |
| `check_checkAction_always_succeeds` / `check_check1271_always_succeeds` / `check_uninitialized_succeeds` | `SudoSigil` | The allow-all contract: ∀ inputs both `checkAction` and `check1271` return SUCCESS, configured **or** never-configured (no `PolicyNotInitialized` guard). |
| `check_check1271_success_implies_anchored(Sym)` | `Eip3009Sigil` | **1271 soundness anchor.** `check1271` SUCCESS **⟺** `keccak(TYPEHASH, from,to,value,va,vb,nonce) == contentsHash` (decoded fields bound to the solady-verified signed value) **AND** `sender == token` **AND** `appDomainSeparator == domain` **AND** `from == account` **AND** `to == allowlisted payee` **AND** `value <= cap`. ∀ symbolic fields + config. Bound: fields-as-scalars (faithful 1:1 model of the 6-word `inner`), single-payee allowlist. `check_checkAction_always_denies` proves the signature-only sigil never gates an action. |
| `check_check1271_withHashAllowlist` / `check_check1271_anySenderNoHashAllowlist` | `AttestationSigil` | A pinned-digest config: SUCCESS **⟺** `sender == allowedSender` AND `hash == allowedHash` (the **REAL** signed hash, not the `innerContent` blob); and an `ANY_SENDER` + empty-hash config never denies. ∀ symbolic sender/hash/inner. Bound: single-entry allowlists. `check_checkAction_always_denies` covers the action path. |
| `check_checkAction_recipientLock_notBypassable(bytes32 locked, bytes32 arg)` | `OmniSigil` (**RESTRICTED**) | A recipient-locked EQUAL leaf permits the action **⟺** `arg == locked` — no calldata word can bypass the lock. Bound: FIXED 36-byte calldata (selector ++ one symbolic word), single-leaf tree. |
| `check_checkAction_limitedRule_boundsUsage(uint256 limit, uint256 arg)` | `OmniSigil` (**RESTRICTED**) | The `LimitUsage` bound: a single limited rule (`used == 0`) permits **⟺** `param <= limit` (SUCCESS ⟹ `used + param <= limit`). Same fixed-shape bound. |
| `check_postCheck_metersUnderCap(uint256 cap, uint256 value)` | `SpendSigil` | **Meter bound:** a non-reverting `postCheck` leaves `st.spent <= cap`, ∀ symbolic outflow + cap. **CAVEAT (machine-proven vs argued):** this proves the **METER** quantity `st.spent <= cap`, NOT `real_outflow <= cap` — an outflow via an unparsed path is metered only by the maskable balance delta (the sigil's RESIDUAL), bounded by controls OUTSIDE the meter (argued, not proven). Bound: NATIVE budget, single fixed-shape call, `Forever`, fresh state. `check_checkAction_reverts` proves the outcome-only `checkAction` always reverts. |
| `check_postCheck_crossExecution_metersUnderCap(uint256 cap, uint256 prior, uint256 value)` | `SpendSigil` | **Cumulative containment (headline).** With a SYMBOLIC in-period prior spend (set by a first `postCheck`, so `prior <= cap`), a non-reverting SECOND `postCheck` leaves `st.spent == prior + value <= cap` — the cap bites ACROSS executions, not just on a fresh meter. Same caveat as the meter bound (METER quantity, not `real_outflow`). Bound: NATIVE, single fixed-shape call ×2 in one block (no rollover). |
| `check_postCheck_crossExecution_capBites(uint256 cap, uint256 prior, uint256 value)` | `SpendSigil` | **Cumulative containment (contrapositive).** With a symbolic in-period `prior` already accrued, the second `postCheck` REVERTS whenever `prior + value > cap` (no overflow) — the cap actively rejects an over-budget cumulative charge, it does not silently clamp/accept. Same bound. |
| `check_postCheck_batch_metersSum(uint256 cap, uint256 v0, uint256 v1)` | `SpendSigil` | **Multi-call metering.** A 2-call NATIVE batch with symbolic per-call values accrues `v0 + v1` (the GLOBAL itemizer sums BOTH calls), and SUCCESS ⟹ `v0 + v1 <= cap`. Bound: batch size 2, NATIVE, fresh in-period meter, `v0 + v1` `vm.assume`d not to overflow. |
| `check_postCheck_windowRollover_resets(uint256 cap, uint256 prior, uint256 value, uint256 t1, uint256 t2)` | `SpendSigil` | **Window rollover (calendar math).** With `Period.Day`, a `postCheck` in a STRICTLY LATER day window (`lastUpdated < startOfPeriod(Day, t2)`) RESETS the meter — `st.spent` becomes `value`, not `prior + value`, and `lastUpdated == t2`. Bound: `Period.Day` (pure-modular `startOfPeriod`, not the civil-calendar Month/Year path), `uint48` timestamps, NATIVE single call. |

Each proof was also **falsification-checked**: mutating the spec makes Halmos report a counterexample,
confirming the assertions are not vacuous. Verified mutations: `value <= limit → value < limit`
(NativeValueLimit/Omni), `SUCCESS → !SUCCESS` (Sudo), dropping the `structHash == contentsHash` anchor term
(Eip3009), dropping the `hash == allowedHash` term (Attestation), `spent <= cap → spent < cap`
(SpendSigil meter bound), `spent <= cap → spent < cap` on the cross-execution cumulative bound (the
cumulative may EQUAL the cap), weakening the cap-bites breach assumption `prior + value > cap →
prior + value >= cap` (the `== cap` case does NOT revert), `spent == v0 + v1 → spent == v0` on the
batch proof (the meter sums BOTH calls, so claiming only the first fails when `v1 > 0`), and
`spent == value → spent == prior + value` on the rollover proof (the meter genuinely resets, so
claiming no-reset fails when `prior > 0`) — each yields a concrete counterexample.

## Deferred targets (follow-up sub-PRs)

What remains intractable for bounded symbolic execution within a sane bound/time, with the reason:

- **OmniSigil — GENERAL rule tree over fully symbolic dynamic calldata.** The proven OmniSigil
  properties are RESTRICTED to a fixed-shape 36-byte calldata + a single-leaf tree (see above). The
  general case — an arbitrarily-shaped AND/OR/NOT tree (recursive packed-node interpreter) over
  variable-length symbolic `bytes calldata` with the static-offset slice `data[4+offset:36+offset]` —
  blows up the solver: symbolic slicing of variable-length bytes combined with the recursive tree
  walk explodes the path count. Needs a tool with first-class dynamic-bytes reasoning (e.g. Certora),
  or a much larger time budget with carefully staged `--loop` / `--array-lengths` bounds.
- **SpendSigil — `real_outflow <= cap` (vs the proven `st.spent <= cap`).** This is NOT attempted here
  and remains a SYSTEM-level **argued residual**, NOT machine-provable on the sigil alone. The meter
  bound (and now the cumulative/multi-call/rollover bounds) prove the METER quantity `st.spent <= cap`;
  the stronger real-outflow claim is the sigil's documented RESIDUAL — an outflow routed through an
  UNPARSED path is metered only by the maskable balance delta (two snapshots yield only the NET
  change), bounded by controls OUTSIDE the meter (blanket-grant blocks, the dangling scan, the
  per-action allowlist, and the bounded-agent threat model). Proving it requires reasoning over the
  WHOLE account (balance deltas of arbitrary external calls, the full ERC-7579 batch decode, ERC-20
  `balanceOf` external calls) — a whole-account Certora model, beyond any tractable Halmos bound on the
  sigil in isolation.
- **SpendSigil — Month/Year window rollover (civil-calendar math).** The Day rollover is now
  machine-proven (`check_postCheck_windowRollover_resets`, pure-modular `startOfPeriod`). The
  Minute/Hour/Week boundaries are likewise pure-modular and follow the same argument; the
  Month/Year boundaries go through the Howard-Hinnant civil-calendar conversion (`_toDate`/`_toTimestamp`,
  integer division chains over a `uint48`-wide timestamp), a far larger symbolic surface that remains
  deferred. The reset PREDICATE itself (`lastUpdated < startOfPeriod(period, now)`) is identical across
  all periods and is exercised by the Day proof; only the `startOfPeriod` arithmetic differs.
- **Certora (stretch)** — a Certora Prover spec as a second, independent prover for the headline gate
  invariants and for the dynamic-bytes cases Halmos cannot reach, beyond Halmos.

**Now proven (moved out of deferred):** SudoSigil, Eip3009Sigil (1271 anchor), AttestationSigil (1271
anchor), OmniSigil (RESTRICTED), SpendSigil (meter bound **+ cross-execution cumulative bound,
multi-call metering, Day window rollover**), NativeValueLimitSigil, TimeFrameSigil — see the table above. The
only SpendSigil properties that remain deferred are `real_outflow <= cap` (an argued system-level
residual, not machine-provable on the sigil alone — see above) and the Month/Year civil-calendar
rollover.

## CI

A non-blocking `symbolic (halmos)` job in `.github/workflows/ci.yml` installs pinned Halmos and runs
this suite (it auto-discovers every `check_*` function, so the new proofs are picked up). It is
`continue-on-error: true` (proofs run + report but do not gate merges). Flip it to a required gate
once the remaining deferred targets above land.
