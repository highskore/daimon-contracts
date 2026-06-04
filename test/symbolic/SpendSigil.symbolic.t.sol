// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { SpendSigil } from "@sigils/SpendSigil/SpendSigil.sol";

// Libraries
import { SpendConfig, Period } from "@sigils/SpendSigil/lib/SpendSigilConfigLib.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title SpendSigil_Symbolic_Test — machine-proven ∀-input rolling-meter bound
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) of the {SpendSigil} METER invariant: after a
///         {SpendSigil.postCheck} that does NOT revert, the persisted rolling spend never exceeds the
///         configured cap — `postCheck succeeds ⟹ st.spent <= cap` — over a SYMBOLIC outflow and a
///         SYMBOLIC cap. This is the cumulative-cap safety the sigil exists to enforce.
/// @dev IMPORTANT CAVEAT (machine-proven vs argued). This proves the METER bound `st.spent <= cap`,
///      i.e. the modeled quantity the meter accrues stays under the cap. It does NOT prove
///      `real_outflow <= cap`. Per the sigil's own RESIDUAL NatSpec, an outflow routed through an
///      UNPARSED path (a call to a non-token target that moves the budgeted token) is metered only by
///      the balance delta, which a same-execution inflow can mask — a fundamental two-snapshots
///      limitation, bounded by controls OUTSIDE the meter (blanket-grant blocks, dangling scan, the
///      per-action allowlist), argued not machine-proven. So: `st.spent <= cap` is PROVEN here;
///      `real_outflow <= cap` is the argued mandate-level claim.
///
///      SYMBOLIC BOUND / MODELLING:
///        - NATIVE budget (`token == 0xEeee…EEeE`): the meter charges the call's `value` directly, with
///          no ERC-20 `balanceOf` parse, no approve dangling-scan, and no allowlist read — isolating
///          the accrual+cap logic (`_accrue`) that the bound is about.
///        - A SINGLE ERC-7579 call (callType 0): `executionData = abi.encodePacked(to, value, data)`
///          with a CONCRETE `to`, a SYMBOLIC `value`, and EMPTY `data`. Fixed byte layout (only `value`
///          symbolic) so LibERC7579's single-decode does not branch on length.
///        - `Period.Forever`: no calendar rollover (the calendar math is out of scope of the bound).
///        - Fresh state: no prior `postCheck`, so the period starts at `spent == 0`; with a zero real
///          balance delta the metered outflow is exactly the call `value`, and success ⟹ `value <= cap`
///          ⟹ the stored `st.spent == value <= cap`. The `spent > cap ⟹ revert` guard is what makes
///          the post-success bound hold for ANY symbolic `value`/`cap`.
contract SpendSigil_Symbolic_Test is Test {
    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xC0)));

    /// @dev The NATIVE budget sentinel (mirrors the sigil constant).
    address internal constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    /// @dev A concrete call target for the single execution (value-only native call; data empty).
    address internal constant TO = address(0xD00D);
    /// @dev ERC-7579 single-call mode (call-type byte 0x00).
    bytes32 internal constant MODE_SINGLE = bytes32(0);
    /// @dev ERC-7579 batch mode (call-type byte 0x01).
    bytes32 internal constant MODE_BATCH = bytes32(uint256(1) << 248);

    /// @dev One batch entry, matching solady `LibERC7579`'s `abi.encode(Call[])` batch layout.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    SpendSigil internal sigil;
    /// @dev The harness IS the account/multiplexer (msg.sender == account at runtime, per the sigil).
    address internal account = address(this);

    function setUp() public {
        sigil = new SpendSigil();
    }

    /// @notice ∀ (cap, value): a non-reverting postCheck leaves the persisted spend at or under the cap.
    /// @param cap The symbolic per-period cap.
    /// @param value The symbolic native outflow of the single executed call.
    function check_postCheck_metersUnderCap(uint256 cap, uint256 value) public {
        // Configure a NATIVE budget, symbolic cap, Forever period (no rollover), empty spender list.
        address[] memory spenders = new address[](0);
        SpendConfig memory cfg =
            SpendConfig({ token: NATIVE, cap: cap, period: Period.Forever, spenders: spenders });
        sigil.initializeWithMultiplexer(account, CID, abi.encode(cfg));

        // Snapshot the pre-execution native balance; with no real transfer the delta is 0, so the
        // metered outflow is exactly the symbolic call `value`.
        sigil.preCheck(CID, account);

        // A single native call: abi.encodePacked(to, value, data) with empty data; only `value` symbolic.
        bytes memory executionData = abi.encodePacked(TO, value, bytes(""));

        // If this returns (does not revert SpendCapExceeded), the meter accepted the outflow.
        sigil.postCheck(CID, account, MODE_SINGLE, executionData);

        // The METER bound: the persisted cumulative spend is at or under the cap.
        (uint256 spent,) = sigil.spendStates(CID, account, account);
        assert(spent <= cap);
    }

    /*·:⛧:·──────── CROSS-EXECUTION CUMULATIVE BOUND ────────:⛧:·*/

    /// @dev Configure a NATIVE budget, symbolic cap, Forever period (no rollover), empty spender list.
    ///      Shared setup for the cross-execution proofs below.
    function _initNative(uint256 cap) private {
        address[] memory spenders = new address[](0);
        SpendConfig memory cfg =
            SpendConfig({ token: NATIVE, cap: cap, period: Period.Forever, spenders: spenders });
        sigil.initializeWithMultiplexer(account, CID, abi.encode(cfg));
    }

    /// @dev A single NATIVE call with the given symbolic `value`: `abi.encodePacked(to, value, "")`.
    function _nativeCall(uint256 value) private pure returns (bytes memory) {
        return abi.encodePacked(TO, value, bytes(""));
    }

    /// @notice ∀ (cap, prior, value): with a SYMBOLIC prior spend already accrued IN-PERIOD, a
    ///         non-reverting second {postCheck} still leaves the persisted spend at or under the cap.
    /// @dev This is the HEADLINE cumulative-containment property: the cap bites ACROSS executions, not
    ///      just on a fresh meter. We establish a genuinely symbolic prior `st.spent` by running a FIRST
    ///      `postCheck` with a symbolic `prior` outflow (its own non-revert constrains `prior <= cap`),
    ///      then run the metered SECOND `postCheck` with a symbolic `value`. Both executions are in the
    ///      same `block.timestamp` and the period is `Forever`, so no window rollover resets the meter
    ///      between them — the second charge accrues ON TOP of the first.
    /// @param cap The symbolic per-period cap.
    /// @param prior The symbolic first-execution native outflow (becomes the in-period prior spend).
    /// @param value The symbolic second-execution native outflow.
    function check_postCheck_crossExecution_metersUnderCap(
        uint256 cap,
        uint256 prior,
        uint256 value
    )
        public
    {
        _initNative(cap);

        // First execution: accrue a symbolic `prior` (a non-revert here means `prior <= cap`).
        sigil.preCheck(CID, account);
        sigil.postCheck(CID, account, MODE_SINGLE, _nativeCall(prior));

        // The meter now holds a SYMBOLIC in-period prior spend == prior (<= cap), lastUpdated == now.
        (uint256 spentAfterFirst,) = sigil.spendStates(CID, account, account);

        // Second execution in the SAME block (no rollover) accrues on top of the prior.
        sigil.preCheck(CID, account);
        sigil.postCheck(CID, account, MODE_SINGLE, _nativeCall(value));

        // If the second postCheck returned, the CUMULATIVE persisted spend is still at or under the cap.
        (uint256 spent,) = sigil.spendStates(CID, account, account);
        assert(spent == spentAfterFirst + value); // it accrued on top of the prior (no reset)
        assert(spent <= cap); // and the cumulative total respects the cap
    }

    /// @notice ∀ (cap, prior, value): if `prior + value > cap` (in-period), the second {postCheck} REVERTS.
    /// @dev The contrapositive direction of the headline: the cap does not just hold on success — it
    ///      actively BITES when the cumulative across executions would exceed it. We accrue a symbolic
    ///      `prior` first, assume the in-period sum would breach the cap (and does not overflow), then
    ///      assert the second `postCheck` reverts (the meter rejects the over-cap charge, it does not
    ///      silently clamp or accept it).
    /// @param cap The symbolic per-period cap.
    /// @param prior The symbolic first-execution native outflow.
    /// @param value The symbolic second-execution native outflow.
    function check_postCheck_crossExecution_capBites(
        uint256 cap,
        uint256 prior,
        uint256 value
    )
        public
    {
        _initNative(cap);

        // First execution accrues a symbolic `prior` (non-revert ⟹ prior <= cap).
        sigil.preCheck(CID, account);
        sigil.postCheck(CID, account, MODE_SINGLE, _nativeCall(prior));

        // Exclude the unchecked-arith path: `prior + value` must not overflow uint256 (an overflow would
        // revert too, but for a different reason — we want the CAP to be what bites).
        vm.assume(prior <= type(uint256).max - value);
        // The cumulative would breach the cap.
        vm.assume(prior + value > cap);

        // The second postCheck MUST revert — the cap rejects the over-budget cumulative charge.
        sigil.preCheck(CID, account);
        try sigil.postCheck(CID, account, MODE_SINGLE, _nativeCall(value)) {
            assert(false); // it must not accept a charge that pushes cumulative spend over the cap
        } catch {
            assert(true);
        }
    }

    /*·:⛧:·──────── MULTI-CALL METERING (BATCH) ────────:⛧:·*/

    /// @notice ∀ (cap, v0, v1): a non-reverting batch {postCheck} meters the SUM of the calls' outflows
    ///         against the cap — `SUCCESS ⟹ v0 + v1 <= cap` — on a fresh in-period meter.
    /// @dev Proves the GLOBAL itemizer sums every call in the executed set (not just the first/last): a
    ///      2-call native batch with symbolic per-call values `v0, v1` accrues `v0 + v1`, and a success
    ///      implies that sum respects the cap. Batch size is bounded to 2 (documented): two calls already
    ///      exercise the cross-call summation loop; a larger batch only adds more identical addends and
    ///      would bloat LibERC7579's symbolic batch decode without strengthening the property.
    /// @param cap The symbolic per-period cap.
    /// @param v0 The symbolic native outflow of the first batched call.
    /// @param v1 The symbolic native outflow of the second batched call.
    function check_postCheck_batch_metersSum(uint256 cap, uint256 v0, uint256 v1) public {
        _initNative(cap);

        // Exclude the unchecked-arith revert path so a non-revert is attributable to the cap, not overflow.
        vm.assume(v0 <= type(uint256).max - v1);

        // A 2-call native batch: abi.encode(Call[]) with concrete `to`/empty data, only the values symbolic.
        bytes memory executionData = _nativeBatch2(v0, v1);

        sigil.preCheck(CID, account);
        sigil.postCheck(CID, account, MODE_BATCH, executionData);

        // SUCCESS ⟹ the SUMMED outflow is metered and respects the cap.
        (uint256 spent,) = sigil.spendStates(CID, account, account);
        assert(spent == v0 + v1); // the meter summed BOTH calls (global itemizer)
        assert(spent <= cap); // and the sum respects the cap
    }

    /// @dev A two-call native ERC-7579 batch: `abi.encode(Call[])` matching solady LibERC7579's batch
    ///      layout, both calls to a concrete `TO` with empty data and only the `value`s symbolic.
    function _nativeBatch2(uint256 v0, uint256 v1) private pure returns (bytes memory) {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ to: TO, value: v0, data: bytes("") });
        calls[1] = Call({ to: TO, value: v1, data: bytes("") });
        return abi.encode(calls);
    }

    /*·:⛧:·──────── WINDOW ROLLOVER (CALENDAR MATH) ────────:⛧:·*/

    /// @notice ∀ (cap, prior, value, t1, t2): with `Period.Day`, a {postCheck} run in a LATER day RESETS
    ///         the meter — the persisted spend becomes `value`, not `prior + value`.
    /// @dev Proves the rolling-window reset, the mechanism that lets the cap be a PER-PERIOD budget rather
    ///      than a lifetime one. We accrue a symbolic `prior` at time `t1` (sets `lastUpdated == t1`), warp
    ///      to a `t2` in a strictly later Day window (`startOfPeriod(Day, t2) > t1`), then accrue `value`.
    ///      The `_accrue` rollover test is `lastUpdated < startOfPeriod(period, now)` ⟹ reset to 0, so the
    ///      second charge starts from a zeroed meter.
    ///
    ///      SYMBOLIC BOUND (documented): the period is fixed to `Period.Day`, whose `startOfPeriod` is the
    ///      pure-modular `ts - (ts % DAY)` (no civil-calendar conversion) — tractable for the solver while
    ///      still exercising the real window-boundary comparison. Month/Year rollover (the Howard-Hinnant
    ///      civil-calendar arithmetic) is a far larger symbolic surface and remains DEFERRED (see README).
    ///      Timestamps are bounded to `uint48` (the real block.timestamp field width; ~8.9M years).
    /// @param cap The symbolic per-period cap.
    /// @param prior The symbolic first-window native outflow.
    /// @param value The symbolic second-window native outflow.
    /// @param t1 The symbolic timestamp of the first charge.
    /// @param t2 The symbolic timestamp of the second charge (assumed in a strictly later Day window).
    function check_postCheck_windowRollover_resets(
        uint256 cap,
        uint256 prior,
        uint256 value,
        uint256 t1,
        uint256 t2
    )
        public
    {
        // Real-field-width timestamps; keep the second strictly later for a sane ordering.
        vm.assume(t1 <= type(uint48).max);
        vm.assume(t2 <= type(uint48).max);
        vm.assume(t1 > 0); // a charge always sets lastUpdated > 0 (Forever sentinel aside)

        // Day-budgeted meter, symbolic cap.
        address[] memory spenders = new address[](0);
        SpendConfig memory cfg =
            SpendConfig({ token: NATIVE, cap: cap, period: Period.Day, spenders: spenders });
        sigil.initializeWithMultiplexer(account, CID, abi.encode(cfg));

        // First charge in window 1 at t1.
        vm.warp(t1);
        sigil.preCheck(CID, account);
        sigil.postCheck(CID, account, MODE_SINGLE, _nativeCall(prior));

        // Constrain t2 to a STRICTLY LATER Day window than t1's stored lastUpdated: this is exactly the
        // sigil's rollover predicate `lastUpdated < startOfPeriod(Day, t2)`.
        uint256 startOfT2Day = t2 - (t2 % 86_400);
        vm.assume(t1 < startOfT2Day);

        // Second charge in the new window at t2: the meter must RESET before accruing.
        vm.warp(t2);
        sigil.preCheck(CID, account);
        sigil.postCheck(CID, account, MODE_SINGLE, _nativeCall(value));

        // The reset means the persisted spend is `value` alone — the prior window's spend was dropped.
        (uint256 spent, uint256 lastUpdated) = sigil.spendStates(CID, account, account);
        assert(spent == value); // RESET: not prior + value
        assert(lastUpdated == t2);
    }
}
