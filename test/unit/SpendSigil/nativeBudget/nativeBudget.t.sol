// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SpendSigil_Unit_Test } from "../SpendSigil.t.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title SpendSigil native (ETH) budget Unit Tests
/// @author highskore.eth
/// @notice The NATIVE-sentinel budget: {postCheck} sums each executed call's `value` GLOBALLY across the call
///         set and enforces the cap once under the per-MANDATE id. The headline test is the cross-call
///         regression — multiple value-bearing calls in one execution must SHARE one budget, summed from the
///         call set itself (no per-call attachment).
contract SpendSigil_nativeBudget_Unit_Test is SpendSigil_Unit_Test {
    /// @dev The canonical native-asset sentinel (mirrors `SpendSigil.NATIVE`, which is private).
    address internal constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    uint256 internal constant T0 = 1_700_000_000;

    function setUp() public override {
        super.setUp();
        vm.warp(T0);
    }

    /// @dev Configure a native budget (token = NATIVE) for `cid` with `cap` + `period`.
    function _initNative(ConfigId cid, uint256 cap, Period period) internal {
        address[] memory spenders = new address[](0); // native has no approvals
        SpendConfig memory cfg =
            SpendConfig({ token: NATIVE, cap: cap, period: period, spenders: spenders });
        spendSigil.initializeWithMultiplexer(account, cid, abi.encode(cfg));
    }

    /// @dev A two-entry native batch carrying `v1` then `v2` of `value` (no calldata).
    function _twoNativeCalls(
        uint256 v1,
        uint256 v2
    )
        internal
        pure
        returns (bytes32 mode, bytes memory ed)
    {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ to: address(0xBEEF), value: v1, data: hex"" });
        calls[1] = Call({ to: address(0xBEEF), value: v2, data: hex"" });
        return _batch(calls);
    }

    /// @dev A single native call carrying `value` (no calldata).
    function _oneNativeCall(uint256 value) internal pure returns (bytes32 mode, bytes memory ed) {
        return _single(address(0xBEEF), value, hex"");
    }

    /// @dev The cumulative native spend recorded under the per-mandate id `CID`.
    function _spent() internal view returns (uint256 spent) {
        (spent,) = spendSigil.spendStates(CID, address(this), account);
    }

    /// @notice REGRESSION: multiple value-bearing calls in one execution must share ONE budget. 60 + 60 across
    ///         two calls exceeds the 100 cap and must revert in the per-mandate postCheck — summed GLOBALLY from
    ///         the call set, NOT counted per-call.
    function test_cumulativeAcrossCalls_sharesOneBudget() external {
        _initNative(CID, CAP, Period.Day);

        spendSigil.preCheck(CID, account);
        (bytes32 mode, bytes memory ed) = _twoNativeCalls(60e6, 60e6);
        // SpendCapExceeded(id = the per-mandate CID, spent = 120e6 summed across both calls, cap = 100e6).
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, CID, 120e6, CAP)
        );
        spendSigil.postCheck(CID, account, mode, ed);
    }

    function test_withinCap_accruesUnderMandateId() external {
        _initNative(CID, CAP, Period.Day);

        spendSigil.preCheck(CID, account);
        (bytes32 mode, bytes memory ed) = _twoNativeCalls(40e6, 50e6);
        spendSigil.postCheck(CID, account, mode, ed);
        assertEq(_spent(), 90e6, "the two calls' native value sums into one mandate budget");
    }

    function test_failClosed_zeroCapRejectsAnyNative() external {
        _initNative(CID, 0, Period.Day);

        spendSigil.preCheck(CID, account);
        (bytes32 mode, bytes memory ed) = _oneNativeCall(1);
        // SpendCapExceeded(CID, spent = 1, cap = 0) — fail-closed: any native over a zero cap reverts.
        vm.expectRevert(abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, CID, 1, 0));
        spendSigil.postCheck(CID, account, mode, ed);
    }

    function test_rollover_resetsInNewPeriod() external {
        _initNative(CID, CAP, Period.Day);

        spendSigil.preCheck(CID, account);
        (bytes32 m1, bytes memory e1) = _oneNativeCall(80e6);
        spendSigil.postCheck(CID, account, m1, e1);
        assertEq(_spent(), 80e6, "first period charge");

        vm.warp(T0 + 2 days);
        spendSigil.preCheck(CID, account);
        (bytes32 m2, bytes memory e2) = _oneNativeCall(80e6);
        spendSigil.postCheck(CID, account, m2, e2);
        assertEq(_spent(), 80e6, "new period resets the running spend, not 160e6");
    }

    /// @notice The balance-delta backstop works for native too: an outflow the `value` sum misses (here a direct
    ///         balance drop) is still charged via `account.balance` before/after.
    function test_balanceDeltaBackstop_chargesUnsummedNativeOutflow() external {
        vm.deal(account, 10 ether);
        _initNative(CID, 5 ether, Period.Day);

        spendSigil.preCheck(CID, account); // snapshots balanceBefore = 10 ether
        vm.deal(account, 7 ether); // 3 ether left the account without a metered value in the call set
        // A call set whose value-sum is zero, so only the balance delta is charged.
        (bytes32 mode, bytes memory ed) = _oneNativeCall(0);
        spendSigil.postCheck(CID, account, mode, ed);
        assertEq(_spent(), 3 ether, "the balance delta is charged even with a zero value-sum");
    }
}
