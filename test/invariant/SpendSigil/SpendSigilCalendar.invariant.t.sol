// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Mocks
import { MockERC20 } from "@test/mock/MockERC20.sol";

// Handlers
import { SpendSigilHandler } from "./SpendSigilHandler.sol";

/// @title SpendSigil Calendar-Period Invariant Tests
/// @author highskore.eth
/// @notice Extends the SpendSigil rolling-cap proof (the Hour suite in {SpendSigil.invariant.t.sol}) to the
///         CALENDAR-ALIGNED periods — Month and Year — whose `startOfPeriod` is the most error-prone window math
///         (civil-calendar conversion, not a simple modulo). Across any interleaving of charges and large clock
///         warps that straddle month/year boundaries, the on-chain spend (1) never exceeds the cap and (2)
///         always equals the independent ghost, so the calendar rollover resets `spent` exactly when (and only
///         when) a window boundary is crossed.
/// @dev The handler reuses `sigil.startOfPeriod(...)` for the ghost's window boundary — by design (DELEGATED
///      CORRECTNESS): the calendar math's own ground truth is pinned to hardcoded constants in
///      `test/unit/SpendSigil/startOfPeriod`, so this suite proves the ACCRUAL STATE MACHINE over the calendar
///      periods while that unit suite proves the boundary values. Same FALSIFICATION PROTOCOL as the Hour suite:
///      deleting the cap check or the rollover reset in {SpendSigil._accrue} trips the handler oracle / the
///      invariants here too.
abstract contract SpendSigilCalendar_Invariant_Base is Test {
    SpendSigil internal sigil;
    MockERC20 internal token;
    SpendSigilHandler internal handler;

    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xCA1)));
    uint256 internal constant CAP = 100e6;

    /// @dev The calendar period under test.
    function _period() internal pure virtual returns (Period);
    /// @dev Upper bound on a single warp — sized larger than the period so a single warp can cross a boundary.
    function _maxWarp() internal pure virtual returns (uint256);

    function setUp() public {
        vm.warp(1_700_000_000); // 2023-11-14 — a well-defined instant mid-month, mid-year (no boundary edge)
        sigil = new SpendSigil();
        token = new MockERC20("USD", "USD");
        handler = new SpendSigilHandler(sigil, token, CID, CAP, _period(), _maxWarp());
        token.mint(address(handler), type(uint128).max);

        SpendConfig memory cfg = SpendConfig({
            token: address(token), cap: CAP, period: _period(), spenders: new address[](0)
        });
        vm.prank(address(handler));
        sigil.initializeWithMultiplexer(address(handler), CID, abi.encode(cfg));

        targetContract(address(handler));
    }

    /// @notice SAFETY: the on-chain rolling spend never exceeds the cap across calendar rollovers.
    function invariant_spentNeverExceedsCap() public view {
        (uint256 spent,) = sigil.spendStates(CID, address(handler), address(handler));
        assertLe(spent, CAP, "spent exceeded cap");
    }

    /// @notice CORRECTNESS: the on-chain `(spent, lastUpdated)` exactly equals the independent ghost mirror.
    function invariant_onChainMatchesGhost() public view {
        (uint256 spent, uint256 lastUpdated) =
            sigil.spendStates(CID, address(handler), address(handler));
        assertEq(spent, handler.ghostSpent(), "spent diverged from ghost");
        assertEq(lastUpdated, handler.ghostLastUpdated(), "lastUpdated diverged from ghost");
    }

    /// @notice COVERAGE: the fuzz reached charges, over-cap rejections, and — critically — calendar rollovers.
    function afterInvariant() public view {
        assertGt(handler.successfulSpends(), 0, "no successful charges explored");
        assertGt(handler.rejectedOverCap(), 0, "no over-cap rejections explored");
        assertGt(handler.rollovers(), 0, "no calendar-window rollovers explored");
    }
}

/// @notice The Month-period instantiation: warps up to ~45 days so a single warp can cross a month boundary.
contract SpendSigilCalendar_Month_Invariant_Test is SpendSigilCalendar_Invariant_Base {
    function _period() internal pure override returns (Period) {
        return Period.Month;
    }

    function _maxWarp() internal pure override returns (uint256) {
        return 45 days;
    }
}

/// @notice The Year-period instantiation: warps up to ~400 days so a single warp can cross a year boundary.
contract SpendSigilCalendar_Year_Invariant_Test is SpendSigilCalendar_Invariant_Base {
    function _period() internal pure override returns (Period) {
        return Period.Year;
    }

    function _maxWarp() internal pure override returns (uint256) {
        return 400 days;
    }
}
