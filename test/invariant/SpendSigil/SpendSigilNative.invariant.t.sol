// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Handlers
import { SpendSigilNativeHandler } from "./SpendSigilNativeHandler.sol";

/// @title SpendSigil NATIVE-Budget Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the SpendSigil rolling cap for the NATIVE (ETH) budget — the value-summed
///         meter the ERC-20 suite does not cover. Across any interleaving of value-declaring charges, real ETH
///         outflows, and clock warps, the on-chain native spend (1) never exceeds the cap and (2) always equals
///         an independent ghost of `(spent, lastUpdated)`.
/// @dev FALSIFICATION PROTOCOL (designed to FAIL on a broken SUT):
///        - Delete the `if (spent > cfg.cap) revert SpendCapExceeded(...)` in {SpendSigil._accrue} → the
///          handler's "CAP BYPASSED" oracle + {invariant_spentNeverExceedsCap} trip.
///        - Delete the rollover reset in {SpendSigil._accrue} → {invariant_onChainMatchesGhost} trips.
contract SpendSigilNative_Invariant_Test is Test {
    /// @dev The canonical native-asset sentinel the SpendSigil treats as the ETH budget.
    address internal constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    SpendSigil internal sigil;
    SpendSigilNativeHandler internal handler;

    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xE74)));
    uint256 internal constant CAP = 5 ether;
    Period internal constant PERIOD = Period.Hour;

    function setUp() public {
        vm.warp(1_000_000); // a well-defined window baseline (avoid the t=0 boundary edge)
        sigil = new SpendSigil();
        handler = new SpendSigilNativeHandler(sigil, CID, CAP, PERIOD, 2 * 3600);
        // Fund the account so the real-move path has ETH; far larger than any reachable cumulative drain.
        vm.deal(address(handler), type(uint128).max);

        SpendConfig memory cfg =
            SpendConfig({ token: NATIVE, cap: CAP, period: PERIOD, spenders: new address[](0) });
        vm.prank(address(handler));
        sigil.initializeWithMultiplexer(address(handler), CID, abi.encode(cfg));

        targetContract(address(handler));
    }

    /// @notice SAFETY: the on-chain native rolling spend never exceeds the cap.
    function invariant_spentNeverExceedsCap() public view {
        (uint256 spent,) = sigil.spendStates(CID, address(handler), address(handler));
        assertLe(spent, CAP, "native spent exceeded cap");
    }

    /// @notice CORRECTNESS: the on-chain `(spent, lastUpdated)` exactly equals the independent ghost mirror.
    function invariant_onChainMatchesGhost() public view {
        (uint256 spent, uint256 lastUpdated) =
            sigil.spendStates(CID, address(handler), address(handler));
        assertEq(spent, handler.ghostSpent(), "native spent diverged from ghost");
        assertEq(lastUpdated, handler.ghostLastUpdated(), "lastUpdated diverged from ghost");
    }

    /// @notice COVERAGE: the fuzz reached both native meter paths, an over-cap rejection, and a rollover.
    function afterInvariant() public view {
        assertGt(handler.successfulSpends(), 0, "no successful charges explored");
        assertGt(handler.rejectedOverCap(), 0, "no over-cap rejections explored");
        assertGt(handler.rollovers(), 0, "no window rollovers explored");
        assertGt(handler.valueSpends(), 0, "declared-value meter path never exercised");
        assertGt(handler.realMoveSpends(), 0, "real-ETH-outflow meter path never exercised");
    }
}
