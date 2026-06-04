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
import { SpendSigilApproveHandler } from "./SpendSigilApproveHandler.sol";

/// @title SpendSigil Approval-Safety Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the SpendSigil's approval guards across any interleaving of grants: an approve
///         is METERED to the budget, must net to zero by post-check (no dangling allowance the agent could pull
///         out-of-band in a later period), and blanket-grant primitives (setApprovalForAll / permit /
///         authorizeOperator / Permit2-approve) on the budgeted token are blocked outright. The independent
///         ghost confirms (1) the on-chain spend never exceeds the cap and (2) it equals the ghost, which
///         advances only on an accepted approve+reset — the blocked grants never mutate state.
/// @dev FALSIFICATION PROTOCOL (designed to FAIL on a broken SUT):
///        - Skip {SpendSigil._scanDangling} (or its revert) → the handler's "DANGLING ALLOWED" oracle trips.
///        - Remove the {BlanketGrantBlocked} / {Permit2GrantBlocked} reverts in {SpendSigil._itemizeOne} → the
///          "BLANKET ALLOWED" / "PERMIT2 ALLOWED" oracles trip.
///        - Delete the cap check in {SpendSigil._accrue} → "CAP BYPASSED" + {invariant_spentNeverExceedsCap}.
contract SpendSigilApprove_Invariant_Test is Test {
    SpendSigil internal sigil;
    MockERC20 internal token;
    SpendSigilApproveHandler internal handler;

    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xA99)));
    uint256 internal constant CAP = 100e6;
    Period internal constant PERIOD = Period.Hour;

    function setUp() public {
        vm.warp(1_000_000);
        sigil = new SpendSigil();
        token = new MockERC20("USD", "USD");
        handler = new SpendSigilApproveHandler(sigil, token, CID, CAP, PERIOD, 2 * 3600);

        // Transfer/approve metering is independent of the approve-spender allowlist (that gates only the 1271
        // tier), so no spenders are configured here.
        SpendConfig memory cfg = SpendConfig({
            token: address(token), cap: CAP, period: PERIOD, spenders: new address[](0)
        });
        vm.prank(address(handler));
        sigil.initializeWithMultiplexer(address(handler), CID, abi.encode(cfg));

        targetContract(address(handler));
    }

    /// @notice SAFETY: the on-chain rolling spend never exceeds the cap.
    function invariant_spentNeverExceedsCap() public view {
        (uint256 spent,) = sigil.spendStates(CID, address(handler), address(handler));
        assertLe(spent, CAP, "spent exceeded cap");
    }

    /// @notice CORRECTNESS: the on-chain `(spent, lastUpdated)` equals the ghost — blocked/reverted grants
    ///         (dangling, blanket, Permit2) never mutate it.
    function invariant_onChainMatchesGhost() public view {
        (uint256 spent, uint256 lastUpdated) =
            sigil.spendStates(CID, address(handler), address(handler));
        assertEq(spent, handler.ghostSpent(), "spent diverged from ghost");
        assertEq(lastUpdated, handler.ghostLastUpdated(), "lastUpdated diverged from ghost");
    }

    /// @notice COVERAGE: the fuzz reached the accepted approve+reset, an over-cap rejection, and each block.
    function afterInvariant() public view {
        assertGt(handler.approveResetAccepted(), 0, "no accepted approve+reset explored");
        assertGt(handler.rejectedOverCap(), 0, "no over-cap rejection explored");
        assertGt(handler.danglingRejected(), 0, "dangling-allowance block never exercised");
        assertGt(handler.blanketRejected(), 0, "blanket-grant block never exercised");
        assertGt(handler.permit2Rejected(), 0, "Permit2-grant block never exercised");
    }
}
