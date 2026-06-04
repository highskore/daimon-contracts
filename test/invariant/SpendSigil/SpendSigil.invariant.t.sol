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

/// @title SpendSigil Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the SpendSigil rolling-cap SAFETY: across any interleaving of random charges
///         and clock warps, the on-chain spend (1) never exceeds the cap and (2) always equals an
///         independently-tracked ghost of `(spent, lastUpdated)`. The window rollover — the subtle, time-driven
///         part example tests under-cover — is exercised by the handler warping the clock.
/// @dev FALSIFICATION PROTOCOL (these invariants are designed to FAIL on a broken SUT — verified manually):
///        - Delete the `if (spent > cfg.cap) revert SpendCapExceeded(...)` line in {SpendSigil._accrue} →
///          the handler's "CAP BYPASSED" oracle and {invariant_spentNeverExceedsCap} both trip.
///        - Delete the rollover reset (`st.lastUpdated < startOfPeriod(...) ? 0 :`) in {SpendSigil._accrue} →
///          {invariant_onChainMatchesGhost} trips (the ghost rolls, the contract no longer does).
///      An invariant that survives a deliberately broken SUT is theater; this one does not.
///
///      SCOPE: this suite proves the rolling-cap accrual state machine over BOTH meter paths — the parsed
///      calldata sum ({SpendSigilHandler.spend}) and the real balance-delta backstop
///      ({SpendSigilHandler.spendViaBalance}) — for the `Hour` period. Deliberately OUT of scope here (each a
///      planned fast-follow invariant suite): the NATIVE budget, the dangling-allowance scan / blanket-grant
///      blocks, and the calendar-aligned `Month`/`Year` rollovers.
contract SpendSigil_Invariant_Test is Test {
    SpendSigil internal sigil;
    MockERC20 internal token;
    SpendSigilHandler internal handler;

    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xC0)));
    uint256 internal constant CAP = 100e6;
    Period internal constant PERIOD = Period.Hour;

    function setUp() public {
        vm.warp(1_000_000); // a well-defined window baseline (avoid the t=0 boundary edge)
        sigil = new SpendSigil();
        token = new MockERC20("USD", "USD");
        handler = new SpendSigilHandler(sigil, token, CID, CAP, PERIOD, 2 * 3600);
        // Fund the account so the balance-delta meter path (spendViaBalance) has tokens to move. Far larger
        // than any reachable cumulative drain (≈ windows × cap), so a real transfer never runs the account dry.
        token.mint(address(handler), type(uint128).max);

        // Configure as the handler: multiplexer (msg.sender) == account == the handler, mirroring the engine's
        // baked-in runtime. Transfer-only charges, so no approve-spender allowlist is needed.
        SpendConfig memory cfg = SpendConfig({
            token: address(token), cap: CAP, period: PERIOD, spenders: new address[](0)
        });
        vm.prank(address(handler));
        sigil.initializeWithMultiplexer(address(handler), CID, abi.encode(cfg));

        targetContract(address(handler));
    }

    /// @notice SAFETY: the on-chain rolling spend never exceeds the cap, whatever the sequence of charges.
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

    /// @notice COVERAGE: the fuzz actually reached every interesting branch — otherwise the proof is vacuous.
    function afterInvariant() public view {
        assertGt(handler.successfulSpends(), 0, "no successful charges explored");
        assertGt(handler.rejectedOverCap(), 0, "no over-cap rejections explored");
        assertGt(handler.rollovers(), 0, "no window rollovers explored");
        assertGt(handler.calldataSpends(), 0, "calldata-sum meter path never exercised");
        assertGt(handler.deltaSpends(), 0, "balance-delta meter path never exercised");
    }
}
