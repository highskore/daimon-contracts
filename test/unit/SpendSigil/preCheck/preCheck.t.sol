// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SpendSigil_Unit_Test } from "../SpendSigil.t.sol";

// Contracts
import { Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Interfaces
import { ISigilBase } from "@interfaces/ISigil.sol";

// Mocks
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title SpendSigil.preCheck Unit Tests
/// @author highskore.eth
/// @notice Proves the per-execution open hook: it requires a configured token (else PolicyNotInitialized) and
///         snapshots the account's pre-execution balance for {postCheck}'s balance-delta backstop. The snapshot
///         is re-taken each preCheck (keyed by the budgeted token), so two executions bracketed in one
///         transaction never leak the first's snapshot into the second.
/// @dev Exercises the real outcome hooks directly against a live MockERC20 (so `balanceOf` is real). With a
///      direct call the test contract is both `msg.sender` and `account`, matching the engine's runtime where
///      `msg.sender == account`. The balance snapshot is keyed by the budgeted token, shared across the hooks
///      within one transaction (one test body == one tx).
contract SpendSigil_preCheck_Unit_Test is SpendSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    MockERC20 internal mock;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        mock = new MockERC20("USD", "USD");
        mock.mint(account, 1000e6);
    }

    /*//////////////////////////////////////////////////////////////
                            NOT INITIALIZED
    //////////////////////////////////////////////////////////////*/

    /// @notice preCheck on an unconfigured (id, account) reverts PolicyNotInitialized.
    function test_preCheck_revertsWhen_uninitialized() external {
        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISigilBase.PolicyNotInitialized.selector, CID, address(this), account
            )
        );
        spendSigil.preCheck(CID, account);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The snapshot taken in preCheck is what postCheck's balance-delta meter charges against: an
    ///         outflow occurring between the two hooks is metered even when the calldata sum sees nothing.
    function test_preCheck_snapshotMetersBalanceDelta() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 outflow = 7e6;

        // Act: open the bracket (snapshot), move tokens out, then close with a call set that sums to zero.
        spendSigil.preCheck(CID, account);
        mock.transfer(SPENDER, outflow); // a real outflow the calldata parse never sees
        (bytes32 mode, bytes memory ed) =
            _single(SPENDER, 0, abi.encodeWithSelector(bytes4(0xdeadbeef)));
        spendSigil.postCheck(CID, account, mode, ed);

        // Assert: the balance delta from the snapshot is what got charged.
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(spent, outflow, "postCheck charges the delta against preCheck's snapshot");
    }

    /// @notice preCheck re-snapshots the balance each call: a stale snapshot from a prior bracket in the same
    ///         transaction does not leak into the next execution's balance-delta meter.
    function test_preCheck_resnapshotsBalance() external {
        // Arrange
        _init(address(mock), Period.Day);

        // Act: a first bracket meters a real outflow, then a SECOND preCheck re-snapshots at the lower balance.
        spendSigil.preCheck(CID, account);
        mock.transfer(SPENDER, 50e6);
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, _transfer(SPENDER, 50e6));
        spendSigil.postCheck(CID, account, mode, ed); // charges 50e6

        spendSigil.preCheck(CID, account); // re-snapshot at the post-transfer balance
        (bytes32 m2, bytes memory e2) =
            _single(SPENDER, 0, abi.encodeWithSelector(bytes4(0xdeadbeef)));
        spendSigil.postCheck(CID, account, m2, e2); // no real balance change since this second snapshot

        // Assert: the second execution metered zero on top of the first's 50e6 — no leak across the re-snapshot.
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(spent, 50e6, "the second bracket's delta is zero against the fresh snapshot");
    }
}
