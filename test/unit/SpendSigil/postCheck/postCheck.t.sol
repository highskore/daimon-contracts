// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SpendSigil_Unit_Test } from "../SpendSigil.t.sol";

// Contracts
import { SpendSigil, Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Interfaces
import { ISigilBase } from "@interfaces/ISigil.sol";

// Mocks
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title SpendSigil.postCheck Unit Tests
/// @author highskore.eth
/// @notice Proves the per-execution close hook end to end against a live token: it itemizes the executed call
///         set GLOBALLY, charges `max(calldata-sum, balance-delta)` (each backstops the other), the rolling
///         period accrues within a window and resets across its boundary, an over-cap charge reverts
///         SpendCapExceeded, and an approval left dangling at close reverts DanglingAllowance — so a grant is
///         charged yet can never be pulled out-of-band.
/// @dev Exercises the real outcome hooks directly against a live MockERC20 (so `balanceOf`/`allowance` are
///      real). With a direct call the test contract is both `msg.sender` and `account`, matching the engine's
///      runtime where `msg.sender == account`. One test body == one transaction, so the preCheck snapshot
///      persists into postCheck. postCheck takes the executed ERC-7579 call set (mode + executionData) and
///      builds the calldata sum itself — no per-call checkAction attachment.
contract SpendSigil_postCheck_Unit_Test is SpendSigil_Unit_Test {
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

    /// @notice postCheck on an unconfigured (id, account) reverts PolicyNotInitialized.
    function test_postCheck_revertsWhen_uninitialized() external {
        // Act & Assert
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, _transfer(SPENDER, 0));
        vm.expectRevert(
            abi.encodeWithSelector(
                ISigilBase.PolicyNotInitialized.selector, CID, address(this), account
            )
        );
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /*//////////////////////////////////////////////////////////////
                            METER: max(...)
    //////////////////////////////////////////////////////////////*/

    /// @notice When the calldata-sum exceeds the balance delta, the calldata-sum is charged: an approve that
    ///         moves no balance (delta 0) is still metered by its named amount, then reset so it cannot dangle.
    function test_postCheck_metersCalldataSum_overDelta() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 amount = 8e6;

        // Act: the executed batch carries an approve (accrues `amount`), then set + RESET the real allowance so
        // the balance never moves (delta 0) and nothing dangles at close.
        spendSigil.preCheck(CID, account);
        mock.approve(SPENDER, amount);
        mock.approve(SPENDER, 0);
        (bytes32 mode, bytes memory ed) = _batch1(address(mock), 0, _approve(SPENDER, amount));
        spendSigil.postCheck(CID, account, mode, ed);

        // Assert: charged by the calldata-sum (the larger of the two), since the delta was zero.
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(spent, amount, "calldata-sum charged when it exceeds the (zero) balance delta");
    }

    /// @notice When the balance delta exceeds the calldata-sum, the delta is charged: an outflow via an
    ///         unparsed path (the call set sums 0) is still metered by the real balance delta.
    function test_postCheck_metersBalanceDelta_overCalldataSum() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 outflow = 9e6;

        // Act: snapshot, move tokens out via a call the itemizer does not sum (a pull on another target), close.
        spendSigil.preCheck(CID, account);
        mock.transfer(SPENDER, outflow);
        (bytes32 mode, bytes memory ed) =
            _single(SPENDER, 0, abi.encodeWithSelector(bytes4(0xdeadbeef)));
        spendSigil.postCheck(CID, account, mode, ed);

        // Assert: charged by the balance delta the calldata parse never saw.
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(spent, outflow, "balance delta charged when calldata-sum misses the outflow");
    }

    /*//////////////////////////////////////////////////////////////
                            ROLLING PERIOD
    //////////////////////////////////////////////////////////////*/

    /// @notice Two charges in the same window accrue cumulatively.
    function test_postCheck_sameWindow_accrues() external {
        // Arrange
        _init(address(mock), Period.Day);
        vm.warp(1_700_000_000); // a fixed instant well inside a Day window

        // Act: two brackets, each metering a real outflow, with no boundary crossed between them.
        _spendOnce(3e6);
        _spendOnce(5e6);

        // Assert
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(spent, 8e6, "charges in the same window accrue cumulatively");
    }

    /// @notice A charge after the window boundary resets `spent` to zero before accruing.
    function test_postCheck_afterBoundary_resets() external {
        // Arrange
        _init(address(mock), Period.Day);
        vm.warp(1_700_000_000);

        // Act: spend in window 1, then jump past the Day boundary and spend again.
        _spendOnce(7e6);
        vm.warp(block.timestamp + 2 days);
        _spendOnce(4e6);

        // Assert: only the post-boundary charge survives (the prior window reset).
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(spent, 4e6, "crossing the window boundary resets spent before accruing");
    }

    /*//////////////////////////////////////////////////////////////
                            OVER-CAP REVERT
    //////////////////////////////////////////////////////////////*/

    /// @notice A metered outflow that would push cumulative spend over the cap reverts SpendCapExceeded.
    function test_postCheck_overCap_reverts() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 over = CAP + 1;

        // Act & Assert: an over-cap transfer in the call set reverts at close.
        spendSigil.preCheck(CID, account);
        mock.transfer(SPENDER, over);
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, _transfer(SPENDER, over));
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, CID, over, CAP)
        );
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /*//////////////////////////////////////////////////////////////
                          DANGLING ALLOWANCE
    //////////////////////////////////////////////////////////////*/

    /// @notice An approve in the call set left non-zero at close reverts DanglingAllowance — a grant must net
    ///         back to zero so it can never be pulled out-of-band.
    function test_postCheck_danglingAllowance_reverts() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 amount = 4e6;

        // Act & Assert: the call set grants the approve, the real allowance is set and left dangling, close.
        spendSigil.preCheck(CID, account);
        mock.approve(SPENDER, amount); // never reset -> dangles
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, _approve(SPENDER, amount));
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.DanglingAllowance.selector, CID, SPENDER, amount)
        );
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /*//////////////////////////////////////////////////////////////
                            BLANKET GRANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A `permit` (EIP-2612) on the budgeted token is a blanket grant honored out-of-band that the
    ///         ERC-20 `allowance` dangling-scan can't account for or revoke — the itemizer blocks it outright.
    function test_postCheck_permit_reverts_blanketGrant() external {
        // Arrange
        _init(address(mock), Period.Day);

        // Act & Assert: a single call to token.permit(...) reverts during itemization (need not execute).
        bytes memory permitData = abi.encodeWithSelector(
            PERMIT_SELECTOR,
            account, // owner
            SPENDER, // spender
            uint256(5e6), // value
            uint256(type(uint256).max), // deadline
            uint8(27), // v
            bytes32(0), // r
            bytes32(0) // s
        );
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, permitData);
        spendSigil.preCheck(CID, account);
        vm.expectRevert(SpendSigil.BlanketGrantBlocked.selector);
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /// @notice A `setApprovalForAll` (ERC-721/1155 operator) on the budgeted token is a blanket grant the
    ///         ERC-20 `allowance` scan can't see (the operator flag lives in a different mapping) — blocked.
    function test_postCheck_setApprovalForAll_reverts_blanketGrant() external {
        // Arrange
        _init(address(mock), Period.Day);

        // Act & Assert
        bytes memory data = abi.encodeWithSelector(SET_APPROVAL_FOR_ALL_SELECTOR, SPENDER, true);
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, data);
        spendSigil.preCheck(CID, account);
        vm.expectRevert(SpendSigil.BlanketGrantBlocked.selector);
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /// @notice An `authorizeOperator` (ERC-777) on the budgeted token is a blanket grant the ERC-20 `allowance`
    ///         scan can't see (the operator lives in a different mapping) — blocked.
    function test_postCheck_authorizeOperator_reverts_blanketGrant() external {
        // Arrange
        _init(address(mock), Period.Day);

        // Act & Assert
        bytes memory data = abi.encodeWithSelector(AUTHORIZE_OPERATOR_SELECTOR, SPENDER);
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, data);
        spendSigil.preCheck(CID, account);
        vm.expectRevert(SpendSigil.BlanketGrantBlocked.selector);
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /// @notice REGRESSION-LOCK: a Permit2 `approve` of the budgeted token still reverts Permit2GrantBlocked. The
    ///         allowance lives inside Permit2 (not the token), so the dangling-scan can't see it. The block keys
    ///         on the selector + the token arg, BEFORE the `target == token` gate — so any target reverts.
    function test_postCheck_permit2ApproveOfBudgetedToken_reverts() external {
        // Arrange
        _init(address(mock), Period.Day);

        // Act & Assert: permit2.approve(token, spender, amount, expiration) with token == the budgeted token.
        bytes memory data = abi.encodeWithSelector(
            PERMIT2_APPROVE_SELECTOR,
            address(mock), // token (the budgeted token) — at offset 0x04
            SPENDER, // spender
            uint160(5e6), // amount
            uint48(type(uint48).max) // expiration
        );
        (bytes32 mode, bytes memory ed) = _single(PERMIT2, 0, data);
        spendSigil.preCheck(CID, account);
        vm.expectRevert(SpendSigil.Permit2GrantBlocked.selector);
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /*//////////////////////////////////////////////////////////////
                          INCREASE ALLOWANCE
    //////////////////////////////////////////////////////////////*/

    /// @notice An `increaseAllowance(spender, X)` on the budgeted token is metered into the cap AND its spender
    ///         is dangling-scanned: left un-reset at close it reverts DanglingAllowance.
    function test_postCheck_increaseAllowance_dangling_reverts() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 amount = 4e6;

        // Act & Assert: the call set grants via increaseAllowance, the real allowance is set + left dangling.
        spendSigil.preCheck(CID, account);
        mock.approve(SPENDER, amount); // mirror the grant the increaseAllowance would make; never reset -> dangles
        (bytes32 mode, bytes memory ed) =
            _single(address(mock), 0, _increaseAllowance(SPENDER, amount));
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.DanglingAllowance.selector, CID, SPENDER, amount)
        );
        spendSigil.postCheck(CID, account, mode, ed);
    }

    /// @notice An `increaseAllowance(spender, X)` that is RESET to zero within the same batch succeeds and
    ///         charges X to the cap (metered by the global calldata-sum even though the balance never moved).
    function test_postCheck_increaseAllowance_useReset_charges() external {
        // Arrange
        _init(address(mock), Period.Day);
        uint256 amount = 4e6;

        // Act: the batch grants via increaseAllowance then resets the real allowance to zero (delta 0, no dangle).
        spendSigil.preCheck(CID, account);
        mock.approve(SPENDER, amount);
        mock.approve(SPENDER, 0);
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ to: address(mock), value: 0, data: _increaseAllowance(SPENDER, amount) });
        calls[1] = Call({ to: address(mock), value: 0, data: _approve(SPENDER, 0) });
        (bytes32 mode, bytes memory ed) = _batch(calls);
        spendSigil.postCheck(CID, account, mode, ed);

        // Assert: charged by the global calldata-sum (the larger of the two; the balance delta was zero).
        (uint256 spent,) = spendSigil.spendStates(CID, address(this), account);
        assertEq(
            spent, amount, "increaseAllowance is metered into the cap via the global calldata-sum"
        );
        assertEq(
            mock.allowance(account, SPENDER), 0, "allowance reset within the batch -> no dangle"
        );
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev `increaseAllowance(spender, added)` content (OZ ERC-20 extension).
    function _increaseAllowance(
        address spender,
        uint256 added
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(INCREASE_ALLOWANCE_SELECTOR, spender, added);
    }

    /// @dev Run one full bracket that meters a real `amount` outflow via a transfer in the call set.
    /// @param amount The amount to move out of the account between the open and close hooks.
    function _spendOnce(uint256 amount) internal {
        spendSigil.preCheck(CID, account);
        mock.transfer(SPENDER, amount);
        (bytes32 mode, bytes memory ed) = _single(address(mock), 0, _transfer(SPENDER, amount));
        spendSigil.postCheck(CID, account, mode, ed);
    }
}
