// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { TimeFrameSigil_Unit_Test } from "../TimeFrameSigil.t.sol";

// Contracts
import { TimeFrameConfigLib } from "@sigils/TimeFrameSigil/lib/TimeFrameConfigLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title TimeFrameSigil.checkAction Unit Tests
/// @author highskore.eth
/// @notice The action evaluation path of the time-window sigil: it returns SUCCESS iff `block.timestamp` is
///         inside the configured `[validAfter, validUntil]` window (both bounds inclusive; `validUntil == 0`
///         means no upper bound), reading NO calldata and enforcing NO value cap.
contract TimeFrameSigil_checkAction_Unit_Test is TimeFrameSigil_Unit_Test {
    /// @dev A representative window: [1000, 2000].
    uint48 internal constant VALID_AFTER = 1000;
    uint48 internal constant VALID_UNTIL = 2000;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice In-window: a timestamp strictly inside `[validAfter, validUntil]` permits the action.
    function test_checkAction_inWindow_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(1500);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "in-window must succeed"
        );
    }

    /// @notice The lower bound is inclusive: `block.timestamp == validAfter` permits the action.
    function test_checkAction_atValidAfter_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(VALID_AFTER);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "validAfter boundary is inclusive"
        );
    }

    /// @notice The upper bound is inclusive: `block.timestamp == validUntil` permits the action.
    function test_checkAction_atValidUntil_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(VALID_UNTIL);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "validUntil boundary is inclusive"
        );
    }

    /// @notice Before `validAfter`: the window has not opened yet, so the action is rejected.
    function test_checkAction_beforeValidAfter_returnsFailed() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(VALID_AFTER - 1);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_FAILED,
            "before validAfter must fail"
        );
    }

    /// @notice After `validUntil`: the window has closed, so the action is rejected.
    function test_checkAction_afterValidUntil_returnsFailed() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(uint256(VALID_UNTIL) + 1);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_FAILED,
            "after validUntil must fail"
        );
    }

    /// @notice `validUntil == 0` is the no-upper-bound sentinel: any timestamp at/after `validAfter` is
    ///         permitted, no matter how far in the future. The window never closes.
    function test_checkAction_validUntilZero_noUpperBound_returnsSuccess() external {
        _init(VALID_AFTER, 0);
        vm.warp(type(uint48).max); // arbitrarily far future
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "validUntil == 0 must have no upper bound"
        );
    }

    /// @notice `validAfter == 0` is the no-lower-bound sentinel: a timestamp of 1 (the minimum reachable in a
    ///         warp) is already inside an open-ended-from-genesis window.
    function test_checkAction_validAfterZero_noLowerBound_returnsSuccess() external {
        _init(0, VALID_UNTIL);
        vm.warp(1);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "validAfter == 0 must have no lower bound"
        );
    }

    /// @notice The fully-open window `(0, 0)` permits the action at any timestamp.
    function test_checkAction_openWindow_returnsSuccess() external {
        _init(0, 0);
        vm.warp(123_456_789);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "open (0,0) window must always succeed"
        );
    }

    /// @notice An unsatisfiable window (`validAfter > validUntil != 0`) can never reach checkAction — it is
    ///         rejected at init, so no such config can exist on-chain. (Window semantics are fuzzed below over
    ///         satisfiable windows; the init-time rejection itself is covered in initializeWithMultiplexer.t.sol.)
    function test_checkAction_unsatisfiableWindow_rejectedAtInit() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                TimeFrameConfigLib.UnsatisfiableWindow.selector, uint48(2000), uint48(1000)
            )
        );
        _init(2000, 1000);
    }

    /// @notice The sigil reads NO calldata: empty calldata is evaluated by the window alone (no revert reading
    ///         a non-existent word), unlike OmniSigil's reverting `data[4:36]` slice.
    function test_checkAction_emptyData_inWindow_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(1500);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, ""),
            VALIDATION_SUCCESS,
            "empty calldata is evaluated by the window alone"
        );
    }

    /// @notice The sigil enforces NO value cap: a non-zero ETH value in-window is permitted (the window is the
    ///         only constraint; pair with another sigil for a value cap).
    function test_checkAction_withValue_inWindow_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(1500);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 1 ether, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "value is not gated by the time window"
        );
    }

    /// @notice An UNINITIALIZED (id, multiplexer, account) reads as the zero window `(0, 0)` — open-ended, so
    ///         it succeeds. (Time bounds are opt-in: a never-configured TimeFrameSigil does not deny; the
    ///         engine's default-deny over the action SCOPE is the gate, this sigil only narrows by TIME.)
    function test_checkAction_uninitialized_returnsSuccess() external {
        vm.warp(1500);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "uninitialized reads as open (0,0) window"
        );
    }

    /// @notice Fuzz: with a configured window, success is EXACTLY the membership predicate
    ///         `t >= validAfter && (validUntil == 0 || t <= validUntil)`.
    function testFuzz_checkAction_matchesWindowPredicate(
        uint48 validAfter,
        uint48 validUntil,
        uint48 t
    )
        external
    {
        // Unsatisfiable windows are rejected at init, so only fuzz satisfiable ones here.
        vm.assume(validUntil == 0 || validAfter <= validUntil);
        _init(validAfter, validUntil);
        vm.warp(t);
        bool inWindow = t >= validAfter && (validUntil == 0 || t <= validUntil);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            inWindow ? VALIDATION_SUCCESS : VALIDATION_FAILED,
            "checkAction must equal the window membership predicate"
        );
    }
}
