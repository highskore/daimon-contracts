// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { TimeFrameSigil_Unit_Test } from "../TimeFrameSigil.t.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title TimeFrameSigil.check1271 Unit Tests
/// @author highskore.eth
/// @notice The ERC-1271 view path mirrors {checkAction}: a signed message authorized under this policy is only
///         valid while `block.timestamp` is inside `[validAfter, validUntil]` (`validUntil == 0` ⇒ no upper
///         bound), reading NO content.
contract TimeFrameSigil_check1271_Unit_Test is TimeFrameSigil_Unit_Test {
    uint48 internal constant VALID_AFTER = 1000;
    uint48 internal constant VALID_UNTIL = 2000;

    /// @notice In-window: a signed message is authorized inside the window.
    function test_check1271_inWindow_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(1500);
        assertEq(
            timeFrame.check1271(ID, ACCOUNT, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "in-window 1271 must succeed"
        );
    }

    /// @notice Before `validAfter`: the message is not yet valid.
    function test_check1271_beforeValidAfter_returnsFailed() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(VALID_AFTER - 1);
        assertEq(
            timeFrame.check1271(ID, ACCOUNT, abi.encodePacked(SEL)),
            VALIDATION_FAILED,
            "before validAfter must fail"
        );
    }

    /// @notice After `validUntil`: the message has expired.
    function test_check1271_afterValidUntil_returnsFailed() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(uint256(VALID_UNTIL) + 1);
        assertEq(
            timeFrame.check1271(ID, ACCOUNT, abi.encodePacked(SEL)),
            VALIDATION_FAILED,
            "after validUntil must fail"
        );
    }

    /// @notice `validUntil == 0`: no upper bound on the 1271 path either.
    function test_check1271_validUntilZero_noUpperBound_returnsSuccess() external {
        _init(VALID_AFTER, 0);
        vm.warp(type(uint48).max);
        assertEq(
            timeFrame.check1271(ID, ACCOUNT, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "validUntil == 0 has no upper bound on 1271"
        );
    }

    /// @notice The 1271 path reads NO content: empty content in-window succeeds.
    function test_check1271_emptyContent_inWindow_returnsSuccess() external {
        _init(VALID_AFTER, VALID_UNTIL);
        vm.warp(1500);
        assertEq(
            timeFrame.check1271(ID, ACCOUNT, ""),
            VALIDATION_SUCCESS,
            "empty content is evaluated by the window alone"
        );
    }

    /// @notice Fuzz: the 1271 path equals the same window membership predicate as checkAction.
    function testFuzz_check1271_matchesWindowPredicate(
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
            timeFrame.check1271(ID, ACCOUNT, abi.encodePacked(SEL)),
            inWindow ? VALIDATION_SUCCESS : VALIDATION_FAILED,
            "check1271 must equal the window membership predicate"
        );
    }
}
