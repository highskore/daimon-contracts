// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RateLimitSigil_Unit_Test } from "../RateLimitSigil.t.sol";

// Types
import { ISigilBase, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title RateLimitSigil.checkAction Unit Tests
/// @author highskore.eth
/// @notice The frequency gate: the fail-closed uninitialized default, the per-window count cap (with no state
///         mutation on a reject), the fixed-window rollover, and the minCooldownSeconds gap.
contract RateLimitSigil_checkAction_Unit_Test is RateLimitSigil_Unit_Test {
    /// @notice Fail-closed: an unconfigured (id, multiplexer, account) reverts rather than permitting.
    function test_uninitialized_reverts() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                ISigilBase.PolicyNotInitialized.selector, ID, address(this), ACCOUNT
            )
        );
        _check();
    }

    function test_permits_belowMaxActions() external {
        _init(3, 3600, 0);
        assertEq(_check(), VALIDATION_SUCCESS, "1st action");
        assertEq(_check(), VALIDATION_SUCCESS, "2nd action");
        (, uint32 count,) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(count, 2, "count tracks permitted actions");
    }

    /// @notice At the cap the action is rejected, and the reject does NOT mutate state (the count stays put).
    function test_rejects_atMaxActions_withoutMutatingState() external {
        _init(2, 3600, 0);
        assertEq(_check(), VALIDATION_SUCCESS, "1st passes");
        assertEq(_check(), VALIDATION_SUCCESS, "2nd passes (cap reached)");
        (uint32 ws, uint32 count, uint32 last) = sigil.states(ID, address(this), ACCOUNT);

        assertEq(_check(), VALIDATION_FAILED, "3rd over the cap is rejected");
        (uint32 ws2, uint32 count2, uint32 last2) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(ws2, ws, "windowStart unchanged on reject");
        assertEq(count2, count, "count NOT incremented on reject");
        assertEq(last2, last, "lastActionAt unchanged on reject");
    }

    /// @notice After the window fully elapses the count resets and the formerly-rejected action now passes.
    function test_rollover_resetsCount() external {
        _init(1, 100, 0);
        assertEq(_check(), VALIDATION_SUCCESS, "1st passes");
        assertEq(_check(), VALIDATION_FAILED, "2nd over the cap rejected");

        // Cross the window boundary: the next action opens a fresh window.
        vm.warp(block.timestamp + 100);
        assertEq(_check(), VALIDATION_SUCCESS, "after rollover the cap is fresh");
        (uint32 ws, uint32 count,) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(ws, uint32(block.timestamp), "windowStart re-anchored to now");
        assertEq(count, 1, "count reset then charged once");
    }

    /// @notice A fixed/tumbling window: actions WITHIN the window keep the original windowStart anchor.
    function test_fixedWindow_keepsAnchorWithinWindow() external {
        _init(5, 1000, 0);
        assertEq(_check(), VALIDATION_SUCCESS, "1st anchors the window");
        (uint32 anchor,,) = sigil.states(ID, address(this), ACCOUNT);

        vm.warp(block.timestamp + 500); // still inside [anchor, anchor + 1000)
        assertEq(_check(), VALIDATION_SUCCESS, "2nd within the window");
        (uint32 ws,,) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(ws, anchor, "anchor unchanged within the window (fixed, not sliding)");
    }

    function test_cooldown_rejectsBeforeGap() external {
        _init(10, 3600, 60);
        assertEq(_check(), VALIDATION_SUCCESS, "1st action");
        vm.warp(block.timestamp + 59); // < cooldown
        assertEq(_check(), VALIDATION_FAILED, "before the cooldown gap is rejected");

        // The rejected action left state untouched: count is still 1.
        (, uint32 count,) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(count, 1, "rejected cooldown action not counted");
    }

    function test_cooldown_permitsAtGap() external {
        _init(10, 3600, 60);
        assertEq(_check(), VALIDATION_SUCCESS, "1st action");
        vm.warp(block.timestamp + 60); // == cooldown (inclusive)
        assertEq(_check(), VALIDATION_SUCCESS, "exactly the cooldown gap passes");
    }

    /// @notice The first action of the account's lifetime is never blocked by the cooldown (lastActionAt is 0).
    function test_cooldown_firstActionNeverBlocked() external {
        _init(10, 3600, 1000);
        assertEq(_check(), VALIDATION_SUCCESS, "first-ever action passes despite a large cooldown");
    }

    /// @notice The first-action cooldown exemption holds even when the cooldown exceeds the current time —
    ///         the explicit `lastActionAt != 0` guard, not a `now >= cooldown` coincidence.
    function test_cooldown_firstActionExempt_evenWhenCooldownExceedsNow() external {
        vm.warp(5); // tiny timestamp: cooldown (10) > block.timestamp
        _init(10, 3600, 10);
        assertEq(_check(), VALIDATION_SUCCESS, "first action exempt via the lastActionAt==0 guard");
    }

    /// @notice A near-uint32-max window must not overflow the rollover check and brick the action (DoS): the
    ///         subtraction form `now - windowStart >= windowSeconds` can't overflow where `windowStart + window`
    ///         would. The old additive form reverts on the 2nd call.
    function test_largeWindowSeconds_doesNotOverflow() external {
        _init(2, type(uint32).max, 0);
        assertEq(_check(), VALIDATION_SUCCESS, "1st passes");
        assertEq(_check(), VALIDATION_SUCCESS, "2nd passes - no uint32 overflow revert");
    }

    /// @notice A window rollover resets the count but NOT the cooldown anchor: an action just after the window
    ///         rolls is still cooldown-rejected when the gap hasn't elapsed.
    function test_cooldown_bitesAcrossWindowRollover() external {
        _init(5, 100, 200); // window 100s, cooldown 200s
        assertEq(_check(), VALIDATION_SUCCESS, "1st action");
        vm.warp(block.timestamp + 100); // window rolls (>= 100) but cooldown (200) not yet elapsed
        assertEq(_check(), VALIDATION_FAILED, "post-rollover action still cooldown-rejected");
    }
}
