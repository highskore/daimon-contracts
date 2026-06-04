// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { RateLimitSigil } from "@sigils/RateLimitSigil/RateLimitSigil.sol";

// Libraries
import { RateLimitConfig } from "@sigils/RateLimitSigil/lib/RateLimitConfigLib.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

// Handlers
import { RateLimitSigilHandler } from "./RateLimitSigilHandler.sol";

/// @title RateLimitSigil Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the RateLimitSigil rolling-frequency SAFETY: across any interleaving of random
///         action attempts and clock warps, the on-chain count (1) never exceeds `maxActions` within the current
///         window and (2) always equals an independently-tracked ghost of `(windowStart, count, lastActionAt)`.
///         The window rollover and cooldown — the subtle, time-driven parts example tests under-cover — are
///         exercised by the handler warping the clock.
/// @dev FALSIFICATION PROTOCOL (these invariants are designed to FAIL on a broken SUT — verified manually):
///        - Delete the `if (count >= cfg.maxActions) return VALIDATION_FAILED` line in {RateLimitSigil.checkAction}
///          → the handler's "RATE BYPASSED" oracle and {invariant_countNeverExceedsMax} both trip.
///        - Delete the rollover reset (`nowTs >= windowStart + cfg.windowSeconds` branch) → the handler oracle
///          and {invariant_onChainMatchesGhost} trip (the ghost rolls, the contract no longer does).
///        - Drop the no-mutation-on-reject guarantee (increment before the cap check) → the ghost diverges.
///      An invariant that survives a deliberately broken SUT is theater; this one does not.
///
///      SCOPE: this suite proves the rolling fixed-window + cooldown state machine for a small cap. The handler
///      splits the action into guided drivers (act-now / act-after-cooldown / act-next-window /
///      fill-to-cap-and-exceed / act-within-cooldown) plus a random warp, so the over-cap, cooldown-reject, and
///      rollover coverage dims are each hit DETERMINISTICALLY (not seed-flaky) while the warp still injects
///      arbitrary interleavings.
contract RateLimitSigil_Invariant_Test is Test {
    RateLimitSigil internal sigil;
    RateLimitSigilHandler internal handler;

    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xC0)));
    uint32 internal constant MAX_ACTIONS = 3;
    uint32 internal constant WINDOW = 100;
    uint32 internal constant COOLDOWN = 20;

    function setUp() public {
        vm.warp(1_000_000); // a well-defined baseline (avoid the t=0 boundary edge)
        sigil = new RateLimitSigil();
        // maxWarp ≈ 1.5× the window so a single warp can either stay within the window (clearing the cooldown)
        // OR cross the boundary (forcing a rollover) — both branches reachable from one warp action.
        handler = new RateLimitSigilHandler(sigil, CID, MAX_ACTIONS, WINDOW, COOLDOWN, 150);

        // Configure as the handler: multiplexer (msg.sender) == account == the handler, mirroring the engine's
        // baked-in runtime.
        RateLimitConfig memory cfg = RateLimitConfig({
            maxActions: MAX_ACTIONS, windowSeconds: WINDOW, minCooldownSeconds: COOLDOWN
        });
        vm.prank(address(handler));
        sigil.initializeWithMultiplexer(address(handler), CID, abi.encode(cfg));

        targetContract(address(handler));
    }

    /// @notice SAFETY: the on-chain count never exceeds the cap within the current window, whatever the sequence.
    function invariant_countNeverExceedsMax() public view {
        (, uint32 count,) = sigil.states(CID, address(handler), address(handler));
        assertLe(count, MAX_ACTIONS, "count exceeded maxActions");
    }

    /// @notice CORRECTNESS: the on-chain `(windowStart, count, lastActionAt)` exactly equals the independent ghost.
    function invariant_onChainMatchesGhost() public view {
        (uint32 windowStart, uint32 count, uint32 lastActionAt) =
            sigil.states(CID, address(handler), address(handler));
        assertEq(windowStart, handler.ghostWindowStart(), "windowStart diverged from ghost");
        assertEq(count, handler.ghostCount(), "count diverged from ghost");
        assertEq(lastActionAt, handler.ghostLastActionAt(), "lastActionAt diverged from ghost");
    }

    /// @notice COVERAGE: the fuzz actually reached every interesting branch — otherwise the proof is vacuous.
    function afterInvariant() public view {
        assertGt(handler.successfulActs(), 0, "no successful actions explored");
        assertGt(handler.rejectedOverCap(), 0, "no over-cap rejections explored");
        assertGt(handler.rejectedCooldown(), 0, "no cooldown rejections explored");
        assertGt(handler.rollovers(), 0, "no window rollovers explored");
    }
}
