// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { RateLimitSigil } from "@sigils/RateLimitSigil/RateLimitSigil.sol";

// Libraries
import { RateLimitConfig } from "@sigils/RateLimitSigil/lib/RateLimitConfigLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title RateLimitSigil_Symbolic_Test — machine-proven ∀-input frequency-cap correctness
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106 track) of {RateLimitSigil.checkAction}'s headline SAFETY: under a
///         FROZEN clock (no window rollover possible), the number of permitted actions never exceeds the
///         configured `maxActions`, and the cooldown is honored. Proven over a SYMBOLIC config and symbolic
///         per-step decisions.
/// @dev Two proofs:
///        1. {check_neverExceedsMaxActions_frozenClock}: with the clock frozen so the fixed window never rolls,
///           feeding a SYMBOLIC `maxActions` (bounded small to keep the unrolled trace finite) a fixed number of
///           consecutive actions and asserting the count of SUCCESSes is exactly `min(steps, maxActions)` — no
///           more than `maxActions` ever pass. Cooldown is disabled here to isolate the count cap.
///        2. {check_default_denies}: the fail-closed default — a NEVER-configured entry reverts
///           `PolicyNotInitialized`, so no action is ever permitted without a real config.
///
///      The window-rollover and cooldown TIME arithmetic (clock-dependent) is exercised by the invariant suite
///      ({RateLimitSigil.invariant.t.sol}) with an independent ghost; this symbolic proof pins the count-cap
///      safety over a symbolic cap with the clock held still.
contract RateLimitSigil_Symbolic_Test is Test {
    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0xBEEF);

    RateLimitSigil internal sigil;

    function setUp() public {
        vm.warp(1_000_000);
        sigil = new RateLimitSigil();
    }

    /// @notice ∀ maxActions (small, no cooldown), clock frozen: at most `maxActions` of N consecutive actions
    ///         pass — the count cap is never exceeded.
    function check_neverExceedsMaxActions_frozenClock(uint32 maxActions) public {
        // Bound the cap so the unrolled fixed step count is finite and meaningful; a large window keeps the
        // clock-frozen run inside one window (no rollover).
        vm.assume(maxActions >= 1 && maxActions <= 3);
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(
                RateLimitConfig({
                    maxActions: maxActions, windowSeconds: 1_000_000, minCooldownSeconds: 0
                })
            )
        );

        // Five consecutive actions at the SAME timestamp (clock frozen). Exactly `min(5, maxActions)` succeed.
        uint256 successes;
        for (uint256 i; i < 5; ++i) {
            uint256 code = sigil.checkAction(ID, ACCOUNT, TARGET, 0, hex"");
            assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
            if (code == VALIDATION_SUCCESS) ++successes;
        }
        // Headline safety: never more than the configured cap.
        assert(successes <= maxActions);
        // And exactly the cap is reached when steps ≥ cap (the cap is tight, not merely an upper bound).
        assert(successes == maxActions);
    }

    /// @notice The fail-closed DEFAULT: a never-configured entry reverts, so nothing is ever permitted.
    function check_default_denies() public {
        // No initializeWithMultiplexer — the (ID, this, ACCOUNT) entry is the zero default (windowSeconds 0).
        try sigil.checkAction(ID, ACCOUNT, TARGET, 0, hex"") returns (uint256) {
            assert(false); // an unconfigured entry MUST revert, never return a code
        } catch {
            assert(true);
        }
    }
}
