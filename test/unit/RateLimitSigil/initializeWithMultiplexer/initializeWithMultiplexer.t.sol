// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RateLimitSigil_Unit_Test } from "../RateLimitSigil.t.sol";

// Libraries
import {
    RateLimitConfig,
    RateLimitConfigLib
} from "@sigils/RateLimitSigil/lib/RateLimitConfigLib.sol";

// Types
import { VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title RateLimitSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Config validation (reject zero maxActions / window) + persistence, and that a re-init overwrites
///         the config WITHOUT resetting the rolling state (a re-bind can't clear an exhausted window).
contract RateLimitSigil_initializeWithMultiplexer_Unit_Test is RateLimitSigil_Unit_Test {
    function test_revertWhen_maxActionsZero() external {
        vm.expectRevert(RateLimitConfigLib.InvalidMaxActions.selector);
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(RateLimitConfig({ maxActions: 0, windowSeconds: 60, minCooldownSeconds: 0 }))
        );
    }

    function test_revertWhen_windowZero() external {
        vm.expectRevert(RateLimitConfigLib.InvalidWindow.selector);
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(RateLimitConfig({ maxActions: 5, windowSeconds: 0, minCooldownSeconds: 0 }))
        );
    }

    function test_storesAndExposesTheConfig() external {
        _init(5, 3600, 30);
        (uint32 maxActions, uint32 windowSeconds, uint32 minCooldownSeconds) =
            sigil.configs(ID, address(this), ACCOUNT);
        assertEq(maxActions, 5, "maxActions");
        assertEq(windowSeconds, 3600, "windowSeconds");
        assertEq(minCooldownSeconds, 30, "minCooldownSeconds");
    }

    /// @notice A re-init overwrites the config but MUST NOT reset the rolling count — otherwise a re-bind could
    ///         be abused to clear an exhausted window. The count survives; only the config changes.
    function test_reinit_overwritesConfig_butKeepsState() external {
        _init(5, 3600, 0);
        assertEq(_check(), VALIDATION_SUCCESS, "first action passes");
        (, uint32 countBefore,) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(countBefore, 1, "count is 1 after one action");

        // Re-init with a different config.
        _init(10, 7200, 5);
        (uint32 maxActions, uint32 windowSeconds, uint32 minCooldownSeconds) =
            sigil.configs(ID, address(this), ACCOUNT);
        assertEq(maxActions, 10, "config overwritten: maxActions");
        assertEq(windowSeconds, 7200, "config overwritten: windowSeconds");
        assertEq(minCooldownSeconds, 5, "config overwritten: minCooldownSeconds");

        // The rolling state is untouched by the re-init.
        (, uint32 countAfter,) = sigil.states(ID, address(this), ACCOUNT);
        assertEq(countAfter, 1, "rolling count NOT reset by re-init");
    }
}
