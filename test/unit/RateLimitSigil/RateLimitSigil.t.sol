// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { RateLimitSigil } from "@sigils/RateLimitSigil/RateLimitSigil.sol";

// Libraries
import { RateLimitConfig } from "@sigils/RateLimitSigil/lib/RateLimitConfigLib.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title RateLimitSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for the RateLimitSigil unit suites: deploys the sigil and exposes the shared
///         (account, configId, target) fixture + init/check helpers. This test contract is the multiplexer
///         (it both configures and checks), matching the runtime where the account/engine is `msg.sender`.
abstract contract RateLimitSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0xBEEF);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    RateLimitSigil internal sigil;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // A well-defined baseline far from the t=0 epoch boundary so window/cooldown subtraction is meaningful.
        vm.warp(1_000_000);
        sigil = new RateLimitSigil();
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Configure the rate limit for (ID, this-contract-as-multiplexer, ACCOUNT).
    function _init(uint32 maxActions, uint32 windowSeconds, uint32 minCooldownSeconds) internal {
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(
                RateLimitConfig({
                    maxActions: maxActions,
                    windowSeconds: windowSeconds,
                    minCooldownSeconds: minCooldownSeconds
                })
            )
        );
    }

    /// @dev Run checkAction (no value/calldata — the sigil reads none).
    function _check() internal returns (uint256) {
        return sigil.checkAction(ID, ACCOUNT, TARGET, 0, hex"");
    }
}
