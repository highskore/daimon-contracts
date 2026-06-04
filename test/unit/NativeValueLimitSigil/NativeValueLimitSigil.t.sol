// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { NativeValueLimitSigil } from "@sigils/NativeValueLimitSigil/NativeValueLimitSigil.sol";

// Libraries
import {
    NativeValueLimitConfig
} from "@sigils/NativeValueLimitSigil/lib/NativeValueLimitConfigLib.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title NativeValueLimitSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for the NativeValueLimitSigil unit suites: deploys the sigil and exposes the shared
///         (account, configId, target) fixture + init/check helpers. This test contract is the multiplexer
///         (it both configures and checks), matching the runtime where the account/engine is `msg.sender`.
abstract contract NativeValueLimitSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0xBEEF);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    NativeValueLimitSigil internal sigil;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        sigil = new NativeValueLimitSigil();
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Configure the cap for (ID, this-contract-as-multiplexer, ACCOUNT).
    function _init(uint256 limit) internal {
        sigil.initializeWithMultiplexer(
            ACCOUNT, ID, abi.encode(NativeValueLimitConfig({ limit: limit }))
        );
    }

    /// @dev Run checkAction for a given native value (no calldata — the sigil reads none).
    function _check(uint256 value) internal view returns (uint256) {
        return sigil.checkAction(ID, ACCOUNT, TARGET, value, hex"");
    }
}
