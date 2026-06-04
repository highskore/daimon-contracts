// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title SudoSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for the SudoSigil unit suites: deploys the allow-all sigil and exposes the
///         shared (account, configId) fixture. The SudoSigil holds no state, so there is nothing to install.
abstract contract SudoSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0x7A86E7);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    SudoSigil internal sudo;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        sudo = new SudoSigil();
    }
}
