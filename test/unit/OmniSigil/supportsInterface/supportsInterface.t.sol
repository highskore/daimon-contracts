// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { OmniSigil_Unit_Test } from "../OmniSigil.t.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ISigilBase, IERC165 } from "@interfaces/ISigil.sol";

/// @title OmniSigil.supportsInterface Unit Tests
/// @author highskore.eth
/// @notice ERC-165 surface: the sigil advertises IERC165, ISigilBase, and IActionSigil (action tier only),
///         does NOT advertise the I1271Sigil signature tier, and rejects unknown ids.
contract OmniSigil_supportsInterface_Unit_Test is OmniSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The sigil advertises ERC-165 support.
    function test_supportsInterface_erc165() external view {
        assertTrue(omni.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    /// @notice The sigil advertises the shared ISigilBase config surface.
    function test_supportsInterface_isigilBase() external view {
        assertTrue(omni.supportsInterface(type(ISigilBase).interfaceId), "ISigilBase");
    }

    /// @notice The sigil advertises the IActionSigil tier it serves.
    function test_supportsInterface_iactionSigil() external view {
        assertTrue(omni.supportsInterface(type(IActionSigil).interfaceId), "IActionSigil");
    }

    /// @notice The sigil does NOT advertise the I1271Sigil signature tier (it serves the action tier only).
    function test_supportsInterface_not1271() external view {
        assertFalse(omni.supportsInterface(type(I1271Sigil).interfaceId), "not I1271Sigil");
    }

    /// @notice An unknown interface id is not advertised.
    function test_supportsInterface_unknown_returnsFalse() external view {
        assertFalse(omni.supportsInterface(0xffffffff), "unknown id");
    }
}
