// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SudoSigil_Unit_Test } from "../SudoSigil.t.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ISigilBase, IERC165 } from "@interfaces/ISigil.sol";

/// @title SudoSigil.supportsInterface Unit Tests
/// @author highskore.eth
/// @notice ERC-165 surface: the sigil advertises IERC165, ISigilBase, and IActionSigil (action tier only),
///         does NOT advertise the I1271Sigil signature tier, and rejects unknown ids.
contract SudoSigil_supportsInterface_Unit_Test is SudoSigil_Unit_Test {
    /// @notice The sigil advertises ERC-165 support.
    function test_supportsInterface_erc165() external view {
        assertTrue(sudo.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    /// @notice The sigil advertises the shared ISigilBase config surface.
    function test_supportsInterface_isigilBase() external view {
        assertTrue(sudo.supportsInterface(type(ISigilBase).interfaceId), "ISigilBase");
    }

    /// @notice The sigil advertises the IActionSigil tier it serves.
    function test_supportsInterface_iactionSigil() external view {
        assertTrue(sudo.supportsInterface(type(IActionSigil).interfaceId), "IActionSigil");
    }

    /// @notice The sigil does NOT advertise the I1271Sigil signature tier (it serves the action tier only).
    function test_supportsInterface_not1271() external view {
        assertFalse(sudo.supportsInterface(type(I1271Sigil).interfaceId), "not I1271Sigil");
    }

    /// @notice An unknown interface id is not advertised.
    function test_supportsInterface_unknown_returnsFalse() external view {
        assertFalse(sudo.supportsInterface(0xffffffff), "unknown id");
    }
}
