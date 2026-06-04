// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SpendSigil_Unit_Test } from "../SpendSigil.t.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ISigilBase, IERC165 } from "@interfaces/ISigil.sol";
import { IOutcomeSigil } from "@interfaces/IOutcomeSigil.sol";

/// @title SpendSigil.supportsInterface Unit Tests
/// @author highskore.eth
/// @notice ERC-165 surface: the sigil advertises IERC165, ISigilBase, and IOutcomeSigil (outcome tier only),
///         does NOT advertise the action ({IActionSigil}) or signature ({I1271Sigil}) tier, and rejects
///         unknown ids.
contract SpendSigil_supportsInterface_Unit_Test is SpendSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The sigil advertises ERC-165 support.
    function test_supportsInterface_erc165() external view {
        assertTrue(spendSigil.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    /// @notice The sigil advertises the shared ISigilBase config surface.
    function test_supportsInterface_isigilBase() external view {
        assertTrue(spendSigil.supportsInterface(type(ISigilBase).interfaceId), "ISigilBase");
    }

    /// @notice The sigil advertises the IOutcomeSigil tier it serves.
    function test_supportsInterface_ioutcomeSigil() external view {
        assertTrue(spendSigil.supportsInterface(type(IOutcomeSigil).interfaceId), "IOutcomeSigil");
    }

    /// @notice The sigil does NOT advertise the action tier (it is a pure outcome sigil).
    function test_supportsInterface_notAction() external view {
        assertFalse(
            spendSigil.supportsInterface(type(IActionSigil).interfaceId), "not IActionSigil"
        );
    }

    /// @notice The sigil does NOT advertise the signature tier (it is a pure outcome sigil).
    function test_supportsInterface_not1271() external view {
        assertFalse(spendSigil.supportsInterface(type(I1271Sigil).interfaceId), "not I1271Sigil");
    }

    /// @notice An unknown interface id is not advertised.
    function test_supportsInterface_unknown_returnsFalse() external view {
        assertFalse(spendSigil.supportsInterface(0xffffffff), "unknown id");
    }
}
