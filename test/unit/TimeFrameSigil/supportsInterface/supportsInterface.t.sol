// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { TimeFrameSigil_Unit_Test } from "../TimeFrameSigil.t.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ISigilBase, IERC165 } from "@interfaces/ISigil.sol";
import { IOutcomeSigil } from "@interfaces/IOutcomeSigil.sol";

/// @title TimeFrameSigil.supportsInterface Unit Tests
/// @author highskore.eth
/// @notice ERC-165 surface: the TimeFrameSigil serves BOTH tiers, so it advertises IERC165, ISigilBase,
///         IActionSigil, AND I1271Sigil; it does NOT advertise the outcome tier; and rejects unknown ids.
contract TimeFrameSigil_supportsInterface_Unit_Test is TimeFrameSigil_Unit_Test {
    /// @notice The sigil advertises ERC-165 support.
    function test_supportsInterface_erc165() external view {
        assertTrue(timeFrame.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    /// @notice The sigil advertises the shared ISigilBase config surface.
    function test_supportsInterface_isigilBase() external view {
        assertTrue(timeFrame.supportsInterface(type(ISigilBase).interfaceId), "ISigilBase");
    }

    /// @notice The sigil advertises the IActionSigil tier (its checkAction is a real time-gate).
    function test_supportsInterface_iactionSigil() external view {
        assertTrue(timeFrame.supportsInterface(type(IActionSigil).interfaceId), "IActionSigil");
    }

    /// @notice The sigil advertises the I1271Sigil tier (its check1271 is a real time-gate).
    function test_supportsInterface_i1271Sigil() external view {
        assertTrue(timeFrame.supportsInterface(type(I1271Sigil).interfaceId), "I1271Sigil");
    }

    /// @notice The sigil does NOT advertise the outcome tier.
    function test_supportsInterface_notOutcome() external view {
        assertFalse(
            timeFrame.supportsInterface(type(IOutcomeSigil).interfaceId), "not IOutcomeSigil"
        );
    }

    /// @notice An unknown interface id is not advertised.
    function test_supportsInterface_unknown_returnsFalse() external view {
        assertFalse(timeFrame.supportsInterface(0xffffffff), "unknown id");
    }
}
