// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { AttestationSigil_Unit_Test } from "../AttestationSigil.t.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ISigilBase, IERC165 } from "@interfaces/ISigil.sol";

/// @title AttestationSigil.supportsInterface Unit Tests
/// @author highskore.eth
/// @notice ERC-165 surface: the sigil advertises IERC165, ISigilBase, and I1271Sigil (signature tier only),
///         does NOT advertise the action tier ({IActionSigil}), and rejects unknown ids.
contract AttestationSigil_supportsInterface_Unit_Test is AttestationSigil_Unit_Test {
    /// @notice The sigil advertises ERC-165 support.
    function test_supportsInterface_erc165() external view {
        assertTrue(policy.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    /// @notice The sigil advertises the shared ISigilBase config surface.
    function test_supportsInterface_isigilBase() external view {
        assertTrue(policy.supportsInterface(type(ISigilBase).interfaceId), "ISigilBase");
    }

    /// @notice The sigil advertises the I1271Sigil tier it serves.
    function test_supportsInterface_i1271Sigil() external view {
        assertTrue(policy.supportsInterface(type(I1271Sigil).interfaceId), "I1271Sigil");
    }

    /// @notice The sigil does NOT advertise the action tier (it gates the 1271 signing path only).
    function test_supportsInterface_notAction() external view {
        assertFalse(policy.supportsInterface(type(IActionSigil).interfaceId), "not IActionSigil");
    }

    /// @notice An unknown interface id is not advertised.
    function test_supportsInterface_unknown_returnsFalse() external view {
        assertFalse(policy.supportsInterface(0xffffffff), "unknown id");
    }
}
