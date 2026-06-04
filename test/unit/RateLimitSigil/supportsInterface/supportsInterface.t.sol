// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RateLimitSigil_Unit_Test } from "../RateLimitSigil.t.sol";

// Types
import { IActionSigil, I1271Sigil, ISigilBase, IERC165 } from "@interfaces/ISigil.sol";

/// @title RateLimitSigil.supportsInterface Unit Tests
/// @author highskore.eth
/// @notice ERC-165 advertises the action tier ({IERC165}, {ISigilBase}, {IActionSigil}) and NOT {I1271Sigil}.
contract RateLimitSigil_supportsInterface_Unit_Test is RateLimitSigil_Unit_Test {
    function test_supportsInterface_erc165() external view {
        assertTrue(sigil.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    function test_supportsInterface_isigilBase() external view {
        assertTrue(sigil.supportsInterface(type(ISigilBase).interfaceId), "ISigilBase");
    }

    function test_supportsInterface_iactionSigil() external view {
        assertTrue(sigil.supportsInterface(type(IActionSigil).interfaceId), "IActionSigil");
    }

    function test_supportsInterface_not1271() external view {
        assertFalse(sigil.supportsInterface(type(I1271Sigil).interfaceId), "not I1271Sigil");
    }
}
