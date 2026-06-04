// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Interfaces
import { IERC1608 } from "@interfaces/IERC1608.sol";

/// @title Daimon.supportsInterface Integration Tests
/// @author highskore.eth
/// @notice The account advertises ERC-165, ERC-1271 (it is a 1271 signer), and ERC-1608 (`executeWithSig`),
///         and nothing else — so a dApp feature-detecting a 1271 signer gets a truthful answer.
contract Daimon_supportsInterface_Integration_Test is Daimon_Integration_Test {
    /// @dev `bytes4(keccak256("isValidSignature(bytes32,bytes)"))` — the ERC-1271 detection id.
    bytes4 internal constant ERC1271_INTERFACE_ID = 0x1626ba7e;
    /// @dev `bytes4(keccak256("supportsInterface(bytes4)"))` — ERC-165 itself.
    bytes4 internal constant ERC165_INTERFACE_ID = 0x01ffc9a7;

    function test_supportsInterface_advertisesErc165() external view {
        assertTrue(daimon.supportsInterface(ERC165_INTERFACE_ID), "ERC-165");
    }

    function test_supportsInterface_advertisesErc1271() external view {
        assertTrue(daimon.supportsInterface(ERC1271_INTERFACE_ID), "ERC-1271 isValidSignature");
    }

    function test_supportsInterface_advertisesErc1608() external view {
        assertTrue(daimon.supportsInterface(type(IERC1608).interfaceId), "ERC-1608");
    }

    function test_supportsInterface_rejectsUnknown() external view {
        // The ERC-165 "invalid" sentinel and an arbitrary id must both be false.
        assertFalse(daimon.supportsInterface(0xffffffff), "0xffffffff sentinel");
        assertFalse(daimon.supportsInterface(0xdeadbeef), "arbitrary id");
    }
}
