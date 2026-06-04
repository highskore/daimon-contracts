// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

/// @title Base_Test
/// @author highskore.eth
/// @notice The root of every Daimon test suite. Holds only what every suite needs — signature packing —
///         and deploys no system-under-test.
abstract contract Base_Test is Test {
    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sign a digest and pack it as `[r][s][v]` (the layout solady's ECDSA recovery expects).
    /// @param pk The signer's private key.
    /// @param hash The digest to sign.
    /// @return The 65-byte packed signature.
    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }
}
