// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// forgefmt: disable-start
/// ┌─ erc7201: daimon.storage.root.v1 ────────────────┐
/// │  validators  ── OR-set of installed auth schemes  │
/// └───────────────────────────────────────────────────┘
// forgefmt: disable-end
/// @title RootStorageLib
/// @author highskore.eth
/// @notice The ERC-7201 namespaced storage for the ROOT layer — the human's installable OR-set of
///         auth schemes. Extracted into a library so the layout, slot, and accessor live in one
///         place and the contract stays thin.
library RootStorageLib {
    /*·:⛧:·──────── LAYOUT ────────:⛧:·*/

    /// @notice ROOT-layer state.
    /// @param validators The installed scheme set. An installed scheme is active (membership ==
    ///        active; there is no activation delay).
    /// @custom:storage-location erc7201:daimon.storage.root.v1
    struct RootStorage {
        EnumerableSetLib.AddressSet validators;
    }

    /// @dev ERC-7201 namespaced storage slot for `daimon.storage.root.v1`. Derived as
    ///      `keccak256(abi.encode(uint256(keccak256("daimon.storage.root.v1")) - 1)) & ~bytes32(uint256(0xff))`
    ///      (the low byte is cleared so the layout cannot collide with a child mapping/array bucket). The
    ///      constant is hardcoded to avoid recomputing the hash on every access.
    bytes32 internal constant ROOT_SLOT =
        0x63b294414f2b0911f199d01f9b16b9ab52865a5f52f8d8d59f70866f338e3d00;

    /// @notice Returns the namespaced {RootStorage} pointer.
    function load() internal pure returns (RootStorage storage $) {
        bytes32 s = ROOT_SLOT;
        assembly {
            $.slot := s
        }
    }
}
