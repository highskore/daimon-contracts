// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ModeLib
/// @author highskore.eth
/// @notice The signature mode bytes for Daimon's modal dispatch. The account routes on the first
///         signature byte (ROOT vs MANDATE); the MANDATE engine routes on the next byte (USE vs BIND).
library ModeLib {
    /*·:⛧:·──────── ACCOUNT MODES ────────:⛧:·*/

    /// @dev First signature byte: ROOT path (OR-set owner check).
    uint8 internal constant MODE_ROOT = 0x00;
    /// @dev First signature byte: MANDATE path (mandate-scoped, via the engine).
    uint8 internal constant MODE_MANDATE = 0x01;

    /*·:⛧:·──────── MANDATE SUB-MODES ────────:⛧:·*/

    /// @dev MANDATE sub-mode (second byte): use an already-enabled mandate.
    uint8 internal constant MANDATE_USE = 0x00;
    /// @dev MANDATE sub-mode (second byte): enable a mandate inline, then use it.
    uint8 internal constant MANDATE_BIND = 0x01;
    /// @dev MANDATE sub-mode (second byte): enable a mandate inline across N chains with ONE ROOT signature
    ///      over the multichain bind ARRAY digest (see {HashLib}), then use it.
    uint8 internal constant MANDATE_BIND_MULTICHAIN = 0x02;
}
