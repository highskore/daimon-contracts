// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Types
import { ActionConfig } from "@sigils/OmniSigil/lib/OmniSigilTypes.sol";

/// @title OmniSigilConfigLib — config storage + access for {OmniSigil}
/// @author highskore.eth
/// @notice Owns the {OmniSigil} configuration storage and the decode/validate/write/read paths over it. Each
///         config is isolated per `(configId, multiplexer, account)` triple — the same isolation boundary every
///         sigil keys on (the engine is baked into the account, so `multiplexer == msg.sender == account` at
///         runtime). Keeping the storage + accessors here mirrors the per-policy ConfigLib pattern.
/// @dev The storage struct lives at a fixed namespaced slot, reached via {_store}. The triple nesting
///      (`ConfigId => multiplexer => account => ActionConfig`) is the literal keying the sigil reads and writes;
///      moving it into this library does not change that logic, only where the mapping is declared.
library OmniSigilConfigLib {
    using OmniSigilTreeLib for *;

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    struct OmniSigilStore {
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => ActionConfig))
        ) configs;
    }

    /// @dev Namespaced base slot for {OmniSigilStore}; isolates this sigil's config from any other slot.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.OmniSigil.config");

    /// @dev The {OmniSigilStore} at the namespaced slot.
    function _store() private pure returns (OmniSigilStore storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @notice Decode `initData` as {ActionConfig}, validate its expression tree, and store it for
    ///         `(id, multiplexer, account)`, replacing any prior config (clean slate via {OmniSigilTreeLib.fill}).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param initData ABI-encoded {ActionConfig}.
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        ActionConfig memory config = abi.decode(initData, (ActionConfig));
        OmniSigilTreeLib.validateExpressionTree(config.paramRules);
        _store().configs[id][multiplexer][account].fill(config);
    }

    /*·:⛧:·──────── READ ────────:⛧:·*/

    /// @notice The stored {ActionConfig} for `(id, multiplexer, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return The config storage pointer (empty rules/nodes if never configured — the default-deny marker).
    function get(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (ActionConfig storage)
    {
        return _store().configs[id][multiplexer][account];
    }
}
