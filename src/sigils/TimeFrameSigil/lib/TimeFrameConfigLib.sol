// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

/*·:⛧:·──────── STRUCTS ────────:⛧:·*/

/// @notice The time window an action is permitted in, abi-decoded from `initData`.
/// @param validAfter The earliest `block.timestamp` (unix seconds, inclusive) the action is allowed at. A
///        value of 0 means "no lower bound" — permitted from genesis.
/// @param validUntil The latest `block.timestamp` (unix seconds, inclusive) the action is allowed at. A value
///        of 0 is the sentinel for "no upper bound" — the window never closes (see {TimeFrameSigil.checkAction}).
struct TimeFrameConfig {
    uint48 validAfter;
    uint48 validUntil;
}

/// @title TimeFrameConfigLib — config storage + access for {TimeFrameSigil}
/// @author highskore.eth
/// @notice Owns the {TimeFrameSigil} configuration storage and the decode/write/read paths over it. The
///         config is isolated per `(configId, multiplexer, account)` triple — the same isolation boundary every
///         sigil keys on (the engine is baked into the account, so `multiplexer == msg.sender == account` at
///         runtime). Keeping the storage + accessors here mirrors the per-policy ConfigLib pattern.
/// @dev The storage struct lives at a fixed namespaced slot (ERC-7201 style), reached via {_store}. The triple
///      nesting (`ConfigId => multiplexer => account => TimeFrameConfig`) is the literal keying the sigil reads
///      and writes; moving it into this library does not change that logic, only where the mapping is declared.
library TimeFrameConfigLib {
    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown at init when `validAfter > validUntil` with a non-zero (real) `validUntil` — an
    ///         unsatisfiable window that no `block.timestamp` can fall inside, so the mandate would bind
    ///         successfully yet be permanently inert. Reject it at configure-time rather than silently
    ///         deny forever. (`validUntil == 0` is the open-ended sentinel and is always allowed.)
    /// @param validAfter The lower bound that exceeded the upper bound.
    /// @param validUntil The non-zero upper bound.
    error UnsatisfiableWindow(uint48 validAfter, uint48 validUntil);

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    struct TimeFrameStore {
        mapping(
            ConfigId id
                => mapping(address multiplexer => mapping(address account => TimeFrameConfig))
        ) configs;
    }

    /// @dev Namespaced base slot for {TimeFrameStore}; isolates this sigil's config from any other slot.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.TimeFrameSigil.config");

    /// @dev The {TimeFrameStore} at the namespaced slot.
    function _store() private pure returns (TimeFrameStore storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @notice Decode `initData` as {TimeFrameConfig} and store it for `(id, multiplexer, account)`, replacing
    ///         any prior window.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param initData ABI-encoded {TimeFrameConfig}.
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        TimeFrameConfig memory cfg = abi.decode(initData, (TimeFrameConfig));
        // Reject an unsatisfiable window at bind (validAfter > validUntil, validUntil real) instead of
        // accepting a config that silently denies forever. validUntil == 0 = open-ended (no upper bound).
        if (cfg.validUntil != 0 && cfg.validAfter > cfg.validUntil) {
            revert UnsatisfiableWindow(cfg.validAfter, cfg.validUntil);
        }
        _store().configs[id][multiplexer][account] = cfg;
    }

    /*·:⛧:·──────── READ ────────:⛧:·*/

    /// @notice The stored time-window config for `(id, multiplexer, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return The config storage pointer (zero window if never configured).
    function get(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (TimeFrameConfig storage)
    {
        return _store().configs[id][multiplexer][account];
    }
}
