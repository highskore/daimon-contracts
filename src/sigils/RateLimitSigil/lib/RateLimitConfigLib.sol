// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConfigId } from "@interfaces/ISigil.sol";

/*·:⛧:·──────── STRUCTS ────────:⛧:·*/

/// @notice {RateLimitSigil} configuration: the action-frequency cap, abi-decoded from `initData`.
/// @param maxActions Maximum number of guarded actions permitted per rolling window. MUST be non-zero — a
///        zero cap would deny every action and is rejected at config time ({InvalidMaxActions}).
/// @param windowSeconds Length (seconds) of the rolling window the action count resets on. MUST be non-zero
///        — a zero window has no duration and is rejected at config time ({InvalidWindow}).
/// @param minCooldownSeconds Minimum seconds that must elapse between two consecutive permitted actions. `0`
///        disables the cooldown (only the per-window count applies). Bounded by the window in practice, but
///        not validated against it — a cooldown ≥ the window simply caps the window at one action.
struct RateLimitConfig {
    uint32 maxActions;
    uint32 windowSeconds;
    uint32 minCooldownSeconds;
}

/// @notice Rolling rate-limit accounting for a (configId, multiplexer, account), persisted across executions.
/// @param windowStart Unix-seconds timestamp anchoring the current FIXED window (the first action's time in
///        it). The window is `[windowStart, windowStart + windowSeconds)`; a later action rolls it forward.
/// @param count Number of permitted actions charged within the current window.
/// @param lastActionAt Unix-seconds timestamp of the last permitted action (drives the cooldown check).
/// @dev All three timestamp fields are `uint32`: `block.timestamp` is cast to `uint32` on every write and
///      compared as `uint32`, so it wraps to zero after ~year 2106. Past that horizon the window/cooldown
///      comparisons mis-evaluate (regardless of any mandate fields); the sigil is not designed to operate
///      beyond it.
struct RateLimitState {
    uint32 windowStart;
    uint32 count;
    uint32 lastActionAt;
}

/// @title RateLimitConfigLib — config + rate-state storage and access for {RateLimitSigil}
/// @author highskore.eth
/// @notice Owns the {RateLimitSigil} persistent storage — the per-instance {RateLimitConfig} and the rolling
///         {RateLimitState} — and the decode/write/read paths over them. Both are isolated per
///         `(configId, multiplexer, account)` triple — the same isolation boundary every sigil keys on (the
///         engine is baked into the account, so `multiplexer == msg.sender == account` at runtime). Mirrors
///         {SpendSigilConfigLib}'s config + rolling-state storage shape; only the metered quantity differs
///         (action COUNT here vs. token outflow there).
/// @dev The storage struct lives at a fixed namespaced slot, reached via {_store}. The triple nesting
///      (`ConfigId => multiplexer => account => ...`) is the literal keying the sigil reads and writes.
library RateLimitConfigLib {
    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown at config time when `maxActions == 0` — a zero cap would deny every action (fail closed
    ///         at configure rather than silently bricking the mandate).
    error InvalidMaxActions();

    /// @notice Thrown at config time when `windowSeconds == 0` — a zero-length window has no rolling period.
    error InvalidWindow();

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    /// @notice The sigil's storage layout: configs + rate states keyed by (id, multiplexer, account).
    struct RateLimitStore {
        mapping(
            ConfigId id
                => mapping(address multiplexer => mapping(address account => RateLimitConfig))
        ) configs;
        mapping(
            ConfigId id
                => mapping(address multiplexer => mapping(address account => RateLimitState))
        ) states;
    }

    /// @dev Namespaced base slot for {RateLimitStore}; isolates this sigil's storage from any other slot.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.RateLimitSigil.config");

    /// @dev The {RateLimitStore} at the namespaced slot.
    function _store() private pure returns (RateLimitStore storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @notice Decode `initData` as {RateLimitConfig}, reject a nonsensical cap/window, and store it for
    ///         `(id, multiplexer, account)`, replacing any prior config. Does NOT reset the rolling
    ///         {RateLimitState}: a re-init keeps the running count so a re-bind can't be abused to clear an
    ///         exhausted window. (A fresh window is reached the normal way — by time elapsing.)
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param initData ABI-encoded {RateLimitConfig} (`maxActions`, `windowSeconds`, `minCooldownSeconds`).
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        RateLimitConfig memory cfg = abi.decode(initData, (RateLimitConfig));
        if (cfg.maxActions == 0) revert InvalidMaxActions();
        if (cfg.windowSeconds == 0) revert InvalidWindow();
        _store().configs[id][multiplexer][account] = cfg;
    }

    /*·:⛧:·──────── READ ────────:⛧:·*/

    /// @notice The stored {RateLimitConfig} for `(id, multiplexer, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return The config storage pointer (zero `windowSeconds` if never configured — the default-deny marker).
    function getConfig(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (RateLimitConfig storage)
    {
        return _store().configs[id][multiplexer][account];
    }

    /// @notice The rolling {RateLimitState} for `(id, multiplexer, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return The rate-state storage pointer.
    function getState(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (RateLimitState storage)
    {
        return _store().states[id][multiplexer][account];
    }
}
