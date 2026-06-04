// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

/*·:⛧:·──────── ENUMS ────────:⛧:·*/

/// @notice The rolling window a {SpendSigil} cap resets on. `Forever` never resets (a lifetime cap).
enum Period {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
    Forever
}

/*·:⛧:·──────── STRUCTS ────────:⛧:·*/

/// @notice Configuration for a {SpendSigil} instance, abi-decoded from `initData`.
/// @param token The budgeted ERC-20 whose outflow is metered against the cap.
/// @param cap Maximum cumulative outflow of `token` per `period`.
/// @param period The rolling window the cap resets on.
/// @param spenders Reserved approve-allowlist field, currently INERT on-chain. It formerly gated the `approve`
///        spender on the stateless ERC-1271 (`check1271`) ceiling, which this pure outcome sigil no longer
///        exposes; nothing reads it. Retained in the struct (storage + SDK encoding shape unchanged) and may
///        be re-consumed by a future tier.
struct SpendConfig {
    address token;
    uint256 cap;
    Period period;
    address[] spenders;
}

/// @notice Rolling spend accounting for a (account, configId), persisted across executions.
/// @param spent Cumulative `token` outflow charged within the current period.
/// @param lastUpdated Unix-seconds timestamp of the last charge (used to detect a period rollover).
struct SpendState {
    uint256 spent;
    uint256 lastUpdated;
}

/// @title SpendSigilConfigLib — config + spend-state storage and access for {SpendSigil}
/// @author highskore.eth
/// @notice Owns the {SpendSigil} persistent storage — the per-instance {SpendConfig} and the rolling
///         {SpendState} — and the decode/write/read paths over them. Both are isolated per
///         `(configId, multiplexer, account)` triple — the same isolation boundary every sigil keys on (the
///         engine is baked into the account, so `multiplexer == msg.sender == account` at runtime). The
///         per-execution transient accounting stays in the sigil; only the persistent config + spend state
///         live here, mirroring the per-policy ConfigLib pattern.
/// @dev The storage struct lives at a fixed namespaced slot, reached via {_store}. The triple nesting
///      (`ConfigId => multiplexer => account => ...`) is the literal keying the sigil reads and writes; moving
///      it into this library does not change that logic, only where the mappings are declared.
library SpendSigilConfigLib {
    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown at config time when the budgeted token is the zero address.
    error InvalidToken();

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    struct SpendSigilStore {
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => SpendConfig))
        ) configs;
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => SpendState))
        ) spendStates;
    }

    /// @dev Namespaced base slot for {SpendSigilStore}; isolates this sigil's storage from any other slot.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.SpendSigil.config");

    /// @dev The {SpendSigilStore} at the namespaced slot.
    function _store() private pure returns (SpendSigilStore storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @notice Decode `initData` as {SpendConfig}, reject a zero budgeted token, and store it for
    ///         `(id, multiplexer, account)`, replacing any prior config.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param initData ABI-encoded {SpendConfig}.
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        SpendConfig memory cfg = abi.decode(initData, (SpendConfig));
        if (cfg.token == address(0)) revert InvalidToken();
        _store().configs[id][multiplexer][account] = cfg;
    }

    /*·:⛧:·──────── READ ────────:⛧:·*/

    /// @notice The stored {SpendConfig} for `(id, multiplexer, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return The config storage pointer (zero `token` if never configured — the default-deny marker).
    function getConfig(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (SpendConfig storage)
    {
        return _store().configs[id][multiplexer][account];
    }

    /// @notice The rolling {SpendState} for `(id, multiplexer, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return The spend-state storage pointer.
    function getState(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (SpendState storage)
    {
        return _store().spendStates[id][multiplexer][account];
    }
}
