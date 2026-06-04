// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConfigId } from "@interfaces/ISigil.sol";

/// @notice {NativeValueLimitSigil} configuration: the maximum native (ETH) value a single guarded action may carry.
struct NativeValueLimitConfig {
    /// @notice Max native value (wei) permitted on one action. `0` = no native value allowed.
    uint256 limit;
}

/// @title NativeValueLimitConfigLib
/// @author highskore.eth
/// @notice Namespaced storage for {NativeValueLimitSigil}: the per-(configId, multiplexer, account) native-value cap.
/// @dev Mirrors {TimeFrameConfigLib} — a fixed storage slot keyed by (id, multiplexer, account).
library NativeValueLimitConfigLib {
    /// @notice The sigil's storage layout: configs keyed by (id, multiplexer, account).
    struct NativeValueLimitStore {
        mapping(
            ConfigId id
                => mapping(
                address multiplexer => mapping(address account => NativeValueLimitConfig)
            )
        ) configs;
    }

    /// @dev Fixed storage slot for the sigil's config store.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.NativeValueLimitSigil.config");

    /// @notice The sigil's config store at its fixed slot.
    function _store() private pure returns (NativeValueLimitStore storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /// @notice Decode + store the native-value cap for (id, multiplexer, account).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the account/engine).
    /// @param account The guarded account.
    /// @param initData ABI-encoded {NativeValueLimitConfig} (a single `uint256 limit`).
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        NativeValueLimitConfig memory cfg = abi.decode(initData, (NativeValueLimitConfig));
        _store().configs[id][multiplexer][account] = cfg;
    }

    /// @notice Read the stored native-value cap for (id, multiplexer, account).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller.
    /// @param account The guarded account.
    /// @return The stored {NativeValueLimitConfig}. An unconfigured entry is `limit == 0` — fail-closed: no native value.
    function get(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (NativeValueLimitConfig storage)
    {
        return _store().configs[id][multiplexer][account];
    }
}
