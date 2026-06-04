// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

/*·:⛧:·──────── STRUCTS ────────:⛧:·*/

/// @notice Configuration for an {Eip3009Sigil} instance — a content-aware x402 voucher gate that authorizes a
///         mandate's session key to 1271-sign EIP-3009 `transferWithAuthorization`s for a specific token, but
///         only to allowlisted payees and only up to a per-payment cap (instead of pinning one exact digest).
/// @param token The EIP-3009 token this voucher signs for — it is the `msg.sender` of `isValidSignature` (the
///        anti-phishing requesting-sender check) and the EIP-712 verifying contract of the signed authorization.
/// @param tokenDomainSeparator The token's EIP-712 domain separator — the value the threaded (ERC-7739-verified)
///        `appDomainSeparator` must equal, so the signed authorization is over THIS token's domain.
/// @param allowedPayees The `to` addresses the agent may pay (an EMPTY list denies every payee — default-deny).
/// @param cap The maximum `value` per authorization (an authorization with `value > cap` is rejected).
struct Eip3009Config {
    address token;
    bytes32 tokenDomainSeparator;
    address[] allowedPayees;
    uint256 cap;
}

/// @title Eip3009ConfigLib — config storage + access for {Eip3009Sigil}
/// @author highskore.eth
/// @notice Owns the {Eip3009Sigil} configuration storage (token + domain separator + payee allowlist + cap +
///         the `initialized` marker) and the decode/clear/write/read paths over it. Isolated per
///         `(configId, multiplexer, account)` — the same boundary every sigil keys on (the engine is baked into
///         the account, so `multiplexer == msg.sender == account` at runtime).
/// @dev Mirrors {AttestationConfigLib}: a fixed namespaced slot reached via {_store}, a triple-nested keying,
///      the payee allowlist as a solady enumerable set (so a re-init CLEARS the prior config), and an
///      `initialized` bool (NOT set non-emptiness) as the configured marker.
library Eip3009ConfigLib {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    struct Eip3009Store {
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => address))
        ) token;
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => bytes32))
        ) domain;
        mapping(
            ConfigId id
                => mapping(
                address multiplexer => mapping(address account => EnumerableSetLib.AddressSet)
            )
        ) payees;
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => uint256))
        ) cap;
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => bool))
        ) initialized;
    }

    /// @dev Namespaced base slot for {Eip3009Store}; isolates this sigil's config from any other slot.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.Eip3009Sigil.config");

    /// @dev The {Eip3009Store} at the namespaced slot.
    function _store() private pure returns (Eip3009Store storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @notice Decode `initData` as {Eip3009Config} and REPLACE the config for `(id, multiplexer, account)`.
    ///         The prior payee allowlist is CLEARED first so a re-bind never leaves a stale payee behind, then
    ///         the scalars are overwritten and the `initialized` marker is set.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param initData ABI-encoded {Eip3009Config}.
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        Eip3009Config memory cfg = abi.decode(initData, (Eip3009Config));
        Eip3009Store storage $ = _store();

        // Clear any prior payees first so a re-init fully REPLACES (never merges with) stale entries.
        EnumerableSetLib.AddressSet storage payeeSet = $.payees[id][multiplexer][account];
        address[] memory prior = payeeSet.values();
        for (uint256 i; i < prior.length; ++i) {
            payeeSet.remove(prior[i]);
        }
        for (uint256 i; i < cfg.allowedPayees.length; ++i) {
            payeeSet.add(cfg.allowedPayees[i]);
        }

        $.token[id][multiplexer][account] = cfg.token;
        $.domain[id][multiplexer][account] = cfg.tokenDomainSeparator;
        $.cap[id][multiplexer][account] = cfg.cap;
        $.initialized[id][multiplexer][account] = true;
    }

    /*·:⛧:·──────── READ ────────:⛧:·*/

    /// @notice Whether `(id, multiplexer, account)` was configured (the `initialized` marker).
    function isInitialized(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (bool)
    {
        return _store().initialized[id][multiplexer][account];
    }

    /// @notice The configured token for `(id, multiplexer, account)`.
    function token(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (address)
    {
        return _store().token[id][multiplexer][account];
    }

    /// @notice The configured token domain separator for `(id, multiplexer, account)`.
    function domain(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (bytes32)
    {
        return _store().domain[id][multiplexer][account];
    }

    /// @notice The configured per-authorization cap for `(id, multiplexer, account)`.
    function cap(ConfigId id, address multiplexer, address account)
        internal
        view
        returns (uint256)
    {
        return _store().cap[id][multiplexer][account];
    }

    /// @notice Whether `payee` is on the payee allowlist for `(id, multiplexer, account)`.
    function payeeAllowed(
        ConfigId id,
        address multiplexer,
        address account,
        address payee
    )
        internal
        view
        returns (bool)
    {
        return _store().payees[id][multiplexer][account].contains(payee);
    }
}
