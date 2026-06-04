// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

/*·:⛧:·──────── STRUCTS ────────:⛧:·*/

/// @notice Configuration for an {AttestationSigil} instance — the attestation gate for a mandate's ERC-1271
///         signing path.
/// @param allowedSenders The requesting dApps the mandate may 1271-sign FOR (the anti-phishing allowlist).
///        An EMPTY allowlist denies every request (default-deny). To sign for ANY dApp, include the sentinel
///        {AttestationSigil.ANY_SENDER} (address(0)) — an explicit, legible opt-out.
/// @param allowedHashes The exact ERC-1271 digests (`hash`) this mandate may attest to. An EMPTY list means
///        ANY hash is allowed (sender-gated only); a NON-EMPTY list PINS the mandate to exactly those digests.
struct AttestationConfig {
    address[] allowedSenders;
    bytes32[] allowedHashes;
}

/// @title AttestationConfigLib — config storage + access for {AttestationSigil}
/// @author highskore.eth
/// @notice Owns the {AttestationSigil} configuration storage — the requesting-sender allowlist, the allowed-hash
///         allowlist, and the `initialized` marker — and the decode/clear/write/read paths over them. All are
///         isolated per `(configId, multiplexer, account)` triple — the same isolation boundary every sigil
///         keys on (the engine is baked into the account, so `multiplexer == msg.sender == account` at runtime).
///         The sentinel short-circuits + gate semantics stay in the sigil; this library only owns the storage
///         and the membership reads it needs, mirroring the per-policy ConfigLib pattern.
/// @dev The storage struct lives at a fixed namespaced slot, reached via {_store}. The triple nesting
///      (`ConfigId => multiplexer => account => ...`) is the literal keying the sigil reads and writes; moving
///      it into this library does not change that logic, only where the mappings are declared. The allowlists
///      are solady enumerable sets so a re-init can CLEAR the prior config; the `initialized` bool — NOT a
///      set's non-emptiness — is the configured marker (an empty sender set on an initialized instance is a
///      deliberate deny-all, distinct from a never-configured instance).
library AttestationConfigLib {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    struct AttestationStore {
        mapping(
            ConfigId id
                => mapping(
                address multiplexer => mapping(address account => EnumerableSetLib.AddressSet)
            )
        ) allowedSenders;
        mapping(
            ConfigId id
                => mapping(
                address multiplexer => mapping(address account => EnumerableSetLib.Bytes32Set)
            )
        ) allowedHashes;
        mapping(
            ConfigId id => mapping(address multiplexer => mapping(address account => bool))
        ) initialized;
    }

    /// @dev Namespaced base slot for {AttestationStore}; isolates this sigil's config from any other slot.
    bytes32 private constant _STORAGE_SLOT = keccak256("daimon.sigil.AttestationSigil.config");

    /// @dev The {AttestationStore} at the namespaced slot.
    function _store() private pure returns (AttestationStore storage $) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @notice Decode `initData` as {AttestationConfig} and REPLACE the requesting-sender + hash allowlists for
    ///         `(id, multiplexer, account)`. Any prior entries are CLEARED first, so a re-bind never leaves a
    ///         stale dApp or stale allowed-hash behind, then the `initialized` marker is set.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param initData ABI-encoded {AttestationConfig}.
    function initialize(
        ConfigId id,
        address multiplexer,
        address account,
        bytes calldata initData
    )
        internal
    {
        AttestationConfig memory cfg = abi.decode(initData, (AttestationConfig));
        AttestationStore storage $ = _store();

        // Clear any prior config first so a re-init fully REPLACES (never merges with) stale entries.
        EnumerableSetLib.AddressSet storage senders = $.allowedSenders[id][multiplexer][account];
        address[] memory priorSenders = senders.values();
        for (uint256 i; i < priorSenders.length; ++i) {
            senders.remove(priorSenders[i]);
        }
        EnumerableSetLib.Bytes32Set storage hashes = $.allowedHashes[id][multiplexer][account];
        bytes32[] memory priorHashes = hashes.values();
        for (uint256 i; i < priorHashes.length; ++i) {
            hashes.remove(priorHashes[i]);
        }

        for (uint256 i; i < cfg.allowedSenders.length; ++i) {
            senders.add(cfg.allowedSenders[i]);
        }
        for (uint256 i; i < cfg.allowedHashes.length; ++i) {
            hashes.add(cfg.allowedHashes[i]);
        }
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

    /// @notice Whether `sender` is on the requesting-dApp allowlist for `(id, multiplexer, account)`.
    function senderAllowed(
        ConfigId id,
        address multiplexer,
        address account,
        address sender
    )
        internal
        view
        returns (bool)
    {
        return _store().allowedSenders[id][multiplexer][account].contains(sender);
    }

    /// @notice Whether `hash` is on the allowed-hash allowlist for `(id, multiplexer, account)`.
    function hashAllowed(
        ConfigId id,
        address multiplexer,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool)
    {
        return _store().allowedHashes[id][multiplexer][account].contains(hash);
    }

    /// @notice Whether a non-empty hash allowlist is configured for `(id, multiplexer, account)`. When false,
    ///         ANY hash is permitted (sender-gated only); when true, the real `hash` must be in the allowlist.
    function hasHashAllowlist(
        ConfigId id,
        address multiplexer,
        address account
    )
        internal
        view
        returns (bool)
    {
        return _store().allowedHashes[id][multiplexer][account].length() != 0;
    }
}
