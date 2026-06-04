// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { MandateId, ActionId } from "@types/MandateTypes.sol";

// forgefmt: disable-start
/// ┌─ erc7201: daimon.storage.mandate.v1 ─────────────────────────────┐
/// │  enabled / enableNonce              ── per-mandate flag + replay   │
/// │  signerConf                         ── the session key's verifier │
/// │  actionSigils / actionIds           ── the sigils gating each act  │
/// │  outcomeSigils                      ── per-execution pre/post hooks │
/// │  execNonceUsed                      ── direct-call replay guard    │
/// │  signatureSigils                    ── per-mandate ERC-1271 gates  │
/// └───────────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
/// @title MandateStorageLib
/// @author highskore.eth
/// @notice The ERC-7201 namespaced storage for the MANDATE layer — the agent's bounded sessions. Extracted
///         into a library so the layout, slot, and accessor live in one place and the engine stays thin. The
///         layer's EIP-712 typehashes are a hashing concern and live in {HashLib}, not here (style guide §3).
library MandateStorageLib {
    /*·:⛧:·──────── LAYOUT ────────:⛧:·*/

    /// @notice A session key's verifier and its stateless credential.
    /// @param validator The {ISessionValidator} that checks the session key's signatures.
    /// @param initData The credential passed to the validator on each check (e.g.
    /// abi.encode(signer)).
    struct SignerConf {
        address validator;
        bytes initData;
    }

    /// @notice All persisted MANDATE state for the account.
    /// @param enabled Whether a mandate (by MandateId) is currently active.
    /// @param signerConf The session-key verifier + credential per mandate.
    /// @param enableNonce Monotonic per-mandate nonce, bound into the bind digest for replay
    ///        protection.
    /// @param actionSigils The set of sigils gating each (ActionId, MandateId).
    /// @param actionIds The ActionIds enabled per mandate, tracked so revoke can fully clear them.
    /// @param outcomeSigils The set of per-execution {IOutcomeSigil}s bracketing the mandate's calls
    ///        with a pre/post pair (e.g. a stateful rolling spend cap). Tracked per mandate so revoke can
    ///        fully clear them.
    /// @param execNonceUsed Single-use nonces for direct-call execution (`executeWithSig`), so a
    ///        relayed execution signature is single-use and order-independent.
    /// @param signatureSigils The set of per-mandate ERC-1271 (attestation) {I1271Sigil}s gating the mandate's
    ///        1271 signing path — what typed data / content the agent may sign, and for which requesting
    ///        dApp. Empty => the mandate cannot 1271-sign (default-deny). Tracked per mandate so revoke can
    ///        fully clear them, and their config is keyed by the mandate alone ({IdLib.toMandateConfigId}),
    ///        like outcome sigils. APPENDED at the end of the struct (after `execNonceUsed`) per the ERC-7201
    ///        append-only rule — a new category must never be inserted mid-struct (that would shift every
    ///        following field's slot and corrupt an in-place upgrade).
    /// @dev The Mandate's `validUntil` is the BIND-AUTHORIZATION DEADLINE — committed to the MANDATE_BIND digest
    ///      (so the ROOT signer authenticates it) and enforced ONCE at bind time by {MandateEngine}; it is NOT
    ///      persisted in this struct and NOT consulted at runtime. RUNTIME time bounds live in a {TimeFrameSigil}
    ///      attached to the action(s), enforced per-action at check time.
    /// @custom:storage-location erc7201:daimon.storage.mandate.v1
    struct MandateStorage {
        mapping(MandateId => bool) enabled;
        mapping(MandateId => SignerConf) signerConf;
        mapping(MandateId => uint256) enableNonce;
        mapping(ActionId => mapping(MandateId => EnumerableSetLib.AddressSet)) actionSigils;
        mapping(MandateId => EnumerableSetLib.Bytes32Set) actionIds;
        mapping(MandateId => EnumerableSetLib.AddressSet) outcomeSigils;
        mapping(uint256 => bool) execNonceUsed;
        mapping(MandateId => EnumerableSetLib.AddressSet) signatureSigils;
    }

    /// @dev ERC-7201 namespaced storage slot for `daimon.storage.mandate.v1`. Derived as
    ///      `keccak256(abi.encode(uint256(keccak256("daimon.storage.mandate.v1")) - 1)) & ~bytes32(uint256(0xff))`
    ///      (the low byte is cleared so the layout cannot collide with a child mapping/array bucket). The
    ///      constant is hardcoded to avoid recomputing the hash on every access.
    bytes32 internal constant MANDATE_SLOT =
        0xdfc736743051a009b346181acb2a9edb427e88dd46ca4f99fe56931fd461d600;

    /// @notice Returns the namespaced {MandateStorage} pointer.
    function load() internal pure returns (MandateStorage storage $) {
        bytes32 s = MANDATE_SLOT;
        assembly {
            $.slot := s
        }
    }
}
