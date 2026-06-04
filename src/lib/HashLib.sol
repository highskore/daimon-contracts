// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { MandateId, Mandate, ChainBind } from "@types/MandateTypes.sol";

/// @title HashLib
/// @author highskore.eth
/// @notice The single source of truth for the Daimon account's EIP-712 typed-data signing surface: every
///         domain typehash, struct hash, and final ROOT/session digest the account verifies — the mandate
///         bind, the direct-call execution, and the multichain bind array.
/// @dev One hashing lib per the style guide (§3): keeping the typehashes + `hashStruct` builders together
///      (and out of the storage lib / engine / account) means the off-chain SDK mirrors exactly one on-chain
///      surface. Two flavours of digest live here:
///        - ACCOUNT-DOMAIN digests (bind, exec) — this lib computes only the chain-agnostic `hashStruct`; the
///          account/engine wraps it in its per-chain EIP-712 domain via its `virtual` `_hashTypedData…` hook
///          (the domain depends on the account address + chainId, so it cannot live in a stateless lib).
///        - The CHAIN-INDEPENDENT multichain digest — fully self-contained here (fixed domain, no `chainId`/
///          `verifyingContract`), so {multichainBindDigest} returns the complete signable digest.
///      Sigil-local content hashing (an attestation/voucher recompute, the OmniSigil tree) stays with the
///      sigil whose check it serves — not here.
library HashLib {
    /*·:⛧:·──────── MANDATE BIND ────────:⛧:·*/

    /// @dev EIP-712 type hash for the mandate-bind digest signed by a ROOT scheme. Commits to the BIND-
    ///      authorization deadline (`validUntil`), the per-call actions, the per-execution outcome sigils, AND
    ///      the per-mandate signature (ERC-1271) sigils, so ROOT authorizes the *whole* mandate shape: a session
    ///      key can never add a sigil (or omit one) the owner did not sign — including an attestation/1271 sigil
    ///      that would let the agent sign EIP-712 typed data on the account's behalf — nor extend the bind
    ///      deadline. `validUntil` here is the deadline on the ROOT bind signature — enforced ONCE at bind time
    ///      (see {MandateEngine}) — NOT a runtime expiry: it is SIGNED so a relayer cannot set or tamper with it.
    ///      RUNTIME time bounds are a separate concern carried inside an action's {TimeFrameSigil} sigil,
    ///      committed to via `actionsHash` (a sigil's `initData` is part of the action).
    bytes32 internal constant MANDATE_BIND_TYPEHASH = keccak256(
        "DaimonMandateBind(bytes32 mandateId,uint48 validUntil,bytes32 actionsHash,bytes32 outcomeSigilsHash,bytes32 signatureSigilsHash,uint256 nonce)"
    );

    /// @notice The MANDATE_BIND struct hash (the EIP-712 `hashStruct`) — NOT yet domain-separated.
    /// @dev Commits the mandate id, the BIND-authorization deadline (`validUntil`), the per-call actions, the
    ///      per-execution outcome sigils, the per-mandate signature (ERC-1271) sigils, and the per-mandate enable
    ///      nonce. Wrap it in the account's EIP-712 domain (the engine's `_hashTypedDataSession`) to get the
    ///      chain+account-bound digest the ROOT signs. Shared by the single-chain and per-chain bind paths so
    ///      both compute the IDENTICAL per-chain digest from the same mandate content.
    /// @param pid The mandate id (`IdLib.toMandateId(s)`).
    /// @param s The mandate being authorized.
    /// @param nonce The per-mandate enable nonce committed into the digest (single-use, scoped).
    /// @return The MANDATE_BIND struct hash (NOT yet domain-separated).
    function bindStructHash(
        MandateId pid,
        Mandate memory s,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                MANDATE_BIND_TYPEHASH,
                MandateId.unwrap(pid),
                s.validUntil,
                keccak256(abi.encode(s.actions)),
                keccak256(abi.encode(s.outcomeSigils)),
                keccak256(abi.encode(s.signatureSigils)),
                nonce
            )
        );
    }

    /*·:⛧:·──────── DIRECT-CALL EXECUTION ────────:⛧:·*/

    /// @dev EIP-712 type hash for the direct-call execution digest, signed by a ROOT scheme or a mandate's
    ///      session key. Binds the ERC-7579 `mode`, `keccak256(executionData)`, the single-use `nonce`, and the
    ///      `deadline` after which the signed execution expires.
    bytes32 internal constant EXEC_TYPEHASH =
        keccak256("Execute(bytes32 mode,bytes32 executionDataHash,uint256 nonce,uint256 deadline)");

    /// @notice The Execute struct hash (the EIP-712 `hashStruct`) — NOT yet domain-separated.
    /// @dev Wrap it in the account's EIP-712 domain (`_hashTypedData`) to get the chain+account-bound digest the
    ///      signer commits to (anti-replay).
    /// @param mode The ERC-7579 execution mode.
    /// @param executionData The encoded execution payload (hashed in-place).
    /// @param nonce The single-use, caller-chosen execution nonce.
    /// @param deadline The unix timestamp after which the signed execution expires.
    /// @return The Execute struct hash (NOT yet domain-separated).
    function execStructHash(
        bytes32 mode,
        bytes memory executionData,
        uint256 nonce,
        uint256 deadline
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(EXEC_TYPEHASH, mode, keccak256(executionData), nonce, deadline));
    }

    /*·:⛧:·──────── MULTICHAIN BIND ────────:⛧:·*/

    /// @dev `keccak256("EIP712Domain(string name,string version)")` — the FIXED, chain-independent EIP-712
    ///      domain type (name + version ONLY). Deliberately omits `chainId` and `verifyingContract` so the
    ///      multichain array digest is identical on every chain (sign once, verify everywhere).
    bytes32 internal constant MULTICHAIN_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version)");

    /// @dev The fixed multichain-bind domain separator:
    ///      `keccak256(abi.encode(MULTICHAIN_DOMAIN_TYPEHASH, keccak256("DaimonMultichainBind"), keccak256("1")))`.
    ///      Chain-independent by construction (no `chainId`/`verifyingContract`), so the same array digest is
    ///      produced on every chain.
    bytes32 internal constant MULTICHAIN_DOMAIN_SEPARATOR = keccak256(
        abi.encode(MULTICHAIN_DOMAIN_TYPEHASH, keccak256("DaimonMultichainBind"), keccak256("1"))
    );

    /// @dev EIP-712 type hash for one `(chainId, bindDigest)` entry in the array.
    bytes32 internal constant CHAIN_BIND_TYPEHASH =
        keccak256("ChainBind(uint64 chainId,bytes32 bindDigest)");

    /// @dev EIP-712 type hash for the multichain-bind struct wrapping the `ChainBind[]` array. Per EIP-712,
    ///      a struct referencing another struct concatenates the referenced type's encoding, so the canonical
    ///      string includes `ChainBind(...)`.
    bytes32 internal constant MULTICHAIN_BIND_TYPEHASH = keccak256(
        "MultichainBind(ChainBind[] perChain)ChainBind(uint64 chainId,bytes32 bindDigest)"
    );

    /// @notice Hash the `ChainBind[]` array per EIP-712 (the hash of the concatenated per-entry struct hashes).
    /// @dev `hashStruct(ChainBind)` per entry, then `keccak256` of the packed entry hashes — the EIP-712 array
    ///      encoding. Order-sensitive: reordering entries changes the result, so the relayer cannot rearrange a
    ///      signed array.
    /// @param arr The per-chain bind entries.
    /// @return The EIP-712 array hash.
    function hashChainBindArray(ChainBind[] memory arr) internal pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](arr.length);
        for (uint256 i; i < arr.length; ++i) {
            h[i] = keccak256(abi.encode(CHAIN_BIND_TYPEHASH, arr[i].chainId, arr[i].bindDigest));
        }
        return keccak256(abi.encodePacked(h));
    }

    /// @notice The final EIP-712 multichain-bind digest the ROOT signs ONCE (and every chain re-derives).
    /// @dev `toTypedDataHash(MULTICHAIN_DOMAIN_SEPARATOR, hashStruct(MultichainBind))`. Uses the FIXED,
    ///      chain-independent domain separator, so the value is identical on every target chain — that is the
    ///      single signed digest the multichain flow verifies everywhere.
    /// @param arr The per-chain bind entries (the full signed array).
    /// @return The chain-independent EIP-712 typed-data hash to sign / verify.
    function multichainBindDigest(ChainBind[] memory arr) internal pure returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(MULTICHAIN_BIND_TYPEHASH, hashChainBindArray(arr)));
        return keccak256(abi.encodePacked(hex"1901", MULTICHAIN_DOMAIN_SEPARATOR, structHash));
    }
}
