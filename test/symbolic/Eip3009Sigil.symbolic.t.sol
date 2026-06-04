// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { Eip3009Sigil } from "@sigils/Eip3009Sigil/Eip3009Sigil.sol";

// Libraries
import { Eip3009Config } from "@sigils/Eip3009Sigil/lib/Eip3009ConfigLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title Eip3009Sigil_Symbolic_Test — machine-proven ∀-input ERC-1271 soundness anchor
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) for the SECURITY-CRITICAL property of {Eip3009Sigil}:
///         the ERC-1271 voucher gate is SOUND — a SUCCESS reply means the relayer-supplied EIP-3009
///         authorization fields (`from,to,value,validAfter,validBefore,nonce`) recompute, via the
///         {Eip3009Sigil-TRANSFER_WITH_AUTHORIZATION_TYPEHASH}, to EXACTLY the solady-verified
///         `contentsHash` (so the decoded fields ARE the value actually signed — they cannot be
///         spoofed), AND the anti-phishing token/domain gate, the payer == account gate, the payee
///         allowlist, and the per-authorization cap all held. Proven over fully SYMBOLIC fields, a
///         symbolic `contentsHash`, symbolic `sender`/`appDomainSeparator`, and a symbolic cap.
/// @dev The proven property (`check_check1271_success_implies_anchored`):
///        check1271 == SUCCESS  ⟹
///          keccak(TYPEHASH, from, to, value, va, vb, nonce) == contentsHash   (the SOUNDNESS ANCHOR)
///          AND sender == configured token
///          AND appDomainSeparator == configured tokenDomainSeparator
///          AND from == account
///          AND to == the (single) allowlisted payee
///          AND value <= cap
///      plus the converse direction (every gate satisfied ⟹ SUCCESS) and a strict two-valued return.
///
///      SYMBOLIC BOUND / MODELLING:
///        - The EIP-3009 `inner` blob is, by the sigil's own contract, EXACTLY six static words
///          (`_CONTENT_LEN == 0xc0`; any other length is rejected before decode). We therefore make
///          the six FIELDS symbolic scalars and reconstruct `inner = abi.encode(...)` in-harness.
///          This is a faithful, NOT a weakened, model: every `inner` that survives the length+decode
///          step maps 1:1 onto six symbolic words, so ranging over the words ranges over every
///          decodable authorization. (Malformed/short blobs are out of scope — they hit the
///          `inner.length != _CONTENT_LEN` fail-closed deny, covered by the unit suite.)
///        - The payee allowlist is bounded to a SINGLE symbolic payee (`allowedPayees.length == 1`).
///          One allowlisted entry is enough to prove the membership gate (`to == payee ⇔ allowed`);
///          a larger set only adds more disjuncts, not new behavior, and would inflate the solver.
///        - `to` is constrained away from the solady set's reserved zero-sentinel and from the
///          configured payee being that sentinel (an unconfigurable real payee — see the sigil's
///          `_SENTINEL_PAYEE` guard), matching the cryptographically-negligible real-world exclusion.
contract Eip3009Sigil_Symbolic_Test is Test {
    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);

    /// @dev The sigil's reserved zero-sentinel narrowed to an address (mirrors `_SENTINEL_PAYEE`).
    address internal constant SENTINEL_PAYEE = address(uint160(0xfbb67fda52d4bfb8bf));

    /// @dev The EIP-3009 `TransferWithAuthorization` typehash (mirrors the sigil constant).
    bytes32 internal constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    Eip3009Sigil internal sigil;

    /// @dev Bundles the full symbolic surface into one struct to stay within stack limits without
    ///      via-IR (13 separate symbolic params overflow the stack). `cfg*` is the symbolic CONFIG;
    ///      the rest is the symbolic engine-threaded 1271 payload + the EIP-3009 authorization FIELDS.
    struct Sym {
        address cfgToken;
        bytes32 cfgDomain;
        address cfgPayee;
        uint256 cfgCap;
        address sender;
        bytes32 appDomainSeparator;
        bytes32 contentsHash;
        address from;
        address to;
        uint256 value;
        uint256 va;
        uint256 vb;
        bytes32 nonce;
    }

    function setUp() public {
        sigil = new Eip3009Sigil();
    }

    /// @notice ∀ (config + voucher fields + threaded 1271 values): check1271 SUCCESS ⟺ the soundness
    ///         anchor holds AND every field gate is satisfied.
    /// @dev We configure, build the exact engine-packed `content`, call the real `check1271`, then
    ///      assert the full equivalence. Every field of `s` is symbolic (halmos).
    function check_check1271_success_implies_anchored(Sym memory s) public {
        // The configured payee must be a real, addable allowlist entry (not the reserved sentinel).
        vm.assume(s.cfgPayee != SENTINEL_PAYEE);

        // Configure a single-payee allowlist with symbolic token/domain/payee/cap.
        address[] memory payees = new address[](1);
        payees[0] = s.cfgPayee;
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(
                Eip3009Config({
                    token: s.cfgToken,
                    tokenDomainSeparator: s.cfgDomain,
                    allowedPayees: payees,
                    cap: s.cfgCap
                })
            )
        );

        // The relayer-supplied authorization fields, packed exactly as the engine threads them.
        bytes memory inner = abi.encode(s.from, s.to, s.value, s.va, s.vb, s.nonce);
        bytes memory content =
            abi.encode(s.sender, bytes32(0), s.appDomainSeparator, s.contentsHash, inner);

        uint256 code = sigil.check1271(ID, ACCOUNT, content);

        // The recomputed struct hash — the SOUNDNESS ANCHOR the sigil checks against `contentsHash`.
        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH, s.from, s.to, s.value, s.va, s.vb, s.nonce
            )
        );

        // The full gate predicate the sigil enforces, in spec form. Includes the EIP-3009 time bounds
        // (validAfter < now < validBefore, both strict) the sigil now enforces — omitting them would make
        // this equivalence unsound (the sigil denies an expired/not-yet-valid voucher that `gatesHold`
        // would otherwise call valid). `block.timestamp` is whatever the symbolic env binds it to.
        bool gatesHold = s.sender == s.cfgToken && s.appDomainSeparator == s.cfgDomain
            && structHash == s.contentsHash && s.from == ACCOUNT && s.to != SENTINEL_PAYEE
            && s.to == s.cfgPayee && s.value <= s.cfgCap && block.timestamp > s.va
            && block.timestamp < s.vb;

        // Headline soundness + converse, in one equivalence: SUCCESS iff every gate (incl. anchor) holds.
        assert((code == VALIDATION_SUCCESS) == gatesHold);
        // Strict two-valued return (the configured path never reverts on these inputs).
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }
}
