// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { AttestationSigil } from "@sigils/AttestationSigil/AttestationSigil.sol";

// Libraries
import { AttestationConfig } from "@sigils/AttestationSigil/lib/AttestationConfigLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title AttestationSigil_Symbolic_Test — machine-proven ∀-input ERC-1271 attestation gate
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) that {AttestationSigil.check1271} binds a 1271 reply to
///         the REAL signed `hash` and the requesting dApp: a SUCCESS reply means the requesting
///         `sender` was allowlisted AND (when a hash allowlist is configured) the REAL `hash` was on
///         it. Proven over a SYMBOLIC packed payload (symbolic `sender` + symbolic `hash`) against a
///         configured single-sender / single-hash allowlist.
/// @dev The {AttestationSigil} gates on the engine-threaded REAL `hash` (a deterministic 1:1 function
///      of the application digest the dApp passed to `isValidSignature`), NOT on the `innerContent`
///      blob — so `innerContent` is symbolic but irrelevant to the gate, and the proof confirms it
///      cannot influence the verdict.
///
///      Two proofs cover the two config branches:
///        1. {check_check1271_withHashAllowlist}: a NON-EMPTY hash allowlist PINS the digest —
///           SUCCESS ⟺ `sender == allowedSender` AND `hash == allowedHash`.
///        2. {check_check1271_anySenderNoHashAllowlist}: ANY_SENDER + EMPTY hash allowlist —
///           SUCCESS ⟺ true (sender-gated open, any hash), i.e. it never denies a configured open gate.
///
///      SYMBOLIC BOUND / MODELLING:
///        - The allowlists are bounded to a SINGLE symbolic entry each (`length == 1`). One entry
///          proves the membership gate (`x == entry ⇔ allowed`); a larger set adds disjuncts, not
///          behavior, and would inflate the solver.
///        - `allowedSender`/`allowedHash` are constrained away from solady's reserved zero-sentinel
///          (an unaddable value — see the sigil's `_SENTINEL_SENDER`/`_ZERO_SENTINEL` guards), and
///          `allowedSender != ANY_SENDER` so the configured-membership branch (not the wildcard) is
///          exercised. The `innerContent` is symbolic-length `bytes` bounded by halmos's global
///          `--default-bytes-lengths`; the gate reads none of it, so the bound is irrelevant.
contract AttestationSigil_Symbolic_Test is Test {
    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant ANY_SENDER = address(0);

    /// @dev solady's reserved zero-sentinel, in both forms (mirrors the sigil constants).
    address internal constant SENTINEL_SENDER = address(uint160(0xfbb67fda52d4bfb8bf));
    bytes32 internal constant ZERO_SENTINEL = bytes32(uint256(0xfbb67fda52d4bfb8bf));

    AttestationSigil internal sigil;

    function setUp() public {
        sigil = new AttestationSigil();
    }

    /// @notice ∀ (sender, hash, inner): with a single-sender + single-hash allowlist configured,
    ///         check1271 SUCCESS ⟺ `sender == allowedSender` AND `hash == allowedHash`.
    function check_check1271_withHashAllowlist(
        address allowedSender,
        bytes32 allowedHash,
        address sender,
        bytes32 hash,
        bytes calldata inner
    )
        public
    {
        // The configured entries must be real, addable members (not the reserved sentinel), and the
        // sender entry must not be the ANY_SENDER wildcard (we exercise the membership branch here).
        vm.assume(allowedSender != SENTINEL_SENDER);
        vm.assume(allowedSender != ANY_SENDER);
        vm.assume(allowedHash != ZERO_SENTINEL);

        address[] memory senders = new address[](1);
        senders[0] = allowedSender;
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = allowedHash;
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(AttestationConfig({ allowedSenders: senders, allowedHashes: hashes }))
        );

        // The engine packs (sender, hash, appDomainSeparator, contentsHash, innerContent).
        bytes memory content = abi.encode(sender, hash, bytes32(0), bytes32(0), inner);
        uint256 code = sigil.check1271(ID, ACCOUNT, content);

        // SUCCESS iff requesting sender allowlisted AND the REAL hash is the pinned digest.
        bool gatesHold = sender == allowedSender && hash == allowedHash;
        assert((code == VALIDATION_SUCCESS) == gatesHold);
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }

    /// @notice ∀ (sender, hash, inner): with ANY_SENDER opted in and NO hash allowlist, check1271
    ///         ALWAYS succeeds (open gate never denies — any dApp, any hash).
    function check_check1271_anySenderNoHashAllowlist(
        address sender,
        bytes32 hash,
        bytes calldata inner
    )
        public
    {
        // ANY_SENDER wildcard, empty hash allowlist (any hash permitted).
        address[] memory senders = new address[](1);
        senders[0] = ANY_SENDER;
        bytes32[] memory hashes = new bytes32[](0);
        sigil.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(AttestationConfig({ allowedSenders: senders, allowedHashes: hashes }))
        );

        bytes memory content = abi.encode(sender, hash, bytes32(0), bytes32(0), inner);
        uint256 code = sigil.check1271(ID, ACCOUNT, content);

        // Open gate: succeeds for every requesting sender and every hash.
        assert(code == VALIDATION_SUCCESS);
    }
}
