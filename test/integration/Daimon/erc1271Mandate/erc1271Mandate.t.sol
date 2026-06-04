// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Integration_Test } from "../../Base.integration.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { LibClone } from "solady/utils/LibClone.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";
import { AttestationSigil, AttestationConfig } from "@sigils/AttestationSigil/AttestationSigil.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Types
import {
    Mandate,
    ActionData,
    OutcomeSigilData,
    SignatureSigilData,
    MandateId
} from "@types/MandateTypes.sol";

/// @title Daimon MANDATE ERC-1271 (attestation) Integration Tests
/// @author highskore.eth
/// @notice Drives the MANDATE-mode ERC-1271 signing path end-to-end through the live account: a bound
///         mandate whose `signatureSigils` is an {AttestationSigil} CAN 1271-sign for an allowlisted dApp +
///         allowlisted digest (`hash`), and is rejected for a non-allowlisted dApp, a non-allowlisted hash,
///         a wrong session key, a malformed payload, or when the mandate carries no signature sigil at all.
///         Crucially it proves the gate binds to the REAL `hash` (the value the dApp validates and the
///         session key signs), not a caller-supplied content blob. ROOT 1271 is unchanged.
contract Daimon_erc1271Mandate_Integration_Test is Integration_Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    /// @dev keccak256("PersonalSign(bytes prefixed)").
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @dev The dApp that may request a signature (the anti-phishing allowlist entry).
    address internal constant DAPP = address(0xDA77);
    address internal constant EVIL_DAPP = address(0xBADD);

    Daimon internal daimon;
    ECDSAValidator internal root1;
    ECDSASessionValidator internal sessionValidator;
    AttestationSigil internal sigPolicy;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal agent;
    uint256 internal agentPk;
    uint256 internal strangerPk;

    /// @dev The opaque content blob threaded through the 1271 payload (carried, not gated on).
    bytes internal constant ORDER = bytes("buy 1 ETH @ 3000 USDC");

    /// @dev The raw application digest the dApp passes to `isValidSignature`.
    bytes32 internal constant INTENT_HASH = keccak256("intent");

    /// @dev The value the mandate's hash allowlist is pinned to: the ERC-7739-NESTED digest of {INTENT_HASH}
    ///      over the account's domain — i.e. the EXACT `hash` that reaches {AttestationSigil.check1271} and
    ///      that the session key signs (solady nests the raw app hash before the validation override). It is
    ///      deterministically (1:1) derived from {INTENT_HASH}, so pinning it is cryptographically equivalent
    ///      to pinning the raw app hash. Computed in {setUp} once the account address is known.
    bytes32 internal pinnedHash;

    function setUp() public virtual {
        // Accounts run as ERC-1967 proxies (the impl disables initializers); deploy a proxy to init.
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        root1 = new ECDSAValidator();
        sessionValidator = new ECDSASessionValidator();
        sigPolicy = new AttestationSigil();
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (agent, agentPk) = makeAddrAndKey("agent");
        (, strangerPk) = makeAddrAndKey("stranger");

        // The pinned hash is the nested digest of the raw app hash over THIS account's domain (the account
        // address is fixed at construction, before initialize), so the allowlist matches what the gate sees.
        pinnedHash = _personalSignDigest(daimon, INTENT_HASH);

        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);

        // Genesis-bind a mandate whose signing capability is gated by the AttestationSigil: dApp = DAPP, hash
        // pinned to the nested digest of INTENT_HASH. Genesis is the no-signature bind path, so the mandate is
        // enabled at deploy time.
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _signingMandate();
        daimon.initialize(vs, ds, ms);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A bound signing mandate: the session key, for the allowlisted dApp + pinned hash, returns
    ///         MAGIC.
    function test_mandate1271_allowedDappAndHash_returnsMagic() external {
        bytes memory sig = _mandateSig(_mandateId(), ORDER, agentPk, INTENT_HASH);

        vm.prank(DAPP);
        assertEq(daimon.isValidSignature(INTENT_HASH, sig), MAGIC_VALUE, "allowlisted dApp + hash");
    }

    /// @notice A non-allowlisted dApp (different `msg.sender`) is rejected — the anti-phishing guarantee.
    function test_mandate1271_wrongDapp_notAccepted() external {
        bytes memory sig = _mandateSig(_mandateId(), ORDER, agentPk, INTENT_HASH);

        vm.prank(EVIL_DAPP);
        assertFalse(_accepts(INTENT_HASH, sig), "non-allowlisted dApp must be rejected");
    }

    /// @notice A non-allowlisted digest is rejected even from the allowlisted dApp (hash-pinned mandate).
    function test_mandate1271_wrongHash_notAccepted() external {
        bytes32 wrongHash = keccak256("a different intent");
        bytes memory sig = _mandateSig(_mandateId(), ORDER, agentPk, wrongHash);

        vm.prank(DAPP);
        assertFalse(_accepts(wrongHash, sig), "off-allowlist hash must be rejected");
    }

    /// @notice SECURITY — the gate binds to the REAL `hash`, not the content blob. The agent signs an
    ///         off-allowlist digest (drain order) but carries the {ORDER} content blob that the OLD design
    ///         would have content-matched. End-to-end the account MUST reject it: the real validated `hash`
    ///         is off-allowlist, and the content blob cannot rescue it.
    function test_mandate1271_allowlistedContentButWrongRealHash_rejected() external {
        bytes32 attackerRealHash = keccak256("drain the whole wallet");
        assertTrue(attackerRealHash != INTENT_HASH, "setup: attacker hash must differ from pinned");

        // Sign the attacker's real digest, but carry the (innocuous-looking, would-be-allowlisted) ORDER.
        bytes memory sig = _mandateSig(_mandateId(), ORDER, agentPk, attackerRealHash);

        vm.prank(DAPP);
        assertFalse(
            _accepts(attackerRealHash, sig),
            "an allowlisted-looking content blob must NOT authorize a mismatched real hash"
        );
    }

    /// @notice A signature from a key that is NOT the mandate's session key is rejected.
    function test_mandate1271_wrongSessionKey_notAccepted() external {
        bytes memory sig = _mandateSig(_mandateId(), ORDER, strangerPk, INTENT_HASH);

        vm.prank(DAPP);
        assertFalse(_accepts(INTENT_HASH, sig), "wrong session key must be rejected");
    }

    /// @notice An unknown / unbound mandate id is rejected (default-deny).
    function test_mandate1271_unknownMandate_notAccepted() external {
        bytes memory sig =
            _mandateSig(MandateId.wrap(bytes32(uint256(0xDEAD))), ORDER, agentPk, INTENT_HASH);

        vm.prank(DAPP);
        assertFalse(_accepts(INTENT_HASH, sig), "unbound mandate must be rejected");
    }

    /// @notice A malformed payload tail (not a well-formed `abi.encode(bytes,bytes)`) fails closed: the
    ///         account returns not-MAGIC (or reverts, which {_accepts} treats as not-accepted) rather than
    ///         panicking unhelpfully. Guards the defensive try/catch decode in {MandateEngine}.
    function test_mandate1271_malformedPayload_failsClosed() external {
        // [0x01 mode][32-byte mandateId][garbage tail that is NOT a valid (bytes,bytes) ABI encoding].
        bytes memory sig = abi.encodePacked(
            bytes1(0x01), MandateId.unwrap(_mandateId()), bytes("not-abi-encoded-garbage")
        );

        vm.prank(DAPP);
        assertFalse(_accepts(INTENT_HASH, sig), "malformed payload must fail closed, not panic");
    }

    /// @notice A bound mandate with NO signature sigil cannot 1271-sign — the capability is strictly opt-in.
    function test_mandate1271_mandateWithoutSignatureSigil_notAccepted() external {
        // Bind (genesis) a fresh account whose mandate has the SAME session key but no signature sigils.
        Daimon d2 = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _nonSigningMandate();
        d2.initialize(vs, ds, ms);

        bytes32 hash = keccak256("intent");
        MandateId pid = _mandateId(_nonSigningMandate());
        bytes32 nested = _personalSignDigest(d2, hash);
        bytes memory keySig = _sign(agentPk, nested);
        bytes memory sig =
            abi.encodePacked(bytes1(0x01), MandateId.unwrap(pid), abi.encode(ORDER, keySig));

        vm.prank(DAPP);
        try d2.isValidSignature(hash, sig) returns (bytes4 mv) {
            assertTrue(mv != MAGIC_VALUE, "no-signature-sigil mandate must not 1271-sign");
        } catch { }
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A mandate whose ONLY capability is 1271-signing for DAPP + the {INTENT_HASH} digest (no on-chain
    ///      actions). The hash allowlist pins the REAL digest the dApp validates, not a content blob.
    function _signingMandate() internal view returns (Mandate memory s) {
        address[] memory senders = new address[](1);
        senders[0] = DAPP;
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = pinnedHash;
        SignatureSigilData[] memory sigs = new SignatureSigilData[](1);
        sigs[0] = SignatureSigilData({
            sigil: address(sigPolicy),
            initData: abi.encode(
                AttestationConfig({ allowedSenders: senders, allowedHashes: hashes })
            )
        });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x1271)),
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: sigs
        });
    }

    /// @dev A mandate with the same session key but NO signature sigils (cannot 1271-sign).
    function _nonSigningMandate() internal view returns (Mandate memory s) {
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xC0FFEE)), // distinct from the signing mandate's salt
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev The signing mandate's id.
    function _mandateId() internal view returns (MandateId) {
        return _mandateId(_signingMandate());
    }

    /// @dev The MandateId of an arbitrary mandate (matches IdLib.toMandateId).
    function _mandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @dev Build a MANDATE-mode 1271 signature for `daimon`: [0x01][mandateId][abi.encode(content, keySig)].
    ///      The session key signs the nested ERC-7739 PersonalSign digest over `hash`.
    function _mandateSig(
        MandateId pid,
        bytes memory content,
        uint256 pk,
        bytes32 hash
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 nested = _personalSignDigest(daimon, hash);
        bytes memory keySig = _sign(pk, nested);
        return abi.encodePacked(bytes1(0x01), MandateId.unwrap(pid), abi.encode(content, keySig));
    }

    /// @dev True iff the account accepts `sig` (returns the ERC-1271 magic value). A revert (solady's
    ///      ERC-7739 may probe a rejected sig) counts as not-accepted.
    function _accepts(bytes32 hash, bytes memory sig) internal view returns (bool) {
        try daimon.isValidSignature(hash, sig) returns (bytes4 mv) {
            return mv == MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev The ERC-7739 PersonalSign digest solady reconstructs when no TypedDataSign data is appended:
    ///      `_hashTypedData(keccak256(PERSONAL_SIGN_TYPEHASH, hash))` over the account's domain.
    function _personalSignDigest(Daimon d, bytes32 hash) internal view returns (bytes32) {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = d.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        bytes32 structHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, hash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
