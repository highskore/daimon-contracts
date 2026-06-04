// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Integration_Test } from "../../Base.integration.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { LibClone } from "solady/utils/LibClone.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";
import { Eip3009Sigil } from "@sigils/Eip3009Sigil/Eip3009Sigil.sol";
import { Eip3009Config } from "@sigils/Eip3009Sigil/lib/Eip3009ConfigLib.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";
import { ConfigId, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

// Types
import {
    Mandate,
    ActionData,
    OutcomeSigilData,
    SignatureSigilData,
    MandateId
} from "@types/MandateTypes.sol";

/// @title Daimon Eip3009Sigil (content-aware x402 voucher) Integration Tests
/// @author highskore.eth
/// @notice Proves {Eip3009Sigil}: the agent's session key may 1271-sign EIP-3009 `transferWithAuthorization`s
///         to an ALLOWLISTED payee under a per-authorization CAP — any matching payment, not one pinned digest.
///         Drives the real ERC-1271 path (TypedDataSign, so {DaimonERC7739} threads the verified contents) with
///         the token pranked as `msg.sender`. The TypedDataSign signature is self-correcting: a wrong build
///         fails solady's app-hash consistency check or the session-key check, so it cannot false-pass.
contract Daimon_Eip3009Sigil_Integration_Test is Integration_Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes32 internal constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    string internal constant CONTENTS_NAME = "TransferWithAuthorization";
    string internal constant CONTENTS_TYPE =
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

    /// @dev The token whose EIP-3009 authorizations this voucher signs (pranked as msg.sender), its domain
    ///      separator, the allowlisted payee, an off-allowlist payee, and the cap.
    address internal constant TOKEN = address(0x70C0);
    bytes32 internal constant TOKEN_DOMAIN_SEPARATOR = keccak256("mock-usdc-3009-domain");
    address internal constant PAYEE = address(0xBEEF);
    address internal constant EVIL_PAYEE = address(0xBADD);
    uint256 internal constant CAP = 10e6;

    Daimon internal daimon;
    ECDSAValidator internal root1;
    ECDSASessionValidator internal sessionValidator;
    Eip3009Sigil internal sigil;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal agent;
    uint256 internal agentPk;

    function setUp() public virtual {
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        root1 = new ECDSAValidator();
        sessionValidator = new ECDSASessionValidator();
        sigil = new Eip3009Sigil();
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (agent, agentPk) = makeAddrAndKey("agent");

        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _voucherMandate();
        daimon.initialize(vs, ds, ms);
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    /// @notice Any allowlisted-payee payment within the cap is signed — at the cap, and below it, to the payee.
    function test_eip3009_voucher_signsAllowlistedPayeeWithinCap() external {
        assertTrue(_accepts(PAYEE, CAP, keccak256("nonce-1")), "exactly cap, allowlisted payee");
        assertTrue(_accepts(PAYEE, 1, keccak256("nonce-2")), "below cap, allowlisted payee");
    }

    /*//////////////////////////////////////////////////////////////
                              ADVERSARIAL
    //////////////////////////////////////////////////////////////*/

    /// @notice A payment ABOVE the cap is denied.
    function test_eip3009_overCap_denied() external {
        assertFalse(_accepts(PAYEE, CAP + 1, keccak256("nonce-3")), "over cap denied");
    }

    /// @notice A payment to a NON-allowlisted payee is denied (even within the cap).
    function test_eip3009_nonAllowlistedPayee_denied() external {
        assertFalse(_accepts(EVIL_PAYEE, 1, keccak256("nonce-4")), "evil payee denied");
    }

    /// @notice A request from a DIFFERENT token (msg.sender != configured token) is denied (anti-phishing).
    function test_eip3009_wrongToken_denied() external {
        (bytes32 hash, bytes memory sig) = _voucherSig(
            agentPk, PAYEE, CAP, keccak256("nonce-5"), TOKEN_DOMAIN_SEPARATOR, address(daimon)
        );
        vm.prank(address(0xF00D)); // not TOKEN
        assertFalse(_call(hash, sig), "wrong token denied");
    }

    /// @notice A signature over a DIFFERENT token domain is denied (appDomainSeparator mismatch).
    function test_eip3009_wrongDomain_denied() external {
        (bytes32 hash, bytes memory sig) = _voucherSig(
            agentPk, PAYEE, CAP, keccak256("nonce-6"), keccak256("other-domain"), address(daimon)
        );
        vm.prank(TOKEN);
        assertFalse(_call(hash, sig), "wrong domain denied");
    }

    /// @notice Tampering the supplied fields so they no longer hash to the signed `contentsHash` is denied
    ///         (the soundness anchor): here the relayer swaps the payee in the content blob after signing.
    function test_eip3009_tamperedFields_denied() external {
        // Sign for PAYEE, but submit a content blob that claims EVIL_PAYEE — keccak(fields) != contentsHash.
        (bytes32 hash, bytes memory sig) = _voucherSigTampered(agentPk, keccak256("nonce-7"));
        vm.prank(TOKEN);
        assertFalse(_call(hash, sig), "tampered fields denied");
    }

    /// @notice A non-session key cannot produce an accepted voucher (session-key check fails).
    function test_eip3009_wrongSigner_denied() external {
        (, uint256 strangerPk) = makeAddrAndKey("stranger");
        (bytes32 hash, bytes memory sig) = _voucherSig(
            strangerPk, PAYEE, CAP, keccak256("nonce-8"), TOKEN_DOMAIN_SEPARATOR, address(daimon)
        );
        vm.prank(TOKEN);
        assertFalse(_call(hash, sig), "wrong signer denied");
    }

    /// @notice An EXPIRED voucher (validBefore <= block.timestamp) is denied — mirrors the token's own
    ///         `block.timestamp >= validBefore` revert, so the sigil never signs an authorization the token
    ///         would reject on submission.
    function test_eip3009_expired_denied() external {
        // validBefore == now: strict `block.timestamp >= vb` rejects it.
        (bytes32 hash, bytes memory sig) =
            _voucherSigTimed(agentPk, keccak256("nonce-exp"), 0, block.timestamp);
        vm.prank(TOKEN);
        assertFalse(_call(hash, sig), "expired voucher (vb == now) denied");
    }

    /// @notice A NOT-YET-VALID voucher (validAfter >= block.timestamp) is denied — mirrors the token's own
    ///         `block.timestamp <= validAfter` revert.
    function test_eip3009_notYetValid_denied() external {
        // validAfter == now: strict `block.timestamp <= va` rejects it.
        (bytes32 hash, bytes memory sig) = _voucherSigTimed(
            agentPk, keccak256("nonce-early"), block.timestamp, type(uint256).max
        );
        vm.prank(TOKEN);
        assertFalse(_call(hash, sig), "not-yet-valid voucher (va == now) denied");
    }

    /// @notice A voucher strictly INSIDE the window (validAfter < now < validBefore) still signs.
    function test_eip3009_withinWindow_signs() external {
        vm.warp(1000);
        (bytes32 hash, bytes memory sig) =
            _voucherSigTimed(agentPk, keccak256("nonce-window"), 999, 1001);
        vm.prank(TOKEN);
        assertTrue(_call(hash, sig), "voucher within (va,vb) window signs");
    }

    /// @notice A `to` equal to solady's reserved set sentinel returns a CLEAN {VALIDATION_FAILED} (not a
    ///         bubbled revert) — fail-closed even on attacker-chosen voucher content. Calls {check1271} directly
    ///         (this test is the multiplexer/account) since the engine-level revert would be masked by the
    ///         try/catch in {_call}.
    function test_eip3009_sentinelPayee_cleanDeny() external {
        ConfigId id = ConfigId.wrap(bytes32(uint256(1)));
        address[] memory payees = new address[](1);
        payees[0] = PAYEE;
        sigil.initializeWithMultiplexer(
            address(this),
            id,
            abi.encode(
                Eip3009Config({
                    token: TOKEN,
                    tokenDomainSeparator: TOKEN_DOMAIN_SEPARATOR,
                    allowedPayees: payees,
                    cap: CAP
                })
            )
        );
        address sentinel = address(uint160(0xfbb67fda52d4bfb8bf));
        bytes memory inner = abi.encode(
            address(this), sentinel, uint256(1), uint256(0), type(uint256).max, bytes32(uint256(9))
        );
        bytes32 contents = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                address(this),
                sentinel,
                uint256(1),
                uint256(0),
                type(uint256).max,
                bytes32(uint256(9))
            )
        );
        bytes memory payload =
            abi.encode(TOKEN, bytes32(0), TOKEN_DOMAIN_SEPARATOR, contents, inner);
        // The membership read would REVERT on the sentinel; the guard makes it a clean deny instead.
        assertEq(
            sigil.check1271(id, address(this), payload),
            VALIDATION_FAILED,
            "sentinel payee clean-denied"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Sign a voucher for (PAYEE-or-given, value, nonce) and call isValidSignature pranked as TOKEN.
    function _accepts(address to, uint256 value, bytes32 nonce) internal returns (bool) {
        (bytes32 hash, bytes memory sig) =
            _voucherSig(agentPk, to, value, nonce, TOKEN_DOMAIN_SEPARATOR, address(daimon));
        vm.prank(TOKEN);
        return _call(hash, sig);
    }

    /// @dev True iff the account accepts `sig` (returns the magic value); a revert (solady RPC probe) = false.
    function _call(bytes32 hash, bytes memory sig) internal view returns (bool) {
        try daimon.isValidSignature(hash, sig) returns (bytes4 mv) {
            return mv == MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev The signing-only voucher mandate gated by {Eip3009Sigil}: token + domain + [PAYEE] + CAP.
    function _voucherMandate() internal view returns (Mandate memory s) {
        address[] memory payees = new address[](1);
        payees[0] = PAYEE;
        SignatureSigilData[] memory sigs = new SignatureSigilData[](1);
        sigs[0] = SignatureSigilData({
            sigil: address(sigil),
            initData: abi.encode(
                Eip3009Config({
                    token: TOKEN,
                    tokenDomainSeparator: TOKEN_DOMAIN_SEPARATOR,
                    allowedPayees: payees,
                    cap: CAP
                })
            )
        });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x3009)),
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: sigs
        });
    }

    function _mandateId() internal view returns (MandateId) {
        Mandate memory s = _voucherMandate();
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @dev Build a TypedDataSign 1271 voucher over an EIP-3009 `TransferWithAuthorization(from→to, value, …)`.
    ///      Returns the app hash the token passes to `isValidSignature` + the modal MANDATE sig with the
    ///      TypedDataSign trailer. `inner` (the EIP-3009 fields) is carried in the modal content for the sigil.
    function _voucherSig(
        uint256 pk,
        address to,
        uint256 value,
        bytes32 nonce,
        bytes32 appDS,
        address from
    )
        internal
        view
        returns (bytes32 hash, bytes memory fullSig)
    {
        uint256 va = 0;
        uint256 vb = type(uint256).max;
        bytes memory inner = abi.encode(from, to, value, va, vb, nonce);
        bytes32 contents = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, va, vb, nonce)
        );
        return _sign(pk, appDS, contents, inner);
    }

    /// @dev Build a voucher to PAYEE for CAP with explicit validAfter / validBefore (for the time-bound paths).
    function _voucherSigTimed(
        uint256 pk,
        bytes32 nonce,
        uint256 va,
        uint256 vb
    )
        internal
        view
        returns (bytes32 hash, bytes memory fullSig)
    {
        address from = address(daimon);
        bytes memory inner = abi.encode(from, PAYEE, CAP, va, vb, nonce);
        bytes32 contents = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, PAYEE, CAP, va, vb, nonce)
        );
        return _sign(pk, TOKEN_DOMAIN_SEPARATOR, contents, inner);
    }

    /// @dev A voucher whose modal content blob claims a DIFFERENT payee than the one signed — so the sigil's
    ///      `keccak(fields) == contentsHash` anchor fails.
    function _voucherSigTampered(
        uint256 pk,
        bytes32 nonce
    )
        internal
        view
        returns (bytes32, bytes memory)
    {
        uint256 va = 0;
        uint256 vb = type(uint256).max;
        // Signed contents pin PAYEE...
        bytes32 contents = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH, address(daimon), PAYEE, CAP, va, vb, nonce
            )
        );
        // ...but the submitted blob claims EVIL_PAYEE.
        bytes memory inner = abi.encode(address(daimon), EVIL_PAYEE, CAP, va, vb, nonce);
        return _sign(pk, TOKEN_DOMAIN_SEPARATOR, contents, inner);
    }

    /// @dev Assemble the TypedDataSign signature: session key signs the account's TypedDataSign nested digest;
    ///      the trailer `appDS ‖ contents ‖ contentsType ‖ uint16(len)` is appended after the modal MANDATE sig.
    function _sign(
        uint256 pk,
        bytes32 appDS,
        bytes32 contents,
        bytes memory inner
    )
        internal
        view
        returns (bytes32 hash, bytes memory fullSig)
    {
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(pk, _typedDataFinalHash(appDS, contents));
        bytes memory modalSig = abi.encodePacked(
            bytes1(0x01),
            MandateId.unwrap(_mandateId()),
            abi.encode(inner, abi.encodePacked(r, sg, v))
        );
        bytes memory ct = bytes(CONTENTS_TYPE);
        fullSig = abi.encodePacked(modalSig, appDS, contents, ct, uint16(ct.length));
        hash = keccak256(abi.encodePacked(hex"1901", appDS, contents));
    }

    /// @dev The account-domain TypedDataSign nested digest the session key signs (own frame for stack limits).
    function _typedDataFinalHash(bytes32 appDS, bytes32 contents) internal view returns (bytes32) {
        bytes32 tdsTypehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                CONTENTS_NAME,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                CONTENTS_TYPE
            )
        );
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) =
            daimon.eip712Domain();
        bytes32 hashStruct = keccak256(
            abi.encode(
                tdsTypehash,
                contents,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                vc,
                salt
            )
        );
        return keccak256(abi.encodePacked(hex"1901", appDS, hashStruct));
    }
}
