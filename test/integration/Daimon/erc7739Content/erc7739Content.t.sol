// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Integration_Test } from "../../Base.integration.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { LibClone } from "solady/utils/LibClone.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";
import { MockContentSigil } from "@test/mock/MockContentSigil.sol";

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

/// @title Daimon ERC-7739 content threading Integration Tests
/// @author highskore.eth
/// @notice Proves {DaimonERC7739}: a TypedDataSign 1271 signature delivers the solady-VERIFIED
///         `appDomainSeparator` + `contentsHash` to a MANDATE signature sigil (so a content-aware sigil can gate
///         the SIGNED typed-data, not just the opaque hash), while the PersonalSign path still threads zeros.
///         The {MockContentSigil} accepts only when the threaded pair equals the configured expected values, so
///         a passing test means the fork delivered the right, verified content. Construction is self-correcting:
///         a wrong TypedDataSign build fails solady's `hash == keccak(0x1901‖appDS‖contents)` consistency check
///         (→ PersonalSign fallback → zeros → mock denies) or the session-key check — it can never false-pass.
contract Daimon_ERC7739Content_Integration_Test is Integration_Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    /// @dev A chosen "app" (e.g. a token / dApp) domain separator, and a test content struct.
    bytes32 internal constant APP_DOMAIN_SEPARATOR = keccak256("the-app-domain-separator");
    string internal constant CONTENTS_NAME = "Mail";
    string internal constant CONTENTS_TYPE = "Mail(address to,uint256 amount)";

    Daimon internal daimon;
    ECDSAValidator internal root1;
    ECDSASessionValidator internal sessionValidator;
    MockContentSigil internal mock;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal agent;
    uint256 internal agentPk;
    uint256 internal strangerPk;

    /// @dev The struct hash of the signed content (`Mail(0xBEEF, 7)`), and the app's EIP-712 digest over it.
    bytes32 internal contentsHash;
    bytes32 internal appHash;

    function setUp() public virtual {
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        root1 = new ECDSAValidator();
        sessionValidator = new ECDSASessionValidator();
        mock = new MockContentSigil();
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (agent, agentPk) = makeAddrAndKey("agent");
        (, strangerPk) = makeAddrAndKey("stranger");

        // The signed content: Mail(to=0xBEEF, amount=7) → its EIP-712 struct hash, and the app's digest over it.
        contentsHash =
            keccak256(abi.encode(keccak256(bytes(CONTENTS_TYPE)), address(0xBEEF), uint256(7)));
        appHash = keccak256(abi.encodePacked(hex"1901", APP_DOMAIN_SEPARATOR, contentsHash));

        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _contentMandate();
        daimon.initialize(vs, ds, ms);
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    /// @notice A TypedDataSign 1271 signature is accepted, and ONLY because the mock received the verified
    ///         `(appDomainSeparator, contentsHash)` — proving {DaimonERC7739} threaded the ERC-7739 content.
    function test_erc7739_typedDataSign_threadsVerifiedContent() external {
        (bytes32 hash, bytes memory sig) =
            _typedDataSign(agentPk, _mandateId(), APP_DOMAIN_SEPARATOR, contentsHash);
        assertEq(hash, appHash, "the app hash the dApp passes");
        assertEq(daimon.isValidSignature(hash, sig), MAGIC_VALUE, "TypedDataSign accepted");
    }

    /*//////////////////////////////////////////////////////////////
                              ADVERSARIAL
    //////////////////////////////////////////////////////////////*/

    /// @notice A TypedDataSign over a DIFFERENT content (different struct hash) is rejected: solady still
    ///         verifies it against the app hash, but the threaded `contentsHash` no longer matches the mock's
    ///         expected value.
    function test_erc7739_wrongContents_rejected() external {
        bytes32 otherContents =
            keccak256(abi.encode(keccak256(bytes(CONTENTS_TYPE)), address(0xBEEF), uint256(99)));
        (bytes32 hash, bytes memory sig) =
            _typedDataSign(agentPk, _mandateId(), APP_DOMAIN_SEPARATOR, otherContents);
        assertFalse(_accepts(hash, sig), "mismatched content denied");
    }

    /// @notice A TypedDataSign from a DIFFERENT app domain is rejected — the threaded `appDomainSeparator` is
    ///         not the configured one.
    function test_erc7739_wrongDomain_rejected() external {
        bytes32 otherDomain = keccak256("a-different-app");
        (bytes32 hash, bytes memory sig) =
            _typedDataSign(agentPk, _mandateId(), otherDomain, contentsHash);
        assertFalse(_accepts(hash, sig), "mismatched domain denied");
    }

    /// @notice A non-session key cannot produce an accepted TypedDataSign (the session-key check fails even
    ///         though the content threads correctly).
    function test_erc7739_wrongSigner_rejected() external {
        (bytes32 hash, bytes memory sig) =
            _typedDataSign(strangerPk, _mandateId(), APP_DOMAIN_SEPARATOR, contentsHash);
        assertFalse(_accepts(hash, sig), "wrong signer denied");
    }

    /// @notice The PersonalSign path threads ZERO content, so this content-gating mock denies it — confirming
    ///         the verified content arrives ONLY on the TypedDataSign path.
    function test_erc7739_personalSign_threadsZeroContent_denied() external {
        // A PersonalSign of the same app hash: no TypedDataSign trailer. solady nests it and the mock sees
        // appDomainSeparator == 0 (!= APP_DOMAIN_SEPARATOR) → denied.
        bytes32 nested = _personalSignDigest(appHash);
        bytes memory keySig = _sign(agentPk, nested);
        bytes memory sig = abi.encodePacked(
            bytes1(0x01), MandateId.unwrap(_mandateId()), abi.encode(bytes(""), keySig)
        );
        assertFalse(_accepts(appHash, sig), "personalSign content-gated out");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev True iff the account accepts `sig`. A revert counts as not-accepted — solady probes a rejected sig
    ///      down its `_erc1271IsValidSignatureViaRPC` path, which burns gas / reverts at `tx.gasprice == 0`.
    function _accepts(bytes32 hash, bytes memory sig) internal view returns (bool) {
        try daimon.isValidSignature(hash, sig) returns (bytes4 mv) {
            return mv == MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev A signing-only mandate whose sole signature sigil is the {MockContentSigil}, configured to expect
    ///      `(APP_DOMAIN_SEPARATOR, contentsHash)`.
    function _contentMandate() internal view returns (Mandate memory s) {
        SignatureSigilData[] memory sigs = new SignatureSigilData[](1);
        sigs[0] = SignatureSigilData({
            sigil: address(mock), initData: abi.encode(APP_DOMAIN_SEPARATOR, contentsHash)
        });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x7739)),
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: sigs
        });
    }

    function _mandateId() internal view returns (MandateId) {
        Mandate memory s = _contentMandate();
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @dev Build a TypedDataSign 1271 signature (solady ERC-7739 layout): the session key signs the account's
    ///      `TypedDataSign(...)` nested digest, and the trailer `appDS ‖ contents ‖ contentsType ‖ uint16(len)`
    ///      is appended after the modal MANDATE signature so solady can reconstruct + verify the content.
    /// @return hash The app digest the dApp passes to `isValidSignature` (`keccak(0x1901‖appDS‖contents)`).
    /// @return fullSig The modal MANDATE-1271 signature with the TypedDataSign trailer appended.
    function _typedDataSign(
        uint256 pk,
        MandateId pid,
        bytes32 appDS,
        bytes32 contents
    )
        internal
        view
        returns (bytes32 hash, bytes memory fullSig)
    {
        bytes32 typedDataSignTypehash = keccak256(
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
                typedDataSignTypehash,
                contents,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                vc,
                salt
            )
        );
        bytes32 finalHash = keccak256(abi.encodePacked(hex"1901", appDS, hashStruct));
        bytes memory keySig = _sign(pk, finalHash);

        bytes memory modalSig =
            abi.encodePacked(bytes1(0x01), MandateId.unwrap(pid), abi.encode(bytes(""), keySig));
        bytes memory contentsTypeBytes = bytes(CONTENTS_TYPE);
        bytes memory trailer =
            abi.encodePacked(appDS, contents, contentsTypeBytes, uint16(contentsTypeBytes.length));
        fullSig = abi.encodePacked(modalSig, trailer);
        hash = keccak256(abi.encodePacked(hex"1901", appDS, contents));
    }

    /// @dev The ERC-7739 PersonalSign digest solady reconstructs when no TypedDataSign trailer is present.
    function _personalSignDigest(bytes32 h) internal view returns (bytes32) {
        bytes32 personalSignTypehash = keccak256("PersonalSign(bytes prefixed)");
        bytes32 domainTypehash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        (, string memory name, string memory version, uint256 chainId, address vc,,) =
            daimon.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                domainTypehash, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc
            )
        );
        bytes32 structHash = keccak256(abi.encode(personalSignTypehash, h));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }
}
