// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Contracts
import { WebAuthnSessionValidator } from "@validators/WebAuthnSessionValidator.sol";
import {
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";
import { HashLib } from "@lib/HashLib.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";
import { Base64 } from "solady/utils/Base64.sol";
import { P256 } from "solady/utils/P256.sol";
import { P256VerifierCode } from "@test/utils/P256VerifierCode.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Types
import {
    Mandate,
    ActionData,
    ActionSigilData,
    OutcomeSigilData,
    SignatureSigilData,
    MandateBinding,
    MandateId
} from "@types/MandateTypes.sol";

// Mocks
import { MockSwapRouter } from "@test/mock/MockSwapRouter.sol";
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title Daimon WebAuthn (P256/passkey) Session Credential Integration Tests
/// @author highskore.eth
/// @notice Issue #88 acceptance: a mandate can bind a NON-ECDSA (WebAuthn/P256) session credential and drive a
///         real execution end-to-end through the MandateEngine — bind (ROOT) → sign (passkey assertion over the
///         engine's EIP-712 execution digest) → on-chain `validateSignatureWithData` accepts → the bounded swap
///         actually runs against a live MockSwapRouter. The session key here is a software P256 passkey, not the
///         ECDSA `agentPk` the sibling {executeWithSig} suite uses: the mandate's `sessionValidator` is a REAL
///         {WebAuthnSessionValidator} and its `sessionValidatorInitData` is `abi.encode(x, y, requireUV)` for the
///         passkey's public key. Verification resolves on-chain via solady's pure-EVM P256 fallback (no RIP-7212
///         under the default EVM version), so the verify→true path is genuine, not faked. A falsification case
///         (an assertion from the WRONG passkey) proves the gate is real: it reverts {UnauthorizedExecution}.
/// @dev The WebAuthn assertion is produced in-test with the `vm.signP256` / `vm.publicKeyP256` cheatcodes plus a
///      browser-shaped `clientDataJSON` — the same `sha256(authenticatorData ‖ sha256(clientDataJSON))` message a
///      real authenticator signs — so the digest the passkey commits to is exactly the engine's execution digest.
contract Daimon_webAuthnSession_Integration_Test is Daimon_Integration_Test {
    /// @dev ERC-7579 execution mode: single call (first byte = call type 0).
    bytes32 internal constant MODE_SINGLE = bytes32(0);

    /// @dev `Executed(uint256 indexed nonce)`.
    event Executed(uint256 indexed nonce);

    /// @dev Any relayer; security is the signature + sigils, not msg.sender.
    address internal constant RELAYER = address(0xCAFE);

    /// @dev The mock router pulls `amountIn` of the input token from the account before minting the output.
    uint256 internal constant AMOUNT_IN = 100e6;

    /// @dev The slippage floor the output must clear (well below the 1:1 output).
    uint256 internal constant AMOUNT_OUT_MIN = 1;

    /// @dev The software passkey's P256 private key (the genuine session credential).
    uint256 internal constant PASSKEY_PK = uint256(0xA7A7);

    /// @dev A DIFFERENT P256 private key whose assertions the bound credential must reject (falsification).
    uint256 internal constant WRONG_PK = uint256(0xBAD5);

    WebAuthnSessionValidator internal webAuthnSession;
    MockSwapRouter internal swapRouter;
    MockERC20 internal tokenIn;
    MockERC20 internal tokenOut;

    /// @dev The passkey's public key coordinates (derived from {PASSKEY_PK}).
    bytes32 internal pkX;
    bytes32 internal pkY;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        // The real session validator (NOT a mock) — the engine forwards the session sig to it verbatim.
        webAuthnSession = new WebAuthnSessionValidator();

        // Foundry has no RIP-7212 precompile under the default EVM version, so etch solady's pure-EVM P256
        // verifier at `P256.VERIFIER` — exactly as the unit suite does — so on-chain verification resolves.
        vm.etch(P256VerifierCode.ADDR, P256VerifierCode.CODE);

        // Derive the passkey's public key from its private key (the credential the mandate binds).
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        pkX = bytes32(x);
        pkY = bytes32(y);

        // A live router + tokens so the bounded action actually executes (effect observed end-to-end).
        swapRouter = new MockSwapRouter();
        tokenIn = new MockERC20("In", "IN");
        tokenOut = new MockERC20("Out", "OUT");
        tokenIn.mint(address(daimon), 1_000_000e6);
        vm.prank(address(daimon));
        tokenIn.approve(address(swapRouter), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice HAPPY PATH (the #88 acceptance criterion): a mandate binds a WebAuthn/P256 session credential;
    ///         the passkey signs the engine's execution digest; the engine's `validateSignatureWithData` ACCEPTS
    ///         the assertion on-chain; and the recipient-locked swap actually runs — the account receives the
    ///         output and `Executed` is emitted. Proves bind → sign → on-chain accept end-to-end through the
    ///         MandateEngine with a non-ECDSA credential.
    function test_webAuthnSession_bindAndExecute_succeeds() external {
        Mandate memory s = _webAuthnSwapSession();
        MandateId pid = _mandateId(s);

        uint256 nonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes32 digest = _execDigest(mode, ed, nonce);

        // ROOT enables the mandate; the passkey signs the execution digest (the WebAuthn challenge).
        bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: address(root1), rootSignature: rootSig });
        bytes memory keySig = _webAuthnAssertion(PASSKEY_PK, digest);
        bytes memory sig = abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));

        uint256 balBefore = tokenOut.balanceOf(address(daimon));
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        // Act & Assert: the passkey-authorized swap executes.
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig);

        assertTrue(daimon.isMandateBound(pid), "the WebAuthn mandate must be enabled");
        assertEq(
            tokenOut.balanceOf(address(daimon)) - balBefore,
            AMOUNT_IN,
            "the passkey-authorized swap must deliver output to the account"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            AMOUNT_IN,
            "the router must pull amountIn of the input token from the account"
        );
    }

    /// @notice HAPPY PATH (USE mode): once the WebAuthn mandate is bound, a subsequent USE-mode execution
    ///         authorized by a fresh passkey assertion over the new execution digest also runs — proving the
    ///         credential is reusable across executions (each over its own digest), not a one-shot bind.
    function test_webAuthnSession_use_afterBind_succeeds() external {
        Mandate memory s = _webAuthnSwapSession();
        MandateId pid = _mandateId(s);

        // Bind at exec nonce 1.
        {
            (bytes32 m0, bytes memory ed0) = _swapExec(address(daimon));
            bytes32 d0 = _execDigest(m0, ed0, 1);
            bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
            MandateBinding memory en = MandateBinding({
                session: s, rootValidator: address(root1), rootSignature: rootSig
            });
            bytes memory bindSig = abi.encodePacked(
                bytes1(0x01), bytes1(0x01), abi.encode(en, _webAuthnAssertion(PASSKEY_PK, d0))
            );
            vm.prank(RELAYER);
            daimon.executeWithSig(m0, ed0, 1, type(uint256).max, bindSig);
        }

        // USE at exec nonce 2: `[0x01][0x00][mandateId][webauthn keySig]`.
        uint256 nonce = 2;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes32 digest = _execDigest(mode, ed, nonce);
        bytes memory keySig = _webAuthnAssertion(PASSKEY_PK, digest);
        bytes memory sig =
            abi.encodePacked(bytes1(0x01), bytes1(0x00), MandateId.unwrap(pid), keySig);

        uint256 balBefore = tokenOut.balanceOf(address(daimon));

        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(address(daimon)) - balBefore,
            AMOUNT_IN,
            "a USE-mode passkey assertion must also execute the bounded swap"
        );
    }

    /// @notice FALSIFICATION: an assertion from the WRONG passkey (a different P256 key than the one the mandate
    ///         bound) must NOT authorize the execution. The engine's `validateSignatureWithData` rejects it
    ///         (P256 verify fails for the bound credential), so `executeWithSig` reverts
    ///         {UnauthorizedExecution} and NO swap runs. If the validator were a no-op (always-true), this test
    ///         would fail — proving the on-chain gate is real.
    function test_webAuthnSession_use_wrongPasskey_revertsUnauthorized() external {
        Mandate memory s = _webAuthnSwapSession();
        MandateId pid = _mandateId(s);

        // Bind the mandate with a genuine assertion at nonce 1.
        {
            (bytes32 m0, bytes memory ed0) = _swapExec(address(daimon));
            bytes32 d0 = _execDigest(m0, ed0, 1);
            bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
            MandateBinding memory en = MandateBinding({
                session: s, rootValidator: address(root1), rootSignature: rootSig
            });
            bytes memory bindSig = abi.encodePacked(
                bytes1(0x01), bytes1(0x01), abi.encode(en, _webAuthnAssertion(PASSKEY_PK, d0))
            );
            vm.prank(RELAYER);
            daimon.executeWithSig(m0, ed0, 1, type(uint256).max, bindSig);
        }

        // USE at nonce 2, but signed by the WRONG passkey over the correct digest.
        uint256 nonce = 2;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes32 digest = _execDigest(mode, ed, nonce);
        bytes memory wrongKeySig = _webAuthnAssertion(WRONG_PK, digest);
        bytes memory sig =
            abi.encodePacked(bytes1(0x01), bytes1(0x00), MandateId.unwrap(pid), wrongKeySig);

        uint256 balBefore = tokenOut.balanceOf(address(daimon));

        // Act & Assert: the wrong-key assertion is rejected by the validator -> UnauthorizedExecution.
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(address(daimon)),
            balBefore,
            "a wrong-passkey assertion must not execute the swap"
        );
    }

    /// @notice FALSIFICATION (tampered authenticatorData): a genuine assertion from the BOUND passkey, but whose
    ///         `authenticatorData` is mutated after signing, breaks the signed message hash
    ///         (`sha256(authenticatorData ‖ sha256(clientDataJSON))` no longer matches), so the validator rejects
    ///         it and `executeWithSig` reverts {UnauthorizedExecution}. Proves the assertion is bound to its full
    ///         content, not just the key.
    function test_webAuthnSession_use_tamperedAuthData_revertsUnauthorized() external {
        Mandate memory s = _webAuthnSwapSession();
        MandateId pid = _mandateId(s);

        // Bind first.
        {
            (bytes32 m0, bytes memory ed0) = _swapExec(address(daimon));
            bytes32 d0 = _execDigest(m0, ed0, 1);
            bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
            MandateBinding memory en = MandateBinding({
                session: s, rootValidator: address(root1), rootSignature: rootSig
            });
            bytes memory bindSig = abi.encodePacked(
                bytes1(0x01), bytes1(0x01), abi.encode(en, _webAuthnAssertion(PASSKEY_PK, d0))
            );
            vm.prank(RELAYER);
            daimon.executeWithSig(m0, ed0, 1, type(uint256).max, bindSig);
        }

        // USE at nonce 2, with a genuine assertion whose authenticatorData has been tampered post-signing.
        uint256 nonce = 2;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes32 digest = _execDigest(mode, ed, nonce);
        bytes memory tamperedKeySig = _webAuthnAssertionTamperedAuthData(PASSKEY_PK, digest);
        bytes memory sig =
            abi.encodePacked(bytes1(0x01), bytes1(0x00), MandateId.unwrap(pid), tamperedKeySig);

        uint256 balBefore = tokenOut.balanceOf(address(daimon));

        // Act & Assert.
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(address(daimon)),
            balBefore,
            "a tampered-authData assertion must not execute the swap"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          MANDATE / EXEC HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The recipient-locked swap mandate, but with the WebAuthn session validator + P256 credential. The
    ///      `to` recipient is pinned to the account (OmniSigil rule at calldata offset 96). A distinct salt keeps
    ///      its MandateId clear of the ECDSA suites.
    function _webAuthnSwapSession() internal view returns (Mandate memory s) {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 96, // `to` in the swapExactTokensForTokens head
            isLimited: false,
            ref: bytes32(uint256(uint160(address(daimon)))),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: type(uint256).max,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        ActionSigilData[] memory sigils = new ActionSigilData[](1);
        sigils[0] = ActionSigilData({ sigil: address(omni), initData: abi.encode(cfg) });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] =
            ActionData({ target: address(swapRouter), selector: SWAP_SELECTOR, sigils: sigils });

        s = Mandate({
            sessionValidator: ISessionValidator(address(webAuthnSession)),
            sessionValidatorInitData: abi.encode(pkX, pkY, true), // (x, y, requireUV)
            salt: bytes32(uint256(0xA11)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev The raw `swapExactTokensForTokens(... recipient ...)` calldata routed to `recipient`.
    function _swapData(address recipient) internal view returns (bytes memory) {
        address[] memory path = new address[](2);
        path[0] = address(tokenIn);
        path[1] = address(tokenOut);
        return abi.encodeWithSelector(
            SWAP_SELECTOR, AMOUNT_IN, AMOUNT_OUT_MIN, path, recipient, uint256(0)
        );
    }

    /// @dev A single-call (ERC-7579 single mode) execution routing the swap to `recipient`.
    function _swapExec(address recipient)
        internal
        view
        returns (bytes32 mode, bytes memory executionData)
    {
        mode = MODE_SINGLE;
        executionData = abi.encodePacked(address(swapRouter), uint256(0), _swapData(recipient));
    }

    /// @dev The EIP-712 execution digest the session key signs over (mirrors {Daimon_Integration_Test} /
    ///      the contract): `_hashTypedData(EXEC structHash)` under the account's domain.
    function _execDigest(
        bytes32 mode,
        bytes memory executionData,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = daimon.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                HashLib.EXEC_TYPEHASH, mode, keccak256(executionData), nonce, type(uint256).max
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /*//////////////////////////////////////////////////////////////
                        WEBAUTHN ASSERTION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Produce a genuine WebAuthn/P256 assertion (the session `keySig`) over the engine's execution
    ///      `digest`, signed by `pk`. Builds the browser-shaped `clientDataJSON` (challenge =
    ///      base64url(abi.encode(digest)), exactly the challenge the validator computes), an authenticatorData
    ///      with UP|UV flags set, computes the WebAuthn message `sha256(authData ‖ sha256(clientDataJSON))`,
    ///      signs it with `vm.signP256` (low-s normalized), and ABI-encodes the {WebAuthn.WebAuthnAuth}.
    function _webAuthnAssertion(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        WebAuthn.WebAuthnAuth memory auth = _buildAuth(pk, digest, _authenticatorData());
        return abi.encode(auth);
    }

    /// @dev Same as {_webAuthnAssertion}, but the `authenticatorData` is MUTATED after the signature is
    ///      produced — so the signed message hash no longer matches and verification must fail.
    function _webAuthnAssertionTamperedAuthData(
        uint256 pk,
        bytes32 digest
    )
        internal
        pure
        returns (bytes memory)
    {
        WebAuthn.WebAuthnAuth memory auth = _buildAuth(pk, digest, _authenticatorData());
        // Flip a byte in the signed authenticatorData (the 4-byte counter tail) — flags stay UP|UV so the flag
        // gate still passes, but the message hash diverges from what was signed.
        auth.authenticatorData[36] = 0xFF;
        return abi.encode(auth);
    }

    /// @dev Assemble + P256-sign a {WebAuthn.WebAuthnAuth} for `digest` over the given `authData`.
    function _buildAuth(
        uint256 pk,
        bytes32 digest,
        bytes memory authData
    )
        internal
        pure
        returns (WebAuthn.WebAuthnAuth memory auth)
    {
        // The validator uses `abi.encode(hash)` as the WebAuthn challenge; the browser encodes it base64url.
        string memory challengeB64 = Base64.encode(abi.encode(digest), true, true);
        // Build clientDataJSON from named parts so the WebAuthn offsets are DERIVED from the prefixes, not
        // hardcoded magic numbers (any tweak to the JSON order then updates the indices automatically):
        // `typeIndex` is where `"type":...` begins (right after the opening `{`); `challengeIndex` is where
        // `"challenge":...` begins (right after the type field + separator).
        string memory opening = "{";
        string memory typeField = '"type":"webauthn.get"';
        string memory sep = ",";
        uint256 typeIndex = bytes(opening).length;
        uint256 challengeIndex = bytes(string.concat(opening, typeField, sep)).length;
        string memory clientDataJSON = string.concat(
            opening,
            typeField,
            sep,
            '"challenge":"',
            challengeB64,
            '","origin":"https://daimon.local","crossOrigin":false}'
        );

        // WebAuthn message: sha256(authenticatorData ‖ sha256(clientDataJSON)).
        bytes32 messageHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));

        (bytes32 r, bytes32 sRaw) = vm.signP256(pk, messageHash);
        bytes32 sLow = _lowS(sRaw);

        auth = WebAuthn.WebAuthnAuth({
            authenticatorData: authData,
            clientDataJSON: clientDataJSON,
            challengeIndex: challengeIndex,
            typeIndex: typeIndex,
            r: r,
            s: sLow
        });
    }

    /// @dev A 37-byte authenticatorData: 32-byte rpIdHash ‖ flags (UP|UV = 0x05) ‖ 4-byte signCount. Length is
    ///      > 0x20 and the flags byte (offset 32) satisfies solady's UP|UV gate.
    function _authenticatorData() internal pure returns (bytes memory) {
        bytes32 rpIdHash = sha256("daimon.local");
        return abi.encodePacked(rpIdHash, bytes1(0x05), bytes4(0x00000001));
    }

    /// @dev Normalize a P256 `s` to the low half-order (solady's `WebAuthn.verify` rejects `s > N/2`).
    function _lowS(bytes32 s) internal pure returns (bytes32) {
        uint256 sv = uint256(s);
        if (sv > P256.N / 2) sv = P256.N - sv;
        return bytes32(sv);
    }
}
