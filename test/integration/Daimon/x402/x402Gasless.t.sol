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
import { MockUSDC3009 } from "@test/mock/MockUSDC3009.sol";

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

/// @title Daimon x402 GASLESS (EIP-3009 voucher) Integration Tests
/// @author highskore.eth
/// @notice Proves the GASLESS x402 settlement path end-to-end and proves it is MANDATE-bounded. The Daimon
///         account 1271-signs an EIP-3009 `transferWithAuthorization` over a 1271-capable token
///         ({MockUSDC3009}); a relayer (any caller) submits it; the payer pays no gas — there is NO
///         {executeWithSig} here. The signing capability is gated by an {AttestationSigil} "voucher":
///
///           - `allowedSenders` = [the token]   (the token is `msg.sender` of `isValidSignature`),
///           - `allowedHashes`  = [the NESTED digest of the SPECIFIC EIP-3009 authorization] — the voucher.
///
///         This REUSES the audited {AttestationSigil} + the ERC-7739 1271 path (no new sigil). The voucher
///         pins payee / amount / window / nonce into the EIP-3009 digest, so it authorizes exactly ONE
///         payment: a different payee, a different amount, an out-of-window time, an off-voucher digest, or a
///         replayed nonce all fail and move no funds. No cumulative cap is needed — each voucher is single-use
///         via the EIP-3009 nonce. (The "≤cap-to-allowlisted-payee" policy variant — a recurring allowance
///         rather than a single pinned payment — is a follow-up.)
contract Daimon_x402Gasless_Integration_Test is Integration_Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    /// @dev keccak256("PersonalSign(bytes prefixed)").
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @dev The intended payee (the x402 resource server) and an attacker-chosen alternate payee.
    address internal constant PAYEE = address(0xBEEF);
    address internal constant EVIL_PAYEE = address(0xBADD);

    /// @dev The pinned payment amount and the (single) authorization nonce.
    uint256 internal constant PAY_AMOUNT = 10e6; // 10 "USDC" (6 decimals)
    uint256 internal constant FUND_AMOUNT = 1000e6;
    bytes32 internal constant PAY_NONCE = keccak256("x402-voucher-nonce-1");

    Daimon internal daimon;
    MockUSDC3009 internal token;
    ECDSAValidator internal root1;
    ECDSASessionValidator internal sessionValidator;
    AttestationSigil internal sigPolicy;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal agent;
    uint256 internal agentPk;
    uint256 internal strangerPk;

    /// @dev The voucher's validity window. Set wide in {setUp}; warped past in the out-of-window test.
    uint256 internal validAfter;
    uint256 internal validBefore;

    /// @dev The raw EIP-3009 `transferWithAuthorization` digest (what {MockUSDC3009} passes to
    ///      `isValidSignature`) and its ERC-7739-NESTED form (the value that reaches the {AttestationSigil}
    ///      gate + that the session key signs — i.e. the voucher placed in `allowedHashes`). Both computed in
    ///      {setUp} once the account + token addresses are known.
    bytes32 internal rawAuthDigest;
    bytes32 internal voucherHash;

    function setUp() public virtual {
        // A fixed, non-zero base time so `validAfter` can be strictly in the past at call time.
        vm.warp(1_000_000);
        validAfter = block.timestamp - 1;
        validBefore = block.timestamp + 1 days;

        // Accounts run as ERC-1967 proxies (the impl disables initializers); deploy a proxy to init.
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        token = new MockUSDC3009("Mock USDC", "mUSDC");
        root1 = new ECDSAValidator();
        sessionValidator = new ECDSASessionValidator();
        sigPolicy = new AttestationSigil();
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (agent, agentPk) = makeAddrAndKey("agent");
        (, strangerPk) = makeAddrAndKey("stranger");

        // The voucher: the raw EIP-3009 digest for (account → PAYEE, PAY_AMOUNT, window, PAY_NONCE), then
        // NESTED into the account's ERC-7739 PersonalSign domain. The token verifies the RAW digest, but
        // solady nests it before the validation override, so the value the gate sees + the key signs is the
        // nested one — that is what `allowedHashes` must pin (1:1 with the raw digest).
        rawAuthDigest =
            _eip3009Digest(address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE);
        voucherHash = _personalSignDigest(daimon, rawAuthDigest);

        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);

        // Genesis-bind a mandate whose signing capability is gated by the AttestationSigil voucher:
        // sender = the token, hash = the nested EIP-3009 voucher. Genesis is the no-signature bind path.
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _voucherMandate();
        daimon.initialize(vs, ds, ms);

        // Fund the account so a transfer can actually move tokens.
        token.mint(address(daimon), FUND_AMOUNT);
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    /// @notice GASLESS x402: a relayer submits the account's voucher-authorized EIP-3009 transfer; the
    ///         account 1271-approves it (token = allowlisted sender, voucher = allowlisted hash), the funds
    ///         move (account −X, PAYEE +X), and the authorization nonce is marked used. NO `executeWithSig`.
    function test_x402Gasless_voucher_settles() external {
        bytes memory sig = _voucherSig(_mandateId(), agentPk, rawAuthDigest);

        uint256 acctBefore = token.balanceOf(address(daimon));
        uint256 payeeBefore = token.balanceOf(PAYEE);

        // Any caller (the relayer) submits it — not the account, not the agent.
        vm.prank(address(0xCAFE));
        token.transferWithAuthorization(
            address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(address(daimon)), acctBefore - PAY_AMOUNT, "account debited X");
        assertEq(token.balanceOf(PAYEE), payeeBefore + PAY_AMOUNT, "payee credited X");
        assertTrue(token.authorizationState(address(daimon), PAY_NONCE), "nonce marked used");
    }

    /// @notice The account's `isValidSignature` accepts exactly the voucher digest from the token (sanity:
    ///         the gate is the thing that authorizes the gasless settlement).
    function test_x402Gasless_isValidSignature_acceptsVoucher() external {
        bytes memory sig = _voucherSig(_mandateId(), agentPk, rawAuthDigest);
        vm.prank(address(token));
        assertEq(
            daimon.isValidSignature(rawAuthDigest, sig), MAGIC_VALUE, "voucher digest accepted"
        );
    }

    /*//////////////////////////////////////////////////////////////
                             ADVERSARIAL
    //////////////////////////////////////////////////////////////*/

    /// @notice A DIFFERENT PAYEE: the EIP-3009 digest changes, so it nests to a hash NOT in `allowedHashes`.
    ///         The account 1271-rejects and no funds move.
    function test_x402Gasless_wrongPayee_rejected() external {
        bytes32 raw = _eip3009Digest(
            address(daimon), EVIL_PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE
        );
        bytes memory sig = _voucherSig(_mandateId(), agentPk, raw);

        uint256 acctBefore = token.balanceOf(address(daimon));
        // The settlement reverts: the account's 1271 path rejects the off-voucher nested digest. The token
        // normalizes a 1271 reject (return non-magic OR revert) into its own `InvalidSignature` via try/catch,
        // so we can assert that exact selector + that no funds moved.
        vm.prank(address(0xCAFE));
        vm.expectRevert(MockUSDC3009.InvalidSignature.selector);
        token.transferWithAuthorization(
            address(daimon), EVIL_PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(address(daimon)), acctBefore, "no debit on wrong payee");
        assertEq(token.balanceOf(EVIL_PAYEE), 0, "evil payee got nothing");
    }

    /// @notice A DIFFERENT AMOUNT: the digest changes → off-voucher hash → 1271-reject, no transfer.
    function test_x402Gasless_wrongAmount_rejected() external {
        uint256 evilAmount = PAY_AMOUNT * 5;
        bytes32 raw =
            _eip3009Digest(address(daimon), PAYEE, evilAmount, validAfter, validBefore, PAY_NONCE);
        bytes memory sig = _voucherSig(_mandateId(), agentPk, raw);

        uint256 acctBefore = token.balanceOf(address(daimon));
        // Reverts: off-voucher digest → 1271 reject → the token's `InvalidSignature` (try/catch normalized).
        vm.prank(address(0xCAFE));
        vm.expectRevert(MockUSDC3009.InvalidSignature.selector);
        token.transferWithAuthorization(
            address(daimon), PAYEE, evilAmount, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(address(daimon)), acctBefore, "no debit on wrong amount");
    }

    /// @notice OUT OF WINDOW: even with a valid voucher signature, the token rejects an expired window
    ///         (`block.timestamp >= validBefore`) before any signature check — no transfer.
    function test_x402Gasless_outOfWindow_rejected() external {
        bytes memory sig = _voucherSig(_mandateId(), agentPk, rawAuthDigest);

        // Warp past the voucher's validBefore.
        vm.warp(validBefore + 1);

        uint256 acctBefore = token.balanceOf(address(daimon));
        vm.prank(address(0xCAFE));
        vm.expectRevert(MockUSDC3009.AuthorizationExpired.selector);
        token.transferWithAuthorization(
            address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(address(daimon)), acctBefore, "no debit out of window");
    }

    /// @notice REPLAY: the SAME voucher cannot settle twice. The first call succeeds and marks the nonce
    ///         used; the second reverts on replay protection and moves no further funds.
    function test_x402Gasless_replay_rejected() external {
        bytes memory sig = _voucherSig(_mandateId(), agentPk, rawAuthDigest);

        vm.prank(address(0xCAFE));
        token.transferWithAuthorization(
            address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );
        uint256 acctAfterFirst = token.balanceOf(address(daimon));

        vm.prank(address(0xCAFE));
        vm.expectRevert(MockUSDC3009.AuthorizationUsedAlready.selector);
        token.transferWithAuthorization(
            address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(address(daimon)), acctAfterFirst, "no second debit on replay");
        assertEq(token.balanceOf(PAYEE), PAY_AMOUNT, "payee credited exactly once");
    }

    /// @notice OFF-VOUCHER DIGEST: a well-formed authorization whose digest is simply NOT the pinned voucher
    ///         (here a fresh nonce, so a brand-new digest) is 1271-rejected — the hash allowlist pins exactly
    ///         the one voucher. Confirms `isValidSignature` itself denies, and the token transfer reverts.
    function test_x402Gasless_offVoucherDigest_rejected() external {
        bytes32 otherNonce = keccak256("some-other-nonce");
        bytes32 raw =
            _eip3009Digest(address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, otherNonce);

        // The account 1271-rejects the off-voucher nested digest directly.
        bytes memory sig = _voucherSig(_mandateId(), agentPk, raw);
        vm.prank(address(token));
        assertFalse(_accepts(raw, sig), "off-voucher digest must be 1271-rejected");

        // And the gasless settlement attempt reverts with the token's `InvalidSignature` (1271 reject
        // normalized via try/catch) and no funds moved.
        uint256 acctBefore = token.balanceOf(address(daimon));
        vm.prank(address(0xCAFE));
        vm.expectRevert(MockUSDC3009.InvalidSignature.selector);
        token.transferWithAuthorization(
            address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, otherNonce, sig
        );
        assertEq(token.balanceOf(address(daimon)), acctBefore, "no debit on off-voucher digest");
    }

    /// @notice WRONG REQUESTING SENDER: even the correct voucher digest is rejected if the requester is not
    ///         the allowlisted token (anti-phishing). A different `msg.sender` to `isValidSignature` fails.
    function test_x402Gasless_wrongSender_rejected() external {
        bytes memory sig = _voucherSig(_mandateId(), agentPk, rawAuthDigest);
        vm.prank(EVIL_PAYEE); // not the token
        assertFalse(_accepts(rawAuthDigest, sig), "non-token requester must be rejected");
    }

    /// @notice WRONG SESSION KEY: a signature from a key that is not the mandate's session key is rejected
    ///         even for the correct voucher + sender.
    function test_x402Gasless_wrongSessionKey_rejected() external {
        bytes memory sig = _voucherSig(_mandateId(), strangerPk, rawAuthDigest);
        vm.prank(address(token));
        assertFalse(_accepts(rawAuthDigest, sig), "wrong session key must be rejected");
    }

    /// @notice EOA PAYER (the real-USDC-equivalent path): a `from` with no code is verified by `ecrecover`,
    ///         not 1271. Confirms the `from.code.length == 0` branch settles a correctly-signed authorization.
    function test_x402_eoaPayer_settles() external {
        (address eoa, uint256 eoaPk) = makeAddrAndKey("eoaPayer");
        token.mint(eoa, FUND_AMOUNT);
        bytes32 raw = _eip3009Digest(eoa, PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPk, raw); // EOA signs the RAW digest directly (no nesting)
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 payeeBefore = token.balanceOf(PAYEE);
        vm.prank(address(0xCAFE));
        token.transferWithAuthorization(
            eoa, PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(eoa), FUND_AMOUNT - PAY_AMOUNT, "EOA debited X");
        assertEq(token.balanceOf(PAYEE), payeeBefore + PAY_AMOUNT, "payee credited X");
    }

    /// @notice EOA PAYER, WRONG KEY: a signature from a different key recovers to a non-`from` address, so the
    ///         `ecrecover` branch rejects it (and the zero-recovery guard rejects a malformed one).
    function test_x402_eoaPayer_wrongKey_rejected() external {
        (address eoa,) = makeAddrAndKey("eoaPayer");
        token.mint(eoa, FUND_AMOUNT);
        bytes32 raw = _eip3009Digest(eoa, PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(strangerPk, raw); // NOT the eoa's key
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(0xCAFE));
        vm.expectRevert(MockUSDC3009.InvalidSignature.selector);
        token.transferWithAuthorization(
            eoa, PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The voucher mandate: its ONLY capability is 1271-signing for the token (sender) + the pinned
    ///      nested EIP-3009 digest (hash). No on-chain actions — settlement is gasless via EIP-3009.
    function _voucherMandate() internal view returns (Mandate memory s) {
        address[] memory senders = new address[](1);
        senders[0] = address(token);
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = voucherHash;
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
            salt: bytes32(uint256(0x402)),
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: sigs
        });
    }

    /// @dev The voucher mandate's id.
    function _mandateId() internal view returns (MandateId) {
        return _mandateId(_voucherMandate());
    }

    /// @dev The MandateId of an arbitrary mandate (matches IdLib.toMandateId).
    function _mandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @dev Build a MANDATE-mode 1271 signature the TOKEN will pass back to the account:
    ///      [0x01][mandateId][abi.encode(content, keySig)]. The content blob is unused by the gate; the
    ///      session key signs the ERC-7739-NESTED digest of the RAW EIP-3009 digest the token computes.
    function _voucherSig(
        MandateId pid,
        uint256 pk,
        bytes32 rawDigest
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 nested = _personalSignDigest(daimon, rawDigest);
        bytes memory keySig = _sign(pk, nested);
        // The 1271 content blob is irrelevant to the voucher gate (it binds `hash`, not content).
        return abi.encodePacked(bytes1(0x01), MandateId.unwrap(pid), abi.encode(bytes(""), keySig));
    }

    /// @dev True iff the account accepts `sig` (returns the ERC-1271 magic value). A revert counts as
    ///      not-accepted (solady's ERC-7739 may probe a rejected sig).
    function _accepts(bytes32 hash, bytes memory sig) internal view returns (bool) {
        try daimon.isValidSignature(hash, sig) returns (bytes4 mv) {
            return mv == MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev The RAW EIP-3009 `transferWithAuthorization` digest, computed exactly as {MockUSDC3009} does
    ///      (EIP-712 over the token domain). This is the value the token passes to `isValidSignature`.
    function _eip3009Digest(
        address from,
        address to,
        uint256 value,
        uint256 va,
        uint256 vb,
        bytes32 nonce
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), from, to, value, va, vb, nonce)
        );
        return keccak256(abi.encodePacked(hex"1901", token.DOMAIN_SEPARATOR(), structHash));
    }

    /// @dev The ERC-7739 PersonalSign digest solady reconstructs when no TypedDataSign data is appended:
    ///      `_hashTypedData(keccak256(PERSONAL_SIGN_TYPEHASH, hash))` over the ACCOUNT's domain. This nests
    ///      the raw EIP-3009 digest into the value the gate sees + the session key signs.
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
