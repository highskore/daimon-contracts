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
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";
import { OmniSigil } from "@sigils/OmniSigil/OmniSigil.sol";
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";
import { MockUSDC3009 } from "@test/mock/MockUSDC3009.sol";
import { MockReentrantInitSigil } from "@test/mock/MockReentrantInitSigil.sol";

// Libraries
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
import { IMandateEngine } from "@interfaces/IMandateEngine.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Types
import {
    Mandate,
    ActionData,
    ActionSigilData,
    OutcomeSigilData,
    SignatureSigilData,
    MandateId,
    ActionId,
    FALLBACK_TARGET_FLAG,
    FALLBACK_ACTIONID
} from "@types/MandateTypes.sol";

/// @title Daimon bindMandates (standalone bind) Integration Tests
/// @author highskore.eth
/// @notice Proves the STANDALONE bind path — {Daimon.bindMandates}, an `onlySelf` entry point reached via a
///         ROOT-authed {executeWithSig} self-call (`address(this).bindMandates([...])`). This closes the gap
///         that a SIGNING-ONLY mandate (an x402 voucher: attestation sigils, NO actions) could only be bound
///         at GENESIS: the inline {executeWithSig} MANDATE_BIND path requires >= 1 bundled executable call, so
///         an action-less voucher had nothing to bundle and could never be bound to a LIVE account.
///
///         Authorization model (mirrors smart-sessions' `enableSessions`): the account enables its own
///         mandates. A relayer cannot call `bindMandates` directly (`onlySelf`); the HUMAN ROOT-signs an
///         {executeWithSig} whose single call targets `address(this).bindMandates(...)`. The ROOT execution
///         branch in {ExecLib} skips per-call sigil enforcement, so it PERMITS the self-call — i.e. a ROOT
///         self-call to `address(this)` is allowed (it is the MANDATE path's `enforceAction` that blocks
///         self-calls, and ROOT skips it). So the outer ROOT signature authorizes the whole bind set; no
///         per-mandate signature is needed (exactly like genesis registration, but post-deploy).
contract Daimon_bindMandates_Integration_Test is Integration_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    /// @dev keccak256("PersonalSign(bytes prefixed)").
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @dev ERC-7579 execution mode: single call (first byte = call type 0).
    bytes32 internal constant MODE_SINGLE = bytes32(0);

    bytes4 internal constant BIND_MANDATES_SELECTOR = IDaimon.bindMandates.selector;

    /// @dev The intended x402 payee (resource server) and the relayer that submits gasless txs.
    address internal constant PAYEE = address(0xBEEF);
    address internal constant RELAYER = address(0xCAFE);

    uint256 internal constant PAY_AMOUNT = 10e6; // 10 "USDC" (6 decimals)
    uint256 internal constant FUND_AMOUNT = 1000e6;
    bytes32 internal constant PAY_NONCE = keccak256("x402-voucher-nonce-1");

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    Daimon internal daimon;
    MockUSDC3009 internal token;
    ECDSAValidator internal root1;
    ECDSASessionValidator internal sessionValidator;
    AttestationSigil internal sigPolicy;
    SudoSigil internal sudo;
    OmniSigil internal omni;
    SpendSigil internal spendSigil;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal agent;
    uint256 internal agentPk;
    uint256 internal strangerPk;

    uint256 internal validAfter;
    uint256 internal validBefore;

    /// @dev The raw EIP-3009 digest the token passes to `isValidSignature`, and its ERC-7739-nested form (the
    ///      voucher placed in `allowedHashes` and signed by the session key). Computed once the account +
    ///      token addresses are known.
    bytes32 internal rawAuthDigest;
    bytes32 internal voucherHash;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

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
        sudo = new SudoSigil();
        omni = new OmniSigil();
        spendSigil = new SpendSigil();
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (agent, agentPk) = makeAddrAndKey("agent");
        (, strangerPk) = makeAddrAndKey("stranger");

        // The voucher digest (account -> PAYEE, PAY_AMOUNT, window, PAY_NONCE), nested into the account's
        // ERC-7739 PersonalSign domain — exactly what `allowedHashes` must pin (1:1 with the raw digest).
        rawAuthDigest =
            _eip3009Digest(address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE);
        voucherHash = _personalSignDigest(daimon, rawAuthDigest);

        // GENESIS: a LIVE account with a ROOT set but NO mandates. The voucher is bound later, post-deploy,
        // via the standalone bind path — the whole point of this suite.
        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);
        daimon.initialize(vs, ds, new Mandate[](0));

        // Fund the account so a settlement can actually move tokens.
        token.mint(address(daimon), FUND_AMOUNT);
    }

    /*//////////////////////////////////////////////////////////////
                          HEADLINE (closes #63)
    //////////////////////////////////////////////////////////////*/

    /// @notice THE headline: a SIGNING-ONLY x402 voucher mandate (one AttestationSigil, NO actions) is bound to
    ///         a LIVE account via a ROOT {executeWithSig} calling `self.bindMandates([voucher])` (relayer
    ///         submitted, gasless for the human). The mandate becomes enabled, and the gasless x402 settlement
    ///         then SETTLES — proving a signing-only voucher CAN be bound post-genesis and used. Before the
    ///         standalone-bind path this was impossible: the inline MANDATE_BIND path needs a bundled call, and
    ///         an action-less voucher has none.
    function test_bindMandates_signingOnlyVoucher_boundOnLiveAccount_thenSettles() external {
        Mandate memory voucher = _voucherMandate();
        MandateId pid = _mandateId(voucher);

        // Precondition: not bound on the live account.
        assertFalse(daimon.isMandateBound(pid), "voucher must not be bound at genesis");

        // The human ROOT-signs an executeWithSig whose single call is self.bindMandates([voucher]); a relayer
        // submits it. The MandateBound event fires from within _registerMandate.
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = voucher;
        vm.expectEmit(true, true, true, true, address(daimon));
        emit IMandateEngine.MandateBound(pid);
        _bindViaRootExec(ms, 1);

        // The standalone bind enabled the signing-only voucher on a live account.
        assertTrue(daimon.isMandateBound(pid), "standalone bind must enable the voucher");

        // Now run the GASLESS x402 settlement against the just-bound voucher.
        bytes memory sig = _voucherSig(pid, agentPk, rawAuthDigest);
        uint256 acctBefore = token.balanceOf(address(daimon));
        uint256 payeeBefore = token.balanceOf(PAYEE);

        vm.prank(RELAYER);
        token.transferWithAuthorization(
            address(daimon), PAYEE, PAY_AMOUNT, validAfter, validBefore, PAY_NONCE, sig
        );

        assertEq(token.balanceOf(address(daimon)), acctBefore - PAY_AMOUNT, "account debited X");
        assertEq(token.balanceOf(PAYEE), payeeBefore + PAY_AMOUNT, "payee credited X");
        assertTrue(token.authorizationState(address(daimon), PAY_NONCE), "nonce marked used");
    }

    /*//////////////////////////////////////////////////////////////
                            AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice The `onlySelf` guard: a non-self external caller (a relayer) cannot call `bindMandates`
    ///         directly — it reverts {Unauthorized}. Only the account itself (via a ROOT-authed self-call) may.
    function test_bindMandates_directExternalCaller_revertsUnauthorized() external {
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _voucherMandate();

        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.Unauthorized.selector);
        daimon.bindMandates(ms);
    }

    /// @notice Even the ROOT signer (the human's EOA) cannot call `bindMandates` directly — `onlySelf` is
    ///         `msg.sender == address(this)`, not an owner check. The human must route through {executeWithSig}.
    function test_bindMandates_rootSignerDirect_revertsUnauthorized() external {
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _voucherMandate();

        vm.prank(rootSigner);
        vm.expectRevert(IDaimon.Unauthorized.selector);
        daimon.bindMandates(ms);
    }

    /*//////////////////////////////////////////////////////////////
                                 BATCH
    //////////////////////////////////////////////////////////////*/

    /// @notice The batch: `bindMandates` enables MULTIPLE mandates in one self-call. Here a signing-only
    ///         voucher AND an action mandate are bound together; both end up enabled.
    function test_bindMandates_multiple_inOneCall() external {
        Mandate memory voucher = _voucherMandate();
        Mandate memory action = _actionMandate();
        MandateId vpid = _mandateId(voucher);
        MandateId apid = _mandateId(action);

        Mandate[] memory ms = new Mandate[](2);
        ms[0] = voucher;
        ms[1] = action;

        // Both MandateBound events fire (order matches the array).
        vm.expectEmit(true, true, true, true, address(daimon));
        emit IMandateEngine.MandateBound(vpid);
        vm.expectEmit(true, true, true, true, address(daimon));
        emit IMandateEngine.MandateBound(apid);
        _bindViaRootExec(ms, 1);

        assertTrue(daimon.isMandateBound(vpid), "voucher bound in the batch");
        assertTrue(daimon.isMandateBound(apid), "action mandate bound in the batch");
    }

    /*//////////////////////////////////////////////////////////////
                              ENABLE NONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Each standalone bind ADVANCES that mandate's enable nonce (the documented invariant), so a stale
    ///         inline {executeWithSig} MANDATE_BIND signature committed to the OLD nonce can never be replayed to
    ///         re-bind/override the mandate after a standalone bind.
    function test_bindMandates_advancesEnableNonce() external {
        Mandate memory action = _actionMandate();
        MandateId apid = _mandateId(action);
        assertEq(daimon.mandateEnableNonce(apid), 0, "nonce starts at 0");

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = action;

        _bindViaRootExec(ms, 1);
        assertEq(
            daimon.mandateEnableNonce(apid), 1, "first standalone bind advances the nonce to 1"
        );

        _bindViaRootExec(ms, 2);
        assertEq(
            daimon.mandateEnableNonce(apid), 2, "second standalone bind advances the nonce to 2"
        );
    }

    /// @notice A standalone bind enforces the `validUntil` bind-deadline (like the inline path), so a relayer
    ///         cannot submit a ROOT-signed `bindMandates` after the mandate's deadline.
    function test_bindMandates_expiredValidUntil_revertsBindExpired() external {
        Mandate memory m = _actionMandate();
        m.validUntil = uint48(block.timestamp - 1); // already past
        MandateId pid = _mandateId(m);

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = m;
        bytes memory inner = abi.encodeWithSelector(BIND_MANDATES_SELECTOR, ms);
        bytes memory executionData = abi.encodePacked(address(daimon), uint256(0), inner);
        uint256 nonce = 1;
        bytes memory sig =
            _rootSig(address(root1), rootPk, _execDigest(MODE_SINGLE, executionData, nonce));

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(IMandateEngine.BindExpired.selector, pid, m.validUntil)
        );
        daimon.executeWithSig(MODE_SINGLE, executionData, nonce, type(uint256).max, sig);
    }

    /*//////////////////////////////////////////////////////////////
                              EMPTY ARRAY
    //////////////////////////////////////////////////////////////*/

    /// @notice An empty `mandates` array reverts {NoMandates} — surfaced through the {executeWithSig} self-call
    ///         (the inner revert bubbles up). Mirrors `enableSessions`' empty-array guard.
    function test_bindMandates_empty_revertsNoMandates() external {
        Mandate[] memory ms = new Mandate[](0);

        bytes memory inner = abi.encodeWithSelector(BIND_MANDATES_SELECTOR, ms);
        bytes memory executionData = abi.encodePacked(address(daimon), uint256(0), inner);
        uint256 nonce = 1;
        bytes memory sig =
            _rootSig(address(root1), rootPk, _execDigest(MODE_SINGLE, executionData, nonce));

        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.NoMandates.selector);
        daimon.executeWithSig(MODE_SINGLE, executionData, nonce, type(uint256).max, sig);
    }

    /*//////////////////////////////////////////////////////////////
                          BOUND MANDATE USABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice A bound voucher is USABLE on the 1271 path: after the standalone bind, the account's
    ///         `isValidSignature` accepts exactly the voucher digest from the allowlisted token. (The
    ///         settlement counterpart is the headline test; this isolates the 1271 acceptance.)
    function test_bindMandates_boundVoucher_isValidSignatureAccepts() external {
        Mandate memory voucher = _voucherMandate();
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = voucher;
        _bindViaRootExec(ms, 1);

        bytes memory sig = _voucherSig(_mandateId(voucher), agentPk, rawAuthDigest);
        vm.prank(address(token));
        assertEq(
            daimon.isValidSignature(rawAuthDigest, sig),
            MAGIC_VALUE,
            "the standalone-bound voucher must 1271-accept its digest"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CEI ORDERING (F3)
    //////////////////////////////////////////////////////////////*/

    /// @notice CEI: the `enabled` flag is flipped LAST, after every sigil's `initializeWithMultiplexer` runs.
    ///         A sigil that reenters `isMandateBound(pid)` during its own init (the FIRST registration loop)
    ///         must observe the mandate as NOT yet enabled — otherwise a sigil whose init reentered an
    ///         `executeWithSig` MANDATE_USE of the same pid would see a partially-configured-but-enabled
    ///         mandate. After registration completes the mandate IS bound.
    function test_bindMandates_ceiOrdering_sigilInitSeesUnbound() external {
        MockReentrantInitSigil probe = new MockReentrantInitSigil();

        // pid is content-derived from (sessionValidator, sessionValidatorInitData, salt) only — independent
        // of the action sigils' initData — so compute it first, then feed it to the probe's initData.
        Mandate memory shell = _probeMandate(probe, "");
        MandateId pid = _mandateId(shell);
        Mandate memory m = _probeMandate(probe, abi.encode(pid));

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = m;
        _bindViaRootExec(ms, 1);

        assertTrue(probe.initRan(), "the reentrant probe init must have run");
        assertFalse(
            probe.observedBound(),
            "sigil init mid-registration must NOT see the mandate enabled (CEI: enable is last)"
        );
        assertTrue(daimon.isMandateBound(pid), "mandate is enabled once registration completes");
    }

    /// @notice CEI on the RE-BIND path: `_clearMandateSets` does not touch `enabled`, so without the
    ///         disable-first guard a re-bind of an already-enabled mandate would leave it enabled across the
    ///         sigil-init loops. Re-binding the same pid, the probe's reentrant init must STILL observe the
    ///         mandate as NOT enabled (it was cleared first), not stale-true from the first bind.
    function test_bindMandates_ceiOrdering_reBindSeesUnbound() external {
        MockReentrantInitSigil probe = new MockReentrantInitSigil();
        Mandate memory shell = _probeMandate(probe, "");
        MandateId pid = _mandateId(shell);
        Mandate memory m = _probeMandate(probe, abi.encode(pid));

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = m;

        // First bind enables the mandate.
        _bindViaRootExec(ms, 1);
        assertTrue(daimon.isMandateBound(pid), "first bind enables the mandate");

        // Re-bind the SAME pid. The probe's init re-runs and re-reads isMandateBound; with disable-first it
        // must see false (cleared), not the stale true left by the first bind.
        _bindViaRootExec(ms, 2);
        assertTrue(probe.initRan(), "re-bind probe init must have run");
        assertFalse(
            probe.observedBound(),
            "re-bind: sigil init mid-registration must NOT see the mandate enabled (CEI: disable first)"
        );
        assertTrue(daimon.isMandateBound(pid), "re-bind re-enables once registration completes");
    }

    /*//////////////////////////////////////////////////////////////
                       SIGIL INTERFACE GATE (F7)
    //////////////////////////////////////////////////////////////*/

    /// @notice A codeless (EOA) address as an ACTION sigil is rejected at bind with {UnsupportedSigil}: it
    ///         cannot advertise {IActionSigil} via ERC-165, so a later low-level `checkAction` would no-op to
    ///         `(true, "")` and fail OPEN. Rejecting it here fails CLOSED.
    function test_bindMandates_eoaActionSigil_revertsUnsupportedSigil() external {
        Mandate memory m = _badActionSigilMandate(address(0xDEAD));
        _bindExpectRevert(m, address(0xDEAD));
    }

    /// @notice A codeless (EOA) address as an OUTCOME sigil is rejected with {UnsupportedSigil} — the real
    ///         fail-open: an outcome sigil's `pre/postCheck` no-op would skip the spend cap entirely.
    function test_bindMandates_eoaOutcomeSigil_revertsUnsupportedSigil() external {
        Mandate memory m = _badOutcomeSigilMandate(address(0xDEAD));
        _bindExpectRevert(m, address(0xDEAD));
    }

    /// @notice A codeless (EOA) address as a SIGNATURE sigil is rejected with {UnsupportedSigil}: its
    ///         `check1271` no-op would skip the attestation gate.
    function test_bindMandates_eoaSignatureSigil_revertsUnsupportedSigil() external {
        Mandate memory m = _badSignatureSigilMandate(address(0xDEAD));
        _bindExpectRevert(m, address(0xDEAD));
    }

    /// @notice WRONG-TIER: an action-only sigil ({OmniSigil}, which supports {IActionSigil} but NOT
    ///         {IOutcomeSigil}) placed in the OUTCOME tier is rejected with {UnsupportedSigil}. This is the case
    ///         `code.length` alone would miss — the address IS a contract, but its `pre/postCheck` would no-op
    ///         and skip the outcome cap.
    function test_bindMandates_wrongTierOmniInOutcome_revertsUnsupportedSigil() external {
        Mandate memory m = _badOutcomeSigilMandate(address(omni));
        _bindExpectRevert(m, address(omni));
    }

    /// @notice WRONG-TIER (Finding-1 closure): an action-only sigil ({OmniSigil}, which supports
    ///         {IActionSigil} but NOT {I1271Sigil}) placed in the SIGNATURE tier is rejected with
    ///         {UnsupportedSigil}. Before the interface segregation OmniSigil advertised the shared fat
    ///         interface and carried a (broken, envelope-misreading) `check1271`, so it would have been
    ///         accepted in the signature slot and reached at 1271 time. The tightened per-tier guard now
    ///         requires `type(I1271Sigil).interfaceId`, so it fails CLOSED at bind.
    function test_bindMandates_wrongTierOmniInSignature_revertsUnsupportedSigil() external {
        Mandate memory m = _badSignatureSigilMandate(address(omni));
        _bindExpectRevert(m, address(omni));
    }

    /// @notice WRONG-TIER (Finding-1 closure): the outcome-only {SpendSigil} (which supports {IOutcomeSigil}
    ///         but NOT {I1271Sigil}) placed in the SIGNATURE tier is rejected with {UnsupportedSigil}. Its
    ///         former `check1271` per-op ceiling misread the engine envelope; dropping the 1271 tier and
    ///         tightening the guard makes a signature-slot misplacement fail CLOSED at bind.
    function test_bindMandates_wrongTierSpendInSignature_revertsUnsupportedSigil() external {
        Mandate memory m = _badSignatureSigilMandate(address(spendSigil));
        _bindExpectRevert(m, address(spendSigil));
    }

    /// @notice A correctly-tiered mandate with a real outcome sigil ({SpendSigil}, which DOES support
    ///         {IOutcomeSigil}) binds normally — the gate does not over-reject valid sigils.
    function test_bindMandates_correctlyTieredSpendOutcome_binds() external {
        OutcomeSigilData[] memory outs = new OutcomeSigilData[](1);
        outs[0] =
            OutcomeSigilData({ sigil: address(spendSigil), initData: abi.encode(_spendConfig()) });
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(sudo), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        Mandate memory m = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x5DC0)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: outs,
            signatureSigils: new SignatureSigilData[](0)
        });

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = m;
        _bindViaRootExec(ms, 1);
        assertTrue(
            daimon.isMandateBound(_mandateId(m)), "correctly-tiered SpendSigil outcome binds"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW ACCESSORS (#170)
    //////////////////////////////////////////////////////////////*/

    /// @notice After binding an ACTION mandate (a fallback SudoSigil), `mandateActionIds` returns exactly the
    ///         fallback ActionId, and `mandateActionSigils(FALLBACK_ACTIONID, pid)` returns exactly the
    ///         configured sigil. Before the bind both are empty.
    function test_views_mandateActionAccessors_reflectBoundState() external {
        Mandate memory action = _actionMandate();
        MandateId pid = _mandateId(action);

        // Precondition: nothing bound, so the accessors read back empty.
        assertEq(daimon.mandateActionIds(pid).length, 0, "no action ids before bind");
        assertEq(
            daimon.mandateActionSigils(FALLBACK_ACTIONID, pid).length,
            0,
            "no action sigils before bind"
        );

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = action;
        _bindViaRootExec(ms, 1);

        // The action mandate registers its single fallback action under FALLBACK_ACTIONID.
        bytes32[] memory aids = daimon.mandateActionIds(pid);
        assertEq(aids.length, 1, "exactly one action id after bind");
        assertEq(aids[0], ActionId.unwrap(FALLBACK_ACTIONID), "the fallback action id is recorded");

        // Its sigils are exactly [sudo], keyed by (FALLBACK_ACTIONID, pid).
        address[] memory sigils = daimon.mandateActionSigils(FALLBACK_ACTIONID, pid);
        assertEq(sigils.length, 1, "exactly one action sigil");
        assertEq(sigils[0], address(sudo), "the configured action sigil is the SudoSigil");
    }

    /// @notice After binding a mandate with an outcome sigil (a {SpendSigil}), `mandateOutcomeSigils` returns
    ///         exactly that sigil. Before the bind it is empty.
    function test_views_mandateOutcomeSigils_reflectBoundState() external {
        OutcomeSigilData[] memory outs = new OutcomeSigilData[](1);
        outs[0] =
            OutcomeSigilData({ sigil: address(spendSigil), initData: abi.encode(_spendConfig()) });
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(sudo), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        Mandate memory m = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x07C0)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: outs,
            signatureSigils: new SignatureSigilData[](0)
        });
        MandateId pid = _mandateId(m);

        assertEq(daimon.mandateOutcomeSigils(pid).length, 0, "no outcome sigils before bind");

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = m;
        _bindViaRootExec(ms, 1);

        address[] memory outcomes = daimon.mandateOutcomeSigils(pid);
        assertEq(outcomes.length, 1, "exactly one outcome sigil after bind");
        assertEq(outcomes[0], address(spendSigil), "the configured outcome sigil is the SpendSigil");
    }

    /// @notice The signing-only voucher (an AttestationSigil signature sigil) is surfaced by the existing
    ///         `mandateSignatureSigils`, AND its action/outcome accessors stay empty — proving the new
    ///         accessors are category-scoped (a signature-only mandate enables no actions/outcomes).
    function test_views_signatureOnlyVoucher_onlySignatureSigilSet() external {
        Mandate memory voucher = _voucherMandate();
        MandateId pid = _mandateId(voucher);

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = voucher;
        _bindViaRootExec(ms, 1);

        address[] memory sigSigils = daimon.mandateSignatureSigils(pid);
        assertEq(sigSigils.length, 1, "exactly one signature sigil");
        assertEq(
            sigSigils[0],
            address(sigPolicy),
            "the configured signature sigil is the AttestationSigil"
        );

        assertEq(daimon.mandateActionIds(pid).length, 0, "voucher enables no actions");
        assertEq(daimon.mandateOutcomeSigils(pid).length, 0, "voucher configures no outcome sigils");
    }

    /// @notice `execNonceUsed` reads the single-use direct-call replay bitmap: false for an unused nonce, true
    ///         once an `executeWithSig` carrying it has succeeded. Here a ROOT-authed `bindMandates` self-call
    ///         (submitted via `executeWithSig` at nonce 1) burns nonce 1.
    function test_views_execNonceUsed_falseThenTrueAfterExec() external {
        // A fresh, never-used nonce reads false.
        assertFalse(daimon.execNonceUsed(1), "nonce 1 unused before any execution");

        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _actionMandate();
        _bindViaRootExec(ms, 1); // submits executeWithSig at nonce 1

        // The execution burned nonce 1; an unrelated nonce stays false.
        assertTrue(daimon.execNonceUsed(1), "nonce 1 burned after the execution");
        assertFalse(daimon.execNonceUsed(2), "an unused nonce stays false");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Submit a ROOT {executeWithSig} self-call binding `m`, expecting it to revert {UnsupportedSigil(bad)}
    ///      (bubbled through the self-call).
    function _bindExpectRevert(Mandate memory m, address bad) internal {
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = m;
        bytes memory inner = abi.encodeWithSelector(BIND_MANDATES_SELECTOR, ms);
        bytes memory executionData = abi.encodePacked(address(daimon), uint256(0), inner);
        uint256 nonce = 1;
        bytes memory sig =
            _rootSig(address(root1), rootPk, _execDigest(MODE_SINGLE, executionData, nonce));

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.UnsupportedSigil.selector, bad));
        daimon.executeWithSig(MODE_SINGLE, executionData, nonce, type(uint256).max, sig);
    }

    /// @dev A mandate whose single fallback ACTION names `bad` as its sigil.
    function _badActionSigilMandate(address bad) internal view returns (Mandate memory s) {
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: bad, initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xBAD1)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev A mandate naming `bad` as its (single) OUTCOME sigil. Needs >= 1 action so the self-call lands.
    function _badOutcomeSigilMandate(address bad) internal view returns (Mandate memory s) {
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(sudo), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        OutcomeSigilData[] memory outs = new OutcomeSigilData[](1);
        outs[0] = OutcomeSigilData({ sigil: bad, initData: "" });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xBAD2)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: outs,
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev A mandate naming `bad` as its (single) SIGNATURE sigil.
    function _badSignatureSigilMandate(address bad) internal view returns (Mandate memory s) {
        SignatureSigilData[] memory sigs = new SignatureSigilData[](1);
        sigs[0] = SignatureSigilData({ sigil: bad, initData: "" });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xBAD3)),
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: sigs
        });
    }

    /// @dev A mandate whose single fallback ACTION sigil is the reentrancy probe, with `probeInit` as its
    ///      init data. The probe is an action sigil so it runs in the FIRST registration loop.
    function _probeMandate(
        MockReentrantInitSigil probe,
        bytes memory probeInit
    )
        internal
        view
        returns (Mandate memory s)
    {
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(probe), initData: probeInit });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xCE10)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev A minimal SpendSigil config (token, cap, Day window, single spender) for the happy-path bind.
    function _spendConfig() internal view returns (SpendConfig memory c) {
        address[] memory spenders = new address[](1);
        spenders[0] = PAYEE;
        c = SpendConfig({
            token: address(token), cap: PAY_AMOUNT, period: Period.Day, spenders: spenders
        });
    }

    /// @dev Build a ROOT {executeWithSig} whose single call is `self.bindMandates(mandates)`, signed by ROOT,
    ///      and submit it from the relayer (gasless for the human). This is the standalone-bind authorization
    ///      path: `onlySelf` + a ROOT-authed self-call (ROOT skips sigil enforcement, so the self-call lands).
    function _bindViaRootExec(Mandate[] memory mandates, uint256 nonce) internal {
        bytes memory inner = abi.encodeWithSelector(BIND_MANDATES_SELECTOR, mandates);
        bytes memory executionData = abi.encodePacked(address(daimon), uint256(0), inner);
        bytes memory sig =
            _rootSig(address(root1), rootPk, _execDigest(MODE_SINGLE, executionData, nonce));
        vm.prank(RELAYER);
        daimon.executeWithSig(MODE_SINGLE, executionData, nonce, type(uint256).max, sig);
    }

    /// @dev The signing-only x402 voucher mandate: its ONLY capability is 1271-signing for the token (sender)
    ///      + the pinned nested EIP-3009 digest (hash). NO on-chain actions — settlement is gasless via
    ///      EIP-3009. This is precisely the mandate shape the inline MANDATE_BIND path cannot bind.
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

    /// @dev A simple ACTION mandate (a SudoSigil fallback catch-all) used to prove the batch binds more than
    ///      one mandate. Distinct salt so its id differs from the voucher.
    function _actionMandate() internal view returns (Mandate memory s) {
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(sudo), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xACFA)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev The MandateId of an arbitrary mandate (matches IdLib.toMandateId).
    function _mandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @dev Build a ROOT-mode signature: `[0x00][20-byte validator][r,s,v]`.
    function _rootSig(
        address validator,
        uint256 pk,
        bytes32 hash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes1(0x00), bytes20(validator), _sign(pk, hash));
    }

    /// @dev The EIP-712 execution digest the ROOT signs: `_hashTypedData(EXEC structHash)` over the account
    ///      domain — `keccak256(EXEC_TYPEHASH, mode, keccak256(executionData), nonce, deadline)`. Uses
    ///      `type(uint256).max` (no expiry).
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

    /// @dev Build a MANDATE-mode 1271 signature the TOKEN passes back to the account:
    ///      [0x01][mandateId][abi.encode(content, keySig)]. The session key signs the ERC-7739-nested digest.
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
        return abi.encodePacked(bytes1(0x01), MandateId.unwrap(pid), abi.encode(bytes(""), keySig));
    }

    /// @dev The RAW EIP-3009 `transferWithAuthorization` digest, computed exactly as {MockUSDC3009} does.
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

    /// @dev The ERC-7739 PersonalSign digest solady reconstructs: `_hashTypedData(keccak256(
    ///      PERSONAL_SIGN_TYPEHASH, hash))` over the ACCOUNT's domain.
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
