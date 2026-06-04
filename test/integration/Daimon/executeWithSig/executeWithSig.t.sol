// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Contracts
import {
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";
import { TimeFrameSigil, TimeFrameConfig } from "@sigils/TimeFrameSigil/TimeFrameSigil.sol";
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";
import { NativeValueLimitSigil } from "@sigils/NativeValueLimitSigil/NativeValueLimitSigil.sol";
import {
    NativeValueLimitConfig
} from "@sigils/NativeValueLimitSigil/lib/NativeValueLimitConfigLib.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";
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
    MandateBinding,
    MandateId,
    FALLBACK_TARGET_FLAG
} from "@types/MandateTypes.sol";

// Mocks
import { MockSwapRouter } from "@test/mock/MockSwapRouter.sol";
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title Daimon executeWithSig (direct-call relayer path) Integration Tests
/// @author highskore.eth
/// @notice Proves the direct-call (ERC-1608) execution path end to end: any relayer submits a ROOT- or
///         session-key-signed ERC-7579 single/batch execution (`mode` + `executionData`) and pays the gas.
///         This actually RUNS the calls against a live MockSwapRouter/MockERC20, so the recipient-lock sigil
///         is enforced on real swaps, the single-use nonce is burned, and `Executed` is emitted. Auth
///         failure reverts (`UnauthorizedExecution`), since this is a transaction, not a validation. The
///         MANDATE path enforces the mandate's sigils over EVERY decoded call (default-deny each), so one
///         violating call reverts the whole batch.
contract Daimon_executeWithSig_Integration_Test is Daimon_Integration_Test {
    /// @dev ERC-7579 execution mode: single call (first byte = call type 0).
    bytes32 internal constant MODE_SINGLE = bytes32(0);

    /// @dev ERC-7579 execution mode: batch (first byte = call type 1).
    bytes32 internal constant MODE_BATCH = bytes32(uint256(1) << 248);

    /// @dev `Executed(uint256 indexed nonce)`.
    event Executed(uint256 indexed nonce);

    /// @dev A single batch entry, matching solady `LibERC7579`'s `abi.encode(Call[])` batch layout.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    MockSwapRouter internal swapRouter;
    MockERC20 internal tokenIn;
    MockERC20 internal tokenOut;

    /// @dev The time-window sigil used by the expiring-mandate suite — proves a {TimeFrameSigil} attached to
    ///      an action enforces a `[validAfter, validUntil]` window at execute time (the sigil-shaped expiry).
    TimeFrameSigil internal timeFrame;

    /// @dev Permissive + bounding sigils used by the fallback-action suite: SudoSigil (allow-all) as a wildcard
    ///      catch-all, and a NativeValueLimitSigil to prove the fallback's sigils still bound the real call.
    SudoSigil internal sudo;
    NativeValueLimitSigil internal nativeValueLimit;

    /// @dev Any relayer; security is the signature + sigils, not msg.sender.
    address internal constant RELAYER = address(0xCAFE);

    /// @dev The mock router pulls `amountIn` of the input token from the account before minting the output.
    uint256 internal constant AMOUNT_IN = 100e6;

    /// @dev The mock router mints `amountIn` (1:1) of the output token to the swap recipient; `AMOUNT_OUT_MIN`
    ///      is the slippage floor the output must clear (well below the 1:1 output).
    uint256 internal constant AMOUNT_OUT_MIN = 1;

    /// @dev A target the swap mandate never enumerates (for the default-deny test).
    address internal constant OTHER_TARGET = address(0xABCD);

    /// @dev A selector the swap mandate never enumerates (for the selector-scoped default-deny test).
    bytes4 internal constant OTHER_SELECTOR = bytes4(keccak256("notASwap(uint256)"));

    /// @dev The expiry timestamp the expiring mandate is bound with (for the expiry test).
    uint48 internal constant EXPIRY = 1_000_000;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        swapRouter = new MockSwapRouter();
        tokenIn = new MockERC20("In", "IN");
        tokenOut = new MockERC20("Out", "OUT");
        timeFrame = new TimeFrameSigil();
        sudo = new SudoSigil();
        nativeValueLimit = new NativeValueLimitSigil();
        vm.deal(address(daimon), 10 ether); // for the native-value fallback tests

        // The router now pulls `amountIn` of the input token from the caller (the account) on every swap, so
        // fund the account and have it approve the router. Mint generously and approve max so the multi-swap
        // suites (batch, bind+execute) all clear `transferFrom`.
        tokenIn.mint(address(daimon), 1_000_000e6);
        vm.prank(address(daimon));
        tokenIn.approve(address(swapRouter), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A session key that direct-executes a single swap routed to the account succeeds: the mock
    ///         router mints the output to the account and `Executed` is emitted.
    function test_executeWithSig_session_selfRecipient_succeeds() external {
        // Arrange: bind the mandate first (a separate ROOT-authed execution would do this on-chain; here we
        // bind inline via the BIND+execute path so the USE below runs against a live mandate).
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _useSigDigest(_swapMandateId(), _execDigest(mode, executionData, nonce));
        uint256 balBefore = tokenOut.balanceOf(address(daimon));
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        // Act & Assert
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(address(daimon)) - balBefore,
            AMOUNT_IN,
            "the USE swap must deliver output to the account"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            AMOUNT_IN,
            "the router must pull amountIn of the input token from the account"
        );
    }

    /// @notice A session key that direct-executes a swap routed to an attacker reverts: the recipient-lock
    ///         sigil denies it, and the direct path surfaces that as `UnauthorizedExecution`.
    function test_executeWithSig_session_attackerRecipient_revertsUnauthorized() external {
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(ATTACKER);
        bytes memory sig = _useSigDigest(_swapMandateId(), _execDigest(mode, executionData, nonce));

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice Default-deny: a USE against a target the mandate never enumerated resolves to an ActionId
    ///         with no configured sigil and is rejected — surfaced on the direct path as
    ///         `UnauthorizedExecution`. Proves the mandate only permits what it enumerates.
    function test_executeWithSig_session_unconfiguredTarget_revertsUnauthorized() external {
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        // A swap routed to the account, but submitted at an unrelated target the mandate never configured.
        bytes memory executionData =
            abi.encodePacked(OTHER_TARGET, uint256(0), _swapData(address(daimon)));
        bytes memory sig =
            _useSigDigest(_swapMandateId(), _execDigest(MODE_SINGLE, executionData, nonce));

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(MODE_SINGLE, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice Default-deny (selector-scoped): a USE on the authorized target but with a selector the
    ///         mandate never enumerated is rejected — the (target, selector) ActionId has no sigil.
    function test_executeWithSig_session_wrongSelector_revertsUnauthorized() external {
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        // The right router, but a non-swap selector -> distinct ActionId, no configured sigil.
        bytes memory inner = abi.encodeWithSelector(OTHER_SELECTOR, uint256(0));
        bytes memory executionData = abi.encodePacked(address(swapRouter), uint256(0), inner);
        bytes memory sig =
            _useSigDigest(_swapMandateId(), _execDigest(MODE_SINGLE, executionData, nonce));

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(MODE_SINGLE, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice A mandate whose action carries a {TimeFrameSigil} cannot be used past its window: after warping
    ///         past `validUntil`, an otherwise in-bounds USE swap is rejected (the TimeFrameSigil's checkAction
    ///         returns VALIDATION_FAILED) and surfaces as `UnauthorizedExecution`. Proves the sigil-shaped time
    ///         bound is enforced PER-ACTION at execution time on the direct-call path — the replacement for the
    ///         old baked-in mandate `validUntil`.
    function test_executeWithSig_session_expired_revertsUnauthorized() external {
        // Arrange: bind the time-framed mandate (window [0, EXPIRY]) while in-window, then warp past EXPIRY.
        _bindExpiringViaExecute(0);
        vm.warp(uint256(EXPIRY) + 1);

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _expiringSwapExec(address(daimon));
        bytes memory sig =
            _useSigDigest(_expiringMandateId(), _execDigest(mode, executionData, nonce));

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice The in-window counterpart: a mandate whose action carries a {TimeFrameSigil} executes
    ///         successfully while `block.timestamp` is inside `[validAfter, validUntil]` — the swap runs and
    ///         `Executed` is emitted. Proves the TimeFrameSigil PERMITS (not just denies) inside its window.
    function test_executeWithSig_session_inWindow_succeeds() external {
        // Bind the time-framed mandate inline at exec nonce 0, while comfortably inside [0, EXPIRY].
        vm.warp(uint256(EXPIRY) - 1);
        _bindExpiringViaExecute(0);

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _expiringSwapExec(address(daimon));
        bytes memory sig =
            _useSigDigest(_expiringMandateId(), _execDigest(mode, executionData, nonce));
        uint256 balBefore = tokenOut.balanceOf(address(daimon));
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        // Act & Assert
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(address(daimon)) - balBefore,
            AMOUNT_IN,
            "an in-window TimeFrameSigil swap must execute"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            AMOUNT_IN,
            "the router must pull amountIn of the input token from the account"
        );
    }

    /// @notice Runtime time bounds are the {TimeFrameSigil} sigil, INDEPENDENT of `validUntil` (the bind-time
    ///         deadline). A mandate bound by the current code persists NO per-mandate runtime expiry; it is gated
    ///         at USE ONLY by its TimeFrameSigil. Past the sigil's window the USE reverts with
    ///         `UnauthorizedExecution` (the sigil returns VALIDATION_FAILED), proving the runtime time bound is
    ///         the sigil, not any stored expiry.
    function test_executeWithSig_session_newMandate_gatedOnlyByTimeFrameSigil() external {
        // Bind a new time-framed mandate inside its window.
        _bindExpiringViaExecute(0);
        MandateId pid = _expiringMandateId();

        // Past the TimeFrameSigil window: the sigil denies the action, surfaced as UnauthorizedExecution.
        vm.warp(uint256(EXPIRY) + 1);
        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _expiringSwapExec(address(daimon));
        bytes memory sig = _useSigDigest(pid, _execDigest(mode, executionData, nonce));

        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice Bind-time deadline: `validUntil` is the deadline on the ROOT bind signature, enforced ONCE at
    ///         bind time. A BIND submitted after the (signed) deadline reverts with {BindExpired}. Here we sign
    ///         a bind whose `validUntil` is in the past relative to the current block, then submit it — the
    ///         engine authenticates the deadline from the digest and rejects the late bind.
    function test_executeWithSig_bind_afterValidUntil_revertsBindExpired() external {
        vm.warp(uint256(EXPIRY) + 100); // now strictly after the bind deadline below
        Mandate memory s = _swapSessionWithValidUntil(EXPIRY);
        MandateId pid = _mandateId(s);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _bindSigFor(s, 0, _execDigest(mode, executionData, execNonce));

        // Act & Assert: the bind is past its signed deadline, so it reverts (no mandate is enabled).
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.BindExpired.selector, pid, EXPIRY));
        daimon.executeWithSig(mode, executionData, execNonce, type(uint256).max, sig);
        assertFalse(daimon.isMandateBound(pid), "an expired bind must not enable the mandate");
    }

    /// @notice The in-deadline counterpart: a BIND submitted at/before its signed `validUntil` deadline
    ///         succeeds (the deadline is inclusive). Proves the bind-time check PERMITS within the window — it
    ///         is not a blanket block on any non-zero `validUntil`.
    function test_executeWithSig_bind_beforeValidUntil_succeeds() external {
        vm.warp(uint256(EXPIRY)); // exactly the deadline (inclusive) — must still bind
        Mandate memory s = _swapSessionWithValidUntil(EXPIRY);
        MandateId pid = _mandateId(s);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _bindSigFor(s, 0, _execDigest(mode, executionData, execNonce));

        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(execNonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, execNonce, type(uint256).max, sig);
        assertTrue(
            daimon.isMandateBound(pid), "a bind at/before its deadline must enable the mandate"
        );
    }

    /// @notice `validUntil` is part of the SIGNED bind digest, so a relayer cannot tamper with it: the ROOT
    ///         signs a bind for `validUntil = EXPIRY`, but the relayer submits a binding carrying a DIFFERENT
    ///         `validUntil`. The on-chain digest (computed from the submitted value) no longer matches the
    ///         ROOT-signed digest, so ROOT authorization fails and the bind reverts {UnauthorizedBind}.
    function test_executeWithSig_bind_tamperedValidUntil_revertsUnauthorized() external {
        // ROOT signs the bind digest for the HONEST deadline (EXPIRY).
        Mandate memory signed = _swapSessionWithValidUntil(EXPIRY);
        bytes memory rootSig = _sign(rootPk, _bindDigest(signed, 0));

        // The relayer swaps in a TAMPERED deadline (e.g. extending it far into the future). Note the MandateId
        // is unchanged (validUntil is not part of toMandateId), so this is a same-id tamper, not a new mandate.
        Mandate memory tampered = _swapSessionWithValidUntil(EXPIRY * 2);
        assertEq(
            MandateId.unwrap(_mandateId(signed)),
            MandateId.unwrap(_mandateId(tampered)),
            "precondition: tampering validUntil must not change the MandateId"
        );
        MandateId pid = _mandateId(tampered);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        MandateBinding memory en = MandateBinding({
            session: tampered, rootValidator: address(root1), rootSignature: rootSig
        });
        bytes memory keySig = _sign(agentPk, _execDigest(mode, executionData, execNonce));
        bytes memory sig = abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));

        // Act & Assert: the digest over the tampered validUntil ≠ the ROOT-signed digest, so auth fails.
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.UnauthorizedBind.selector, pid));
        daimon.executeWithSig(mode, executionData, execNonce, type(uint256).max, sig);
    }

    /// @notice A 2-call batch where every call complies with the mandate's recipient-lock succeeds: both
    ///         swaps run, so the account receives 2× the per-swap output. This proves batching works.
    function test_executeWithSig_batch_allCompliant_succeeds() external {
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        Call[] memory calls = new Call[](2);
        calls[0] = _swapCall(address(daimon));
        calls[1] = _swapCall(address(daimon));
        (bytes32 mode, bytes memory executionData) = _batchExec(calls);
        bytes memory sig = _useSigDigest(_swapMandateId(), _execDigest(mode, executionData, nonce));
        uint256 balBefore = tokenOut.balanceOf(address(daimon));
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        // Act & Assert
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(address(daimon)) - balBefore,
            2 * AMOUNT_IN,
            "both compliant swaps in the batch must execute"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            2 * AMOUNT_IN,
            "both batched swaps must each pull amountIn of the input token from the account"
        );
    }

    /// @notice The critical batch invariant: in a 2-call batch where call[0] complies (self recipient) but
    ///         call[1] violates the recipient-lock sigil (attacker recipient), the WHOLE tx reverts
    ///         `UnauthorizedExecution` and NEITHER call executes. Validation runs over the entire batch
    ///         before any external call, so the compliant call must not leak through.
    function test_executeWithSig_batch_oneCallViolates_revertsWholeBatch() external {
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        Call[] memory calls = new Call[](2);
        calls[0] = _swapCall(address(daimon)); // compliant: self recipient
        calls[1] = _swapCall(ATTACKER); // violates: attacker recipient
        (bytes32 mode, bytes memory executionData) = _batchExec(calls);
        bytes memory sig = _useSigDigest(_swapMandateId(), _execDigest(mode, executionData, nonce));
        uint256 balBefore = tokenOut.balanceOf(address(daimon));

        // Act & Assert: one bad call reverts everything.
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        // The compliant call[0] must NOT have executed (whole-batch atomicity).
        assertEq(
            tokenOut.balanceOf(address(daimon)),
            balBefore,
            "a single violating call must revert the whole batch: no call may execute"
        );
    }

    /// @notice Replaying a consumed nonce reverts: the nonce is burned before the external calls.
    function test_executeWithSig_replayNonce_revertsExecNonceUsed() external {
        _bindViaExecute(address(daimon), 0);

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _useSigDigest(_swapMandateId(), _execDigest(mode, executionData, nonce));

        // Arrange: first execution consumes the nonce.
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        // Act & Assert: same nonce again -> burned.
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IDaimon.ExecNonceUsed.selector, nonce));
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice A signed execution whose `deadline` is in the past reverts with `Expired` — the signed expiry
    ///         is the ERC-1608 freshness guard. Crucially, the `deadline` check runs BEFORE the nonce burn, so
    ///         an expired payload leaves its nonce REUSABLE: re-signing the same `(mode, executionData, nonce)`
    ///         with a fresh, valid `deadline` then succeeds.
    function test_executeWithSig_pastDeadline_revertsExpired_nonceReusable() external {
        uint256 nonce = 5;
        uint256 pastDeadline = block.timestamp - 1; // strictly in the past
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));

        // ROOT signs the expired payload (ROOT bypasses sigils, so this isolates the deadline check).
        bytes32 expiredDigest = _execDigest(mode, executionData, nonce, pastDeadline);
        bytes memory expiredSig = _rootSig(address(root1), rootPk, expiredDigest);

        // Act & Assert: an expired deadline reverts before the nonce is burned.
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.Expired.selector);
        daimon.executeWithSig(mode, executionData, nonce, pastDeadline, expiredSig);

        // The nonce must NOT have been burned by the expired submission.
        assertFalse(daimon.execNonceUsed(nonce), "an expired payload must not burn its nonce");

        // Re-sign the SAME payload + nonce with a valid (max) deadline: it now succeeds and burns the nonce.
        bytes memory freshSig =
            _rootSig(address(root1), rootPk, _execDigest(mode, executionData, nonce));
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, freshSig);
        assertTrue(daimon.execNonceUsed(nonce), "a valid resubmission must burn the nonce");
    }

    /// @notice A ROOT signature over the execution digest authorizes any execution directly (no mandate, no
    ///         recipient-lock — ROOT is the owner OR-set). Here ROOT routes the swap to an attacker, which
    ///         a session key could not, proving ROOT bypasses the sigils.
    function test_executeWithSig_root_succeeds() external {
        uint256 nonce = 7;
        (bytes32 mode, bytes memory executionData) = _swapExec(ATTACKER);
        bytes32 digest = _execDigest(mode, executionData, nonce);
        bytes memory sig = _rootSig(address(root1), rootPk, digest);
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        // Act & Assert
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        assertEq(
            tokenOut.balanceOf(ATTACKER),
            AMOUNT_IN,
            "ROOT bypasses sigils: attacker received output"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            AMOUNT_IN,
            "the router still pulls amountIn of the input token from the account"
        );
    }

    /// @notice BIND + execute in one direct call: the session signature carries the ROOT-signed binding, so
    ///         the mandate is enabled and the swap runs in a single relayer submission.
    function test_executeWithSig_bindAndExecute_succeeds() external {
        uint256 nonce = 3;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _bindSig(address(daimon), 0, _execDigest(mode, executionData, nonce));
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        // Act & Assert
        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        assertTrue(
            daimon.isMandateBound(_swapMandateId()), "bind-in-execute must enable the mandate"
        );
        assertEq(
            tokenOut.balanceOf(address(daimon)), AMOUNT_IN, "account must receive the swap output"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            AMOUNT_IN,
            "the router must pull amountIn of the input token from the account"
        );
    }

    /// @notice The `mandateEnableNonce` getter tracks the per-mandate enable nonce: 0 before any bind, then
    ///         monotonically incremented on every successful BIND (never reset). This is the value an
    ///         off-chain caller must read and commit into the bind digest for the NEXT bind.
    function test_executeWithSig_mandateEnableNonce_tracksBinds() external {
        MandateId pid = _swapMandateId();
        assertEq(daimon.mandateEnableNonce(pid), 0, "never-bound mandate must report nonce 0");

        _bindViaExecute(address(daimon), 1);
        assertEq(daimon.mandateEnableNonce(pid), 1, "one bind must advance the nonce to 1");
    }

    /// @notice Regression for issue #5: re-binding the same MandateId must commit the CURRENT on-chain enable
    ///         nonce (read via `mandateEnableNonce`), not a hardcoded 0. The first bind uses nonce 0; the
    ///         second must use nonce 1 (the fetched value) or the ROOT signature does not verify.
    function test_executeWithSig_rebind_usesFetchedNonce_succeeds() external {
        MandateId pid = _swapMandateId();

        // First bind: nonce 0 (the fresh value the getter reports).
        _bindViaExecute(address(daimon), 1);
        assertTrue(daimon.isMandateBound(pid), "first bind must enable the mandate");
        assertEq(daimon.mandateEnableNonce(pid), 1, "after first bind the next nonce is 1");

        // Second BIND of the SAME mandate, signing the bind digest at the FETCHED nonce (1).
        uint256 execNonce = 2;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _bindSig(
            address(daimon),
            daimon.mandateEnableNonce(pid),
            _execDigest(mode, executionData, execNonce)
        );

        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(execNonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, execNonce, type(uint256).max, sig);

        assertEq(daimon.mandateEnableNonce(pid), 2, "re-bind must advance the nonce to 2");
    }

    /// @notice Regression for issue #5 (negative): re-binding the same MandateId with a hardcoded nonce 0 —
    ///         the bug — fails ROOT authorization, since the contract now expects nonce 1. Proves the digest
    ///         MUST track the on-chain `mandateEnableNonce`.
    function test_executeWithSig_rebind_staleNonce_revertsUnauthorized() external {
        MandateId pid = _swapMandateId();

        // First bind: nonce 0.
        _bindViaExecute(address(daimon), 1);

        // Second BIND signing the STALE nonce 0 instead of the current 1 -> ROOT sig will not verify.
        uint256 execNonce = 2;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig = _bindSig(address(daimon), 0, _execDigest(mode, executionData, execNonce));

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.UnauthorizedBind.selector, pid));
        daimon.executeWithSig(mode, executionData, execNonce, type(uint256).max, sig);
    }

    /// @notice An unknown sig-mode byte reverts with `InvalidSignatureMode(mode)`.
    function test_executeWithSig_unknownMode_revertsInvalidSignatureMode() external {
        uint256 nonce = 9;
        (bytes32 mode, bytes memory executionData) = _swapExec(address(daimon));
        bytes memory sig =
            abi.encodePacked(bytes1(0x02), _sign(agentPk, _execDigest(mode, executionData, nonce)));

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IDaimon.InvalidSignatureMode.selector, uint8(0x02)));
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /// @notice An empty batch reverts with `NotSupported` (checked before any external call).
    function test_executeWithSig_emptyBatch_revertsNotSupported() external {
        uint256 nonce = 11;
        Call[] memory calls = new Call[](0);
        (bytes32 mode, bytes memory executionData) = _batchExec(calls);
        bytes memory sig = _rootSig(address(root1), rootPk, _execDigest(mode, executionData, nonce));

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.NotSupported.selector);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The recipient-lock swap mandate, but over the LIVE MockSwapRouter / MockERC20 (the base
    ///      `_session()` uses placeholder addresses that can't actually execute). Recipient `to` is pinned
    ///      to the account at calldata offset 96.
    function _swapSession() internal view returns (Mandate memory s) {
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
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0xEEEE)), // distinct from the base swap/spend mandates
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev The MandateId of the live-router swap mandate.
    function _swapMandateId() internal view returns (MandateId) {
        return _mandateId(_swapSession());
    }

    /// @dev The live-router swap mandate, but carrying an explicit bind-time deadline `validUntil`. `validUntil`
    ///      is NOT part of {IdLib.toMandateId}, so this shares the same MandateId as {_swapSession} — used by the
    ///      bind-deadline tests, which need a non-zero signed deadline.
    function _swapSessionWithValidUntil(uint48 validUntil)
        internal
        view
        returns (Mandate memory s)
    {
        s = _swapSession();
        s.validUntil = validUntil;
    }

    /// @dev A SESSION BIND-mode signature for an EXPLICIT mandate `s` (so callers can set its `validUntil`):
    ///      `[0x01][0x01][abi.encode(MandateBinding, keySig)]`. ROOT signs the bind digest of `s` at
    ///      `bindNonce` (committing `s.validUntil`); the session key signs the exec `digest`.
    function _bindSigFor(
        Mandate memory s,
        uint256 bindNonce,
        bytes32 digest
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory rootSig = _sign(rootPk, _bindDigest(s, bindNonce));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: address(root1), rootSignature: rootSig });
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));
    }

    /// @dev The raw `swapExactTokensForTokens(... recipient ...)` calldata routed to `recipient` (no
    ///      `execute(...)` wrapper — the direct path runs this directly against the router from the account).
    function _swapData(address recipient) internal view returns (bytes memory) {
        address[] memory path = new address[](2);
        path[0] = address(tokenIn);
        path[1] = address(tokenOut);
        return abi.encodeWithSelector(
            SWAP_SELECTOR, AMOUNT_IN, AMOUNT_OUT_MIN, path, recipient, uint256(0)
        );
    }

    /// @dev A single swap `Call` to the live router carrying the raw swap calldata for `recipient`.
    function _swapCall(address recipient) internal view returns (Call memory) {
        return Call({ to: address(swapRouter), value: 0, data: _swapData(recipient) });
    }

    /// @dev A single-call execution (ERC-7579 single mode) routing the swap to `recipient`.
    ///      `executionData = abi.encodePacked(to, value, data)` — the layout `LibERC7579.decodeSingle` reads.
    function _swapExec(address recipient)
        internal
        view
        returns (bytes32 mode, bytes memory executionData)
    {
        mode = MODE_SINGLE;
        executionData = abi.encodePacked(address(swapRouter), uint256(0), _swapData(recipient));
    }

    /// @dev A batch execution (ERC-7579 batch mode): `executionData = abi.encode(Call[])` — the layout
    ///      `LibERC7579.decodeBatch` / `getExecution` read.
    function _batchExec(Call[] memory calls)
        internal
        pure
        returns (bytes32 mode, bytes memory executionData)
    {
        mode = MODE_BATCH;
        executionData = abi.encode(calls);
    }

    /// @dev The EIP-712 execution digest the signer commits to: `_hashTypedData(EXEC structHash)`. Mirrors
    ///      the contract: `keccak256(abi.encode(HashLib.EXEC_TYPEHASH, mode,
    ///      keccak256(executionData), nonce, deadline))` under the account's domain. Reconstructs the domain
    ///      separator the same way `_bindDigest` does. The no-deadline overload uses `type(uint256).max`.
    function _execDigest(
        bytes32 mode,
        bytes memory executionData,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        return _execDigest(mode, executionData, nonce, type(uint256).max);
    }

    /// @dev The EIP-712 execution digest committing to an explicit `deadline` — used by the expiry suite to
    ///      sign a payload whose `deadline` is in the past.
    function _execDigest(
        bytes32 mode,
        bytes memory executionData,
        uint256 nonce,
        uint256 deadline
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
            abi.encode(HashLib.EXEC_TYPEHASH, mode, keccak256(executionData), nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @dev A SESSION USE-mode signature over `digest`: `[0x01][0x00][32-byte mandateId][session-key sig]`.
    function _useSigDigest(MandateId pid, bytes32 digest) internal view returns (bytes memory) {
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(0x01), bytes1(0x00), MandateId.unwrap(pid), keySig);
    }

    /// @dev A SESSION BIND-mode signature over `digest`: `[0x01][0x01][abi.encode(MandateBinding, keySig)]`.
    ///      The ROOT scheme signs the bind digest at `bindNonce`; the session key signs the exec `digest`.
    function _bindSig(
        address recipient,
        uint256 bindNonce,
        bytes32 digest
    )
        internal
        view
        returns (bytes memory)
    {
        recipient; // recipient is encoded in executionData, not the binding; kept for call-site symmetry.
        Mandate memory s = _swapSession();
        bytes memory rootSig = _sign(rootPk, _bindDigest(s, bindNonce));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: address(root1), rootSignature: rootSig });
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));
    }

    /// @dev Bind the live-router swap mandate inline via a direct BIND+execute (self-recipient) at the
    ///      given exec `nonce`, so subsequent USEs run against an enabled mandate.
    function _bindViaExecute(address recipient, uint256 nonce) internal {
        (bytes32 mode, bytes memory executionData) = _swapExec(recipient);
        bytes memory sig = _bindSig(recipient, 0, _execDigest(mode, executionData, nonce));
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /// @dev The same recipient-lock swap mandate as {_swapSession}, but with a {TimeFrameSigil} attached to
    ///      the swap action enforcing a `[0, EXPIRY]` window — used to prove a time bound (now "just a sigil")
    ///      is enforced at execution time. The action carries BOTH the OmniSigil recipient lock AND the
    ///      TimeFrameSigil (ERC-7579 / smart-sessions allow many sigils per action, all AND-ed). Distinct
    ///      salt so its MandateId differs from the non-expiring swap mandate.
    function _expiringSession() internal view returns (Mandate memory s) {
        s = _swapSession();
        s.salt = bytes32(uint256(0xE0E0)); // distinct id from the non-expiring swap mandate

        // Append the TimeFrameSigil to the (single) swap action's policy set.
        ActionSigilData[] memory sigils = new ActionSigilData[](2);
        sigils[0] = s.actions[0].sigils[0]; // the OmniSigil recipient lock
        sigils[1] = ActionSigilData({
            sigil: address(timeFrame),
            initData: abi.encode(TimeFrameConfig({ validAfter: 0, validUntil: EXPIRY }))
        });
        s.actions[0].sigils = sigils;
    }

    /// @dev The MandateId of the expiring swap mandate.
    function _expiringMandateId() internal view returns (MandateId) {
        return _mandateId(_expiringSession());
    }

    /// @dev A single-call execution routing the expiring mandate's swap to `recipient`.
    function _expiringSwapExec(address recipient)
        internal
        view
        returns (bytes32 mode, bytes memory executionData)
    {
        mode = MODE_SINGLE;
        executionData = abi.encodePacked(address(swapRouter), uint256(0), _swapData(recipient));
    }

    /// @dev Bind the expiring swap mandate inline via a direct BIND+execute (self-recipient) at exec
    ///      `nonce`, while it is still valid, so a subsequent post-expiry USE runs against an enabled
    ///      (but expired) mandate.
    function _bindExpiringViaExecute(uint256 nonce) internal {
        (bytes32 mode, bytes memory executionData) = _expiringSwapExec(address(daimon));
        Mandate memory s = _expiringSession();
        bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: address(root1), rootSignature: rootSig });
        bytes memory keySig = _sign(agentPk, _execDigest(mode, executionData, nonce));
        bytes memory sig = abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /*//////////////////////////////////////////////////////////////
                        FALLBACK ACTION POLICY (#51)
    //////////////////////////////////////////////////////////////*/

    /// @notice A FALLBACK action (target == FALLBACK_TARGET_FLAG) gates ANY (target, selector) call that has no
    ///         exact-match action. With a SudoSigil fallback, a call to a target the mandate never enumerated
    ///         succeeds — the wildcard catch-all. Bound + executed in one direct call.
    function test_executeWithSig_fallback_unlistedTarget_succeeds() external {
        Mandate memory s = _sudoFallbackSession();
        uint256 nonce = 1;
        (bytes32 mode, bytes memory ed) = _execTo(OTHER_TARGET, 0, hex"deadbeef");
        bytes memory sig = _bindSigFor(s, 0, _execDigest(mode, ed, nonce));

        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(nonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig);
        assertTrue(
            daimon.isMandateBound(_mandateId(s)), "the fallback catch-all permits the unlisted call"
        );
    }

    /// @notice EXACT match wins: a mandate carrying BOTH the recipient-locked swap action AND a SudoSigil
    ///         fallback still DENIES a swap to the attacker on the EXACT router — the exact action's sigil set is
    ///         used (and rejects), never the permissive fallback. The fallback only fills gaps.
    function test_executeWithSig_fallback_exactMatchWins_attackerDenied() external {
        Mandate memory s = _sudoFallbackSession();
        // Bind via a compliant exact swap (self recipient).
        uint256 n0 = 1;
        (bytes32 m0, bytes memory ed0) = _swapExec(address(daimon));
        vm.prank(RELAYER);
        daimon.executeWithSig(
            m0, ed0, n0, type(uint256).max, _bindSigFor(s, 0, _execDigest(m0, ed0, n0))
        );

        // A swap to the ATTACKER on the EXACT router: the exact recipient-lock denies it (no fallback).
        uint256 n1 = 2;
        (bytes32 m1, bytes memory ed1) = _swapExec(ATTACKER);
        bytes memory sig = _useSigDigest(_mandateId(s), _execDigest(m1, ed1, n1));
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(m1, ed1, n1, type(uint256).max, sig);
    }

    /// @notice The fallback's sigils still BOUND the real call: a NativeValueLimitSigil(0) fallback permits a
    ///         zero-value call to any target but rejects any native value — proving the wildcard is not a blanket
    ///         allow-all unless its sigils are (compose value/time/spend sigils to bound it).
    function test_executeWithSig_fallback_nativeValueLimit_boundsRealCall() external {
        Mandate memory s = _nativeValueLimitFallbackSession(0); // no ETH
        // value == 0 to an unlisted target: permitted (and binds).
        uint256 n0 = 1;
        (bytes32 m0, bytes memory ed0) = _execTo(OTHER_TARGET, 0, hex"deadbeef");
        vm.prank(RELAYER);
        daimon.executeWithSig(
            m0, ed0, n0, type(uint256).max, _bindSigFor(s, 0, _execDigest(m0, ed0, n0))
        );
        assertTrue(daimon.isMandateBound(_mandateId(s)), "zero-value fallback call permitted");

        // value == 1 to the same target: the NativeValueLimitSigil(0) denies it.
        uint256 n1 = 2;
        (bytes32 m1, bytes memory ed1) = _execTo(OTHER_TARGET, 1, hex"deadbeef");
        bytes memory sig = _useSigDigest(_mandateId(s), _execDigest(m1, ed1, n1));
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(m1, ed1, n1, type(uint256).max, sig);
    }

    /// @notice The self-call guard precedes the fallback: even a SudoSigil catch-all does NOT let a session
    ///         target the account itself (the nested-execution bypass guard stays).
    function test_executeWithSig_fallback_selfCall_stillDenied() external {
        Mandate memory s = _sudoFallbackSession();
        // Bind via an unlisted target (the fallback permits it).
        uint256 n0 = 1;
        (bytes32 m0, bytes memory ed0) = _execTo(OTHER_TARGET, 0, hex"deadbeef");
        vm.prank(RELAYER);
        daimon.executeWithSig(
            m0, ed0, n0, type(uint256).max, _bindSigFor(s, 0, _execDigest(m0, ed0, n0))
        );

        // A call targeting the account itself: denied even with the catch-all.
        uint256 n1 = 2;
        (bytes32 m1, bytes memory ed1) = _execTo(address(daimon), 0, hex"deadbeef");
        bytes memory sig = _useSigDigest(_mandateId(s), _execDigest(m1, ed1, n1));
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(m1, ed1, n1, type(uint256).max, sig);
    }

    /// @notice The fallback sentinel is never a real call target: a call whose `to` is FALLBACK_TARGET_FLAG is
    ///         denied (it only marks the fallback entry in the mandate, it is not callable).
    function test_executeWithSig_fallback_sentinelTarget_denied() external {
        Mandate memory s = _sudoFallbackSession();
        uint256 n0 = 1;
        (bytes32 m0, bytes memory ed0) = _execTo(OTHER_TARGET, 0, hex"deadbeef");
        vm.prank(RELAYER);
        daimon.executeWithSig(
            m0, ed0, n0, type(uint256).max, _bindSigFor(s, 0, _execDigest(m0, ed0, n0))
        );

        uint256 n1 = 2;
        (bytes32 m1, bytes memory ed1) = _execTo(FALLBACK_TARGET_FLAG, 0, hex"deadbeef");
        bytes memory sig = _useSigDigest(_mandateId(s), _execDigest(m1, ed1, n1));
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(m1, ed1, n1, type(uint256).max, sig);
    }

    /// @notice A REGISTERED-but-empty exact action (sigils == []) keeps its existing default-DENY and does NOT
    ///         inherit a sibling FALLBACK — the wildcard only fills genuinely-UNREGISTERED `(target, selector)`,
    ///         so the fallback can never broaden an owner-signed exact action beyond its explicit shape. (An
    ///         UNREGISTERED target in the SAME mandate still resolves to the fallback.)
    function test_executeWithSig_emptySigilExactAction_deniedNotFallback() external {
        Mandate memory s = _swapSession();
        s.salt = bytes32(uint256(0xFA13)); // distinct id
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(sudo), initData: "" });
        ActionData[] memory actions = new ActionData[](2);
        // Registered exact action for (OTHER_TARGET, OTHER_SELECTOR) but with NO sigils — must stay denied.
        actions[0] = ActionData({
            target: OTHER_TARGET, selector: OTHER_SELECTOR, sigils: new ActionSigilData[](0)
        });
        actions[1] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s.actions = actions;
        MandateId pid = _mandateId(s);

        // Bind via an UNREGISTERED target (the fallback permits it) so the mandate is live.
        address unlisted = address(0xDEAD);
        uint256 n0 = 1;
        (bytes32 m0, bytes memory ed0) = _execTo(unlisted, 0, hex"deadbeef");
        vm.prank(RELAYER);
        daimon.executeWithSig(
            m0, ed0, n0, type(uint256).max, _bindSigFor(s, 0, _execDigest(m0, ed0, n0))
        );
        assertTrue(daimon.isMandateBound(pid), "binds via the fallback (unregistered target)");

        // The registered-but-empty exact action is DENIED — it does NOT fall through to the SudoSigil wildcard.
        uint256 n1 = 2;
        (bytes32 m1, bytes memory ed1) =
            _execTo(OTHER_TARGET, 0, abi.encodeWithSelector(OTHER_SELECTOR));
        bytes memory sig = _useSigDigest(pid, _execDigest(m1, ed1, n1));
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(m1, ed1, n1, type(uint256).max, sig);
    }

    /// @dev A mandate with the recipient-locked swap action PLUS a SudoSigil fallback (target =
    ///      FALLBACK_TARGET_FLAG, allow-all). Distinct salt so its id differs from the other suites.
    function _sudoFallbackSession() internal view returns (Mandate memory s) {
        s = _swapSession();
        s.salt = bytes32(uint256(0xFA11)); // distinct id
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: address(sudo), initData: "" });
        ActionData[] memory actions = new ActionData[](2);
        actions[0] = s.actions[0]; // the exact recipient-locked swap
        actions[1] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s.actions = actions;
    }

    /// @dev A mandate whose ONLY action is a fallback gated by a NativeValueLimitSigil(`limit`) — the wildcard
    ///      catch-all bounded to at most `limit` native value per call.
    function _nativeValueLimitFallbackSession(uint256 limit)
        internal
        view
        returns (Mandate memory s)
    {
        s = _swapSession();
        s.salt = bytes32(uint256(0xFA12)); // distinct id
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({
            sigil: address(nativeValueLimit),
            initData: abi.encode(NativeValueLimitConfig({ limit: limit }))
        });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s.actions = actions;
    }

    /// @dev A single-call execution to an arbitrary `target` with `value` + raw `data`.
    function _execTo(
        address target,
        uint256 value,
        bytes memory data
    )
        internal
        pure
        returns (bytes32 mode, bytes memory executionData)
    {
        mode = MODE_SINGLE;
        executionData = abi.encodePacked(target, value, data);
    }
}
