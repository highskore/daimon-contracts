// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";
import {
    OmniSigil,
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";
import { IdLib } from "@lib/IdLib.sol";
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";
import { ConfigId } from "@interfaces/ISigil.sol";

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
import { MockERC20 } from "@test/mock/MockERC20.sol";
import { MockSwapRouter } from "@test/mock/MockSwapRouter.sol";

/// @title Daimon Swap-With-Approve (2-action pull-input swap) Integration Tests
/// @author highskore.eth
/// @notice Drives the realistic PULL-INPUT swap mandate end to end against the live {MockSwapRouter}, which
///         pulls the swap's input token via `transferFrom`. The mandate the SDK's `buildSwapWithApproveMandate`
///         produces has TWO actions — a BOUNDED `approve(router, amountIn)` and the recipient-locked swap — plus
///         a {SpendSigil} (a pure OUTCOME sigil) capping the input token's outflow. Proves the batch
///         `[approve, swap]` succeeds within
///         the cap (the router pulls the input, the recipient receives the output, the allowance nets to zero),
///         an OFF-cap swap reverts SpendCapExceeded, an unbounded/wrong approve is blocked by OmniSigil, and an
///         attacker-recipient swap is contained.
contract Daimon_swapWithApprove_Integration_Test is Daimon_Integration_Test {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 internal constant APPROVE_SELECTOR = 0x095ea7b3; // approve(address,uint256)

    bytes32 internal constant MODE_BATCH = bytes32(uint256(1) << 248);

    address internal constant RELAYER = address(0xCAFE);

    uint256 internal constant AMOUNT_IN = 100e18; // the EXACT input the bounded approve permits
    uint256 internal constant AMOUNT_OUT = AMOUNT_IN; // the 1:1 demo router mints `amountIn` to `to`
    uint256 internal constant CAP = 250e18; // mUSDC outflow cap (allows 2 swaps, not 3)
    uint256 internal constant FUNDING = 1000e18;

    /// @dev A single batch entry, matching solady `LibERC7579`'s `abi.encode(Call[])` batch layout.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    SpendSigil internal spendSigil;
    MockSwapRouter internal router;
    MockERC20 internal tokenIn; // mUSDC (pulled by the router)
    MockERC20 internal tokenOut; // mWETH (minted to the recipient)

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        spendSigil = new SpendSigil();
        router = new MockSwapRouter();
        tokenIn = new MockERC20("USD", "USD");
        tokenOut = new MockERC20("WETH", "WETH");
        // Fund the account with the input token so the router has something to pull.
        tokenIn.mint(address(daimon), FUNDING);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice SUT: the full 2-action mandate. A within-cap self-swap batch `[approve, swap]` (carrying the inline
    ///         genesis-style BIND) succeeds: the router pulls the input, the recipient (the account) receives the
    ///         output, the allowance nets to zero, and the input outflow is debited to the cap.
    function test_swapWithApprove_self_withinCap_succeeds() external {
        uint256 inBefore = tokenIn.balanceOf(address(daimon));
        uint256 outBefore = tokenOut.balanceOf(address(daimon));

        (bytes32 mode, bytes memory ed) = _swapBatch(address(daimon));
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, _bindUseSig(1, mode, ed));

        // The router pulled exactly AMOUNT_IN of the input and minted AMOUNT_OUT of the output to the account.
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)), AMOUNT_IN, "input pulled by the router"
        );
        assertEq(
            tokenOut.balanceOf(address(daimon)) - outBefore,
            AMOUNT_OUT,
            "output minted to recipient"
        );
        // The swap consumed the approval, so no allowance dangles (the post-check would have reverted otherwise).
        assertEq(
            tokenIn.allowance(address(daimon), address(router)), 0, "approval consumed, no dangle"
        );
        // The input outflow is metered to the rolling cap (max of calldata-sum and balance-delta == AMOUNT_IN).
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, AMOUNT_IN, "input outflow debited to the cap");
    }

    /// @notice SUT: the SpendSigil outcome cap. After two swaps (2 * 100 = 200 <= 250), a third swap pushes the
    ///         cumulative input outflow over the cap, reverts SpendCapExceeded, and rolls the whole batch back
    ///         (no pull, no allowance left behind).
    function test_swapWithApprove_overCap_reverts() external {
        // Swap 1 carries the inline bind; swaps 2 onward are plain MANDATE USEs.
        (bytes32 m1, bytes memory e1) = _swapBatch(address(daimon));
        vm.prank(RELAYER);
        daimon.executeWithSig(m1, e1, 1, type(uint256).max, _bindUseSig(1, m1, e1));
        (bytes32 m2, bytes memory e2) = _swapBatch(address(daimon));
        vm.prank(RELAYER);
        daimon.executeWithSig(m2, e2, 2, type(uint256).max, _useSig(2, m2, e2));

        // The third swap would make 300 > 250 -> revert; the whole tx rolls back.
        (bytes32 m3, bytes memory e3) = _swapBatch(address(daimon));
        bytes memory sig3 = _useSig(3, m3, e3);
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, _cid(), 300e18, CAP)
        );
        daimon.executeWithSig(m3, e3, 3, type(uint256).max, sig3);

        assertEq(tokenIn.balanceOf(address(daimon)), inBefore, "over-cap swap moves no input");
        assertEq(
            tokenIn.allowance(address(daimon), address(router)),
            0,
            "rolled back: no dangling approval"
        );
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, 200e18, "spend stays at the two committed swaps");
    }

    /// @notice SUT: the OmniSigil bound on the approve. An approve for MORE than amountIn (e.g. the unlimited
    ///         type(uint256).max grant) is rejected by the OmniSigil amount-EQUAL rule — the agent can never
    ///         widen the allowance the swap needs.
    function test_swapWithApprove_unboundedApprove_blocked() external {
        Call[] memory calls = new Call[](2);
        calls[0] = _approveCall(address(router), type(uint256).max); // unbounded grant
        calls[1] = _swapCall(address(daimon));
        (bytes32 mode, bytes memory ed) = _batchExec(calls);
        bytes memory sig = _bindUseSig(1, mode, ed);

        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sig);
    }

    /// @notice SUT: the OmniSigil bound on the approve. An approve naming a spender OTHER than the router is
    ///         rejected by the OmniSigil spender-EQUAL rule (a hijacked agent can't approve an attacker).
    function test_swapWithApprove_wrongSpender_blocked() external {
        Call[] memory calls = new Call[](2);
        calls[0] = _approveCall(ATTACKER, AMOUNT_IN); // right amount, WRONG spender
        calls[1] = _swapCall(address(daimon));
        (bytes32 mode, bytes memory ed) = _batchExec(calls);
        bytes memory sig = _bindUseSig(1, mode, ed);

        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sig);
    }

    /// @notice SUT: the OmniSigil recipient lock on the swap. A swap whose `to` is an attacker is rejected — the
    ///         recipient lock contains the redirect even when the approve is in-bounds.
    function test_swapWithApprove_attackerRecipient_contained() external {
        Call[] memory calls = new Call[](2);
        calls[0] = _approveCall(address(router), AMOUNT_IN); // in-bounds approve
        calls[1] = _swapCall(ATTACKER); // redirect attempt
        (bytes32 mode, bytes memory ed) = _batchExec(calls);
        bytes memory sig = _bindUseSig(1, mode, ed);

        uint256 attackerBefore = tokenOut.balanceOf(ATTACKER);
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sig);
        assertEq(tokenOut.balanceOf(ATTACKER), attackerBefore, "attacker received nothing");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The 2-action swap mandate: a bounded approve(router, amountIn) + a recipient-locked swap, each gated
    ///      per-call by an OmniSigil, with the SpendSigil ONLY as the per-execution OUTCOME cap on the input
    ///      token (it is a pure outcome sigil — never attached to an action).
    function _swapSession() internal view returns (Mandate memory s) {
        bytes memory spendCfg = abi.encode(_spendConfig());

        // Action 0 — bounded approve: spender (offset 0) == router AND amount (offset 32) == amountIn.
        ParamRule[] memory approveRules = new ParamRule[](2);
        approveRules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0,
            isLimited: false,
            ref: bytes32(uint256(uint160(address(router)))),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        approveRules[1] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 32,
            isLimited: false,
            ref: bytes32(AMOUNT_IN),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        uint256[] memory approveNodes = new uint256[](3);
        approveNodes[0] = OmniSigilTreeLib.createRuleNode(0);
        approveNodes[1] = OmniSigilTreeLib.createRuleNode(1);
        approveNodes[2] = OmniSigilTreeLib.createAndNode(0, 1);
        ActionConfig memory approveCfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({
                rootNodeIndex: 2, rules: approveRules, packedNodes: approveNodes
            })
        });
        ActionSigilData[] memory approveSigils = new ActionSigilData[](1);
        approveSigils[0] =
            ActionSigilData({ sigil: address(omni), initData: abi.encode(approveCfg) });

        // Action 1 — recipient-locked swap: `to` (offset 96) == account.
        ParamRule[] memory swapRules = new ParamRule[](1);
        swapRules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 96,
            isLimited: false,
            ref: bytes32(uint256(uint160(address(daimon)))),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        uint256[] memory swapNodes = new uint256[](1);
        swapNodes[0] = OmniSigilTreeLib.createRuleNode(0);
        ActionConfig memory swapCfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: swapRules, packedNodes: swapNodes })
        });
        ActionSigilData[] memory swapSigils = new ActionSigilData[](1);
        swapSigils[0] = ActionSigilData({ sigil: address(omni), initData: abi.encode(swapCfg) });

        ActionData[] memory actions = new ActionData[](2);
        actions[0] = ActionData({
            target: address(tokenIn), selector: APPROVE_SELECTOR, sigils: approveSigils
        });
        actions[1] =
            ActionData({ target: address(router), selector: SWAP_SELECTOR, sigils: swapSigils });

        OutcomeSigilData[] memory outs = new OutcomeSigilData[](1);
        outs[0] = OutcomeSigilData({ sigil: address(spendSigil), initData: spendCfg });

        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x5117a9a9)),
            validUntil: 0,
            actions: actions,
            outcomeSigils: outs,
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev The SpendSigil config: budget the INPUT token, cap CAP, Day window, allowlist = [router].
    function _spendConfig() internal view returns (SpendConfig memory c) {
        address[] memory spenders = new address[](1);
        spenders[0] = address(router);
        c = SpendConfig({
            token: address(tokenIn), cap: CAP, period: Period.Day, spenders: spenders
        });
    }

    /// @dev The MandateId of the swap mandate.
    function _swapMandateId() internal view returns (MandateId) {
        return _mandateId(_swapSession());
    }

    /// @dev The outcome-sigil ConfigId for this mandate (per-execution, keyed by the mandate alone).
    function _cid() internal view returns (ConfigId) {
        return IdLib.toMandateConfigId(_swapMandateId());
    }

    /// @dev A BIND+USE signature: the inline genesis-style mandate BIND (ROOT-signed) packed with the agent's
    ///      USE signature over the exec digest for `(mode, ed, nonce)`. The BIND always carries the clean
    ///      `_swapSession()` policy; the caller supplies the batch actually executed against it — an in-bounds
    ///      `[approve, swap]` for the happy path, or a violating batch the sigils must reject. The `0` is the
    ///      BIND nonce (distinct from the exec `nonce`); each test binds once at a fresh account.
    function _bindUseSig(
        uint256 nonce,
        bytes32 mode,
        bytes memory ed
    )
        internal
        view
        returns (bytes memory)
    {
        Mandate memory s = _swapSession();
        bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: address(root1), rootSignature: rootSig });
        bytes memory keySig = _sign(agentPk, _execDigest(mode, ed, nonce));
        return abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));
    }

    /// @dev A USE-mode signature over the exec digest for `(mode, ed, nonce)`.
    function _useSig(
        uint256 nonce,
        bytes32 mode,
        bytes memory ed
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory keySig = _sign(agentPk, _execDigest(mode, ed, nonce));
        return
            abi.encodePacked(bytes1(0x01), bytes1(0x00), MandateId.unwrap(_swapMandateId()), keySig);
    }

    /// @dev The ordered swap batch `[approve(router, amountIn), swap(...to)]`.
    function _swapBatch(address to) internal view returns (bytes32 mode, bytes memory ed) {
        Call[] memory calls = new Call[](2);
        calls[0] = _approveCall(address(router), AMOUNT_IN);
        calls[1] = _swapCall(to);
        return _batchExec(calls);
    }

    /// @dev An `inputToken.approve(spender, amount)` call.
    function _approveCall(address spender, uint256 amount) internal view returns (Call memory) {
        return _call(address(tokenIn), abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount));
    }

    /// @dev A `router.swapExactTokensForTokens(amountIn, amountOutMin, [in, out], to, deadline)` call.
    function _swapCall(address to) internal view returns (Call memory) {
        address[] memory path = new address[](2);
        path[0] = address(tokenIn);
        path[1] = address(tokenOut);
        bytes memory data = abi.encodeWithSelector(
            MockSwapRouter.swapExactTokensForTokens.selector,
            AMOUNT_IN,
            AMOUNT_OUT,
            path,
            to,
            block.timestamp + 3600
        );
        return _call(address(router), data);
    }

    /// @dev A generic `Call` to `to` with `data`.
    function _call(address to, bytes memory data) internal pure returns (Call memory) {
        return Call({ to: to, value: 0, data: data });
    }

    /// @dev A batch execution (ERC-7579 batch mode): `ed = abi.encode(Call[])`.
    function _batchExec(Call[] memory calls) internal pure returns (bytes32 mode, bytes memory ed) {
        mode = MODE_BATCH;
        ed = abi.encode(calls);
    }

    /// @dev The EIP-712 execution digest the signer commits to (mirrors the contract).
    function _execDigest(
        bytes32 mode,
        bytes memory ed,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        (, string memory name, string memory version, uint256 chainId, address vc,,) =
            daimon.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                vc
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(HashLib.EXEC_TYPEHASH, mode, keccak256(ed), nonce, type(uint256).max)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
