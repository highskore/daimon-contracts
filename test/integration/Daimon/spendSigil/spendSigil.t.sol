// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";
import { ConfigId } from "@interfaces/ISigil.sol";

// Libraries
import { IdLib } from "@lib/IdLib.sol";
import { HashLib } from "@lib/HashLib.sol";

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
import { MockPullSink } from "@test/mock/MockPullSink.sol";

/// @title Daimon SpendSigil (outcome-bracketed rolling spend cap) Integration Tests
/// @author highskore.eth
/// @notice Drives the {SpendSigil} end to end over the real `executeWithSig` MANDATE path against a live
///         MockERC20: a relayer submits a session-key-signed ERC-7579 single/batch, each action is permitted by
///         a {SudoSigil} (allow-all) and the loop is bracketed by the SpendSigil's {SpendSigil.preCheck} and
///         {SpendSigil.postCheck} outcome hooks. The SpendSigil is a PURE outcome sigil — it is NOT attached to
///         any action; {postCheck} itemizes the executed call set GLOBALLY to build the calldata sum. Proves the
///         cumulative cap debits real balance moves, the `max(global-calldata-sum, balance-delta)` meter catches
///         an unparsed outflow AND defeats inflow-masking, approvals are auto-checked for dangling allowance,
///         and the ROOT (owner) path bypasses the whole thing.
contract Daimon_spendSigil_Integration_Test is Daimon_Integration_Test {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 internal constant TRANSFER_SELECTOR = 0xa9059cbb; // transfer(address,uint256)
    bytes4 internal constant APPROVE_SELECTOR = 0x095ea7b3; // approve(address,uint256)
    bytes4 internal constant MINT_SELECTOR = 0x40c10f19; // mint(address,uint256)
    bytes4 internal constant PULL_SELECTOR = MockPullSink.pull.selector; // pull(address,uint256)

    bytes32 internal constant MODE_SINGLE = bytes32(0);
    bytes32 internal constant MODE_BATCH = bytes32(uint256(1) << 248);

    address internal constant RELAYER = address(0xCAFE);
    address internal constant PAYEE = address(0x7777);
    uint256 internal constant CAP = 10e6;
    uint256 internal constant FUNDING = 1000e6;

    event Executed(uint256 indexed nonce);

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
    SudoSigil internal sudo;
    MockERC20 internal token;
    MockPullSink internal sink;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        spendSigil = new SpendSigil();
        sudo = new SudoSigil();
        token = new MockERC20("USD", "USD");
        sink = new MockPullSink();
        token.mint(address(daimon), FUNDING);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice SUT: SpendSigil.postCheck. A transfer within the cap executes, delivers the tokens, and
    ///         debits the rolling `spent`.
    function test_spendSigil_withinCap_succeeds_andDebits() external {
        _bind(0);

        uint256 amount = 6e6;
        (bytes32 mode, bytes memory ed) = _singleExec(_transferCall(PAYEE, amount));
        uint256 balBefore = token.balanceOf(PAYEE);

        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, _useSig(1, mode, ed));

        assertEq(token.balanceOf(PAYEE) - balBefore, amount, "payee must receive the transfer");
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, amount, "rolling spend must be debited by the outflow");
    }

    /// @notice SUT: SpendSigil.postCheck. Two transfers that cumulatively exceed the cap: the second
    ///         reverts SpendCapExceeded and the WHOLE tx rolls back (no debit, no transfer).
    function test_spendSigil_overCap_reverts_wholeTx() external {
        _bind(0);

        // First payment of 6 (within cap) accrues.
        (bytes32 m1, bytes memory e1) = _singleExec(_transferCall(PAYEE, 6e6));
        vm.prank(RELAYER);
        daimon.executeWithSig(m1, e1, 1, type(uint256).max, _useSig(1, m1, e1));

        // Second payment of 6 would make 12 > 10 -> revert.
        (bytes32 m2, bytes memory e2) = _singleExec(_transferCall(PAYEE, 6e6));
        bytes memory sig2 = _useSig(2, m2, e2);
        uint256 balBefore = token.balanceOf(PAYEE);

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, _cid(), 12e6, CAP)
        );
        daimon.executeWithSig(m2, e2, 2, type(uint256).max, sig2);

        assertEq(token.balanceOf(PAYEE), balBefore, "over-cap call must move no tokens");
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, 6e6, "rolling spend must stay at the first (committed) payment");
    }

    /// @notice SUT: SpendSigil.startOfPeriod + postCheck. After the rolling Day window elapses, `spent`
    ///         resets to 0 and a fresh full-cap spend succeeds.
    function test_spendSigil_rollingWindow_resets() external {
        _bind(0);

        // Spend the full cap in period 1.
        (bytes32 m1, bytes memory e1) = _singleExec(_transferCall(PAYEE, CAP));
        vm.prank(RELAYER);
        daimon.executeWithSig(m1, e1, 1, type(uint256).max, _useSig(1, m1, e1));
        (uint256 spent1,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent1, CAP, "period 1 spend equals the cap");

        // Advance past the day boundary: the next charge must reset `spent`.
        vm.warp(block.timestamp + 2 days);

        (bytes32 m2, bytes memory e2) = _singleExec(_transferCall(PAYEE, CAP));
        vm.prank(RELAYER);
        daimon.executeWithSig(m2, e2, 2, type(uint256).max, _useSig(2, m2, e2));
        (uint256 spent2,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent2, CAP, "the window reset; a fresh full-cap spend is allowed");
    }

    /// @notice SUT: SpendSigil.postCheck. An approve left dangling (allowance != 0 at post-check) reverts
    ///         DanglingAllowance and rolls the whole tx back. The spender is collected from the executed call
    ///         set by postCheck itself (no per-action attachment).
    function test_spendSigil_danglingApproval_reverts() external {
        _bind(0);

        uint256 amount = 4e6;
        (bytes32 mode, bytes memory ed) = _singleExec(_approveCall(address(sink), amount));
        bytes memory sig = _useSig(1, mode, ed);

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpendSigil.DanglingAllowance.selector, _cid(), address(sink), amount
            )
        );
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sig);

        assertEq(token.allowance(address(daimon), address(sink)), 0, "tx rolled back: no allowance");
    }

    /// @notice SUT: SpendSigil.postCheck. An approve followed by a use (transferFrom) and a reset (approve 0)
    ///         in one batch: it executes, charges the approved amount once to the cap (via the global
    ///         calldata-sum), and leaves no dangling allowance.
    function test_spendSigil_approveUseReset_batch_succeeds() external {
        _bind(0);

        uint256 amount = 4e6;
        Call[] memory calls = new Call[](3);
        calls[0] = _approveCall(address(sink), amount); // grant
        calls[1] = _pullCall(amount); // sink pulls via transferFrom
        calls[2] = _approveCall(address(sink), 0); // reset
        (bytes32 mode, bytes memory ed) = _batchExec(calls);
        uint256 sinkBefore = token.balanceOf(address(sink));

        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, _useSig(1, mode, ed));

        assertEq(
            token.balanceOf(address(sink)) - sinkBefore, amount, "sink pulled the approved amount"
        );
        assertEq(token.allowance(address(daimon), address(sink)), 0, "allowance reset -> no dangle");
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, amount, "the approval is charged once (max of calldata-sum and delta)");
    }

    /// @notice INTENDED BEHAVIOR (finding #2 lock — NOT a soundness bug): the `spenders` allowlist governs ONLY
    ///         the ERC-1271 signing tier. On the EXECUTION path the allow-all SudoSigil does not constrain which
    ///         spender an `approve` may name, so an approve to a NON-allowlisted spender (here ATTACKER, absent
    ///         from the [sink] allowlist) is ALLOWED — provided it nets back to zero in the same execution (the
    ///         dangling-allowance scan) and the metered grant stays under the cap. It is charged to the cap; it
    ///         can never leave a standing allowance to be pulled out-of-band. This documents the choice as
    ///         deliberate: per-spender EXECUTION locks belong on an OmniSigil action rule, not on the cap.
    function test_spendSigil_approveNonAllowlistedSpender_resetInBatch_allowed() external {
        _bind(0);

        uint256 amount = 4e6;
        Call[] memory calls = new Call[](2);
        calls[0] = _approveCall(ATTACKER, amount); // grant to a NON-allowlisted spender
        calls[1] = _approveCall(ATTACKER, 0); // reset within the SAME batch -> no dangle
        (bytes32 mode, bytes memory ed) = _batchExec(calls);

        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, _useSig(1, mode, ed));

        assertEq(
            token.allowance(address(daimon), ATTACKER),
            0,
            "allowance reset within the batch -> no dangle"
        );
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(
            spent,
            amount,
            "the non-allowlisted approve is charged to the cap (execution-path allows it)"
        );
    }

    /// @notice SUT: SpendSigil.postCheck (the max() backstop). An outflow that leaves via an unparsed
    ///         target (a pre-existing allowance pull) is undercounted by the calldata sum (0) but caught by
    ///         the real balance delta, so an over-cap pull reverts SpendCapExceeded.
    function test_spendSigil_unparsedOutflow_caughtByMax() external {
        _bind(0);

        // A pre-existing allowance (granted out-of-band, e.g. by ROOT before the mandate) lets the sink
        // pull tokens via a selector SpendSigil does NOT parse, so the calldata sum stays 0.
        vm.prank(address(daimon));
        token.approve(address(sink), type(uint256).max);

        uint256 over = CAP + 1; // a pull above the cap
        (bytes32 mode, bytes memory ed) = _singleExec(_pullCall(over));
        bytes memory sig = _useSig(1, mode, ed);

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, _cid(), over, CAP)
        );
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sig);

        // And a within-cap pull via the same unparsed path IS metered (debited), proving max() charges it.
        uint256 ok = 7e6;
        (bytes32 m2, bytes memory e2) = _singleExec(_pullCall(ok));
        vm.prank(RELAYER);
        daimon.executeWithSig(m2, e2, 2, type(uint256).max, _useSig(2, m2, e2));
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, ok, "the unparsed pull is charged via the balance-delta max()");
    }

    /// @notice SUT: SpendSigil.postCheck (the GLOBAL calldata-sum defeats inflow-masking). The headline fix:
    ///         the SpendSigil is ONLY in outcomes (NOT attached to any action). A single execution mints an
    ///         INFLOW of the budgeted token and then transfers a gross OUTFLOW above the cap, so the NET balance
    ///         delta is ~0 — masking the outflow in the delta. Because postCheck itemizes EVERY executed call,
    ///         the global calldata-sum still sees the gross transfer and the cap CATCHES it (SpendCapExceeded).
    ///         With the old per-action attachment an ungated value-bearing action could leave the sum
    ///         incomplete; here there is no attachment at all and the mask still dies.
    function test_spendSigil_inflowMask_caughtByGlobalCalldataSum() external {
        _bind(0);

        uint256 gross = CAP + 5e6; // a gross outflow above the cap
        Call[] memory calls = new Call[](2);
        calls[0] = _mintCall(address(daimon), gross); // INFLOW: balance up by `gross`
        calls[1] = _transferCall(PAYEE, gross); // OUTFLOW: balance down by `gross` -> net delta 0
        (bytes32 mode, bytes memory ed) = _batchExec(calls);
        bytes memory sig = _useSig(1, mode, ed);

        // The balance delta nets to 0 (the mint masks the transfer), but the global calldata-sum is `gross`.
        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, _cid(), gross, CAP)
        );
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sig);
    }

    /// @notice SUT: ExecLib.enforceAndExecute (ROOT path). A ROOT-authorized over-cap transfer bypasses the
    ///         spend cap entirely — the outcome hooks never run on the owner path.
    function test_spendSigil_rootPath_bypassesCap() external {
        _bind(0);

        uint256 over = CAP + 50e6; // far over the cap
        (bytes32 mode, bytes memory ed) = _singleExec(_transferCall(PAYEE, over));
        bytes32 digest = _execDigest(mode, ed, 9);
        bytes memory sig = _rootSig(address(root1), rootPk, digest);
        uint256 balBefore = token.balanceOf(PAYEE);

        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 9, type(uint256).max, sig);

        assertEq(
            token.balanceOf(PAYEE) - balBefore, over, "ROOT bypasses the cap: full transfer lands"
        );
        (uint256 spent,) = spendSigil.spendStates(_cid(), address(daimon), address(daimon));
        assertEq(spent, 0, "ROOT path never runs the outcome hooks: no debit");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The spend mandate: per-call actions (token.transfer/approve/mint and sink.pull) each permitted by a
    ///      SudoSigil (allow-all), with the SpendSigil ONLY as the per-execution OUTCOME cap (token, CAP, Day).
    ///      The SpendSigil is a pure outcome sigil and is NOT attached to any action.
    function _spendSigilSession() internal view returns (Mandate memory s) {
        // Each action is permitted by an allow-all SudoSigil; the cap is enforced entirely by the outcome tier.
        ActionSigilData[] memory permit = new ActionSigilData[](1);
        permit[0] = ActionSigilData({ sigil: address(sudo), initData: "" });

        ActionData[] memory actions = new ActionData[](4);
        actions[0] =
            ActionData({ target: address(token), selector: TRANSFER_SELECTOR, sigils: permit });
        actions[1] =
            ActionData({ target: address(token), selector: APPROVE_SELECTOR, sigils: permit });
        actions[2] = ActionData({ target: address(token), selector: MINT_SELECTOR, sigils: permit });
        actions[3] = ActionData({ target: address(sink), selector: PULL_SELECTOR, sigils: permit });

        OutcomeSigilData[] memory outs = new OutcomeSigilData[](1);
        outs[0] = OutcomeSigilData({ sigil: address(spendSigil), initData: abi.encode(_config()) });

        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(uint256(0x59169119)), // distinct from the other suites' mandates
            validUntil: 0,
            actions: actions,
            outcomeSigils: outs,
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev The SpendSigil config: budget `token`, cap `CAP`, Day window, allowlist = [sink].
    function _config() internal view returns (SpendConfig memory c) {
        address[] memory spenders = new address[](1);
        spenders[0] = address(sink);
        c = SpendConfig({ token: address(token), cap: CAP, period: Period.Day, spenders: spenders });
    }

    /// @dev The MandateId of the spend-sigil mandate.
    function _spendSigilMandateId() internal view returns (MandateId) {
        return _mandateId(_spendSigilSession());
    }

    /// @dev The outcome-sigil ConfigId for this mandate (per-execution, keyed by the mandate alone).
    function _cid() internal view returns (ConfigId) {
        return IdLib.toOutcomeConfigId(_spendSigilMandateId());
    }

    /// @dev Bind the spend-sigil mandate inline at the given exec `nonce`, via a no-op self-transfer of 0.
    function _bind(uint256 nonce) internal {
        Mandate memory s = _spendSigilSession();
        bytes memory rootSig = _sign(rootPk, _bindDigest(s, 0));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: address(root1), rootSignature: rootSig });

        // Bind alongside a within-cap transfer of 0 (a no-op outflow) so the BIND+execute succeeds.
        (bytes32 mode, bytes memory ed) = _singleExec(_transferCall(PAYEE, 0));
        bytes memory keySig = _sign(agentPk, _execDigest(mode, ed, nonce));
        bytes memory sig = abi.encodePacked(bytes1(0x01), bytes1(0x01), abi.encode(en, keySig));
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig);
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
        return abi.encodePacked(
            bytes1(0x01), bytes1(0x00), MandateId.unwrap(_spendSigilMandateId()), keySig
        );
    }

    /// @dev A `token.transfer(to, amount)` call.
    function _transferCall(address to, uint256 amount) internal view returns (Call memory) {
        return _call(address(token), abi.encodeWithSelector(TRANSFER_SELECTOR, to, amount));
    }

    /// @dev A `token.approve(spender, amount)` call.
    function _approveCall(address spender, uint256 amount) internal view returns (Call memory) {
        return _call(address(token), abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount));
    }

    /// @dev A `token.mint(to, amount)` call (an INFLOW of the budgeted token; not metered as outflow).
    function _mintCall(address to, uint256 amount) internal view returns (Call memory) {
        return _call(address(token), abi.encodeWithSelector(MINT_SELECTOR, to, amount));
    }

    /// @dev A `sink.pull(token, amount)` call (unparsed selector; pulls via transferFrom).
    function _pullCall(uint256 amount) internal view returns (Call memory) {
        return _call(address(sink), abi.encodeWithSelector(PULL_SELECTOR, address(token), amount));
    }

    /// @dev A generic `Call` to `to` with `data`.
    function _call(address to, bytes memory data) internal pure returns (Call memory) {
        return Call({ to: to, value: 0, data: data });
    }

    /// @dev A single-call execution (ERC-7579 single mode).
    function _singleExec(Call memory c) internal pure returns (bytes32 mode, bytes memory ed) {
        mode = MODE_SINGLE;
        ed = abi.encodePacked(c.to, c.value, c.data);
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
