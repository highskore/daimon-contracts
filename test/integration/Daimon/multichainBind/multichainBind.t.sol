// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Libraries
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
import { IMandateEngine } from "@interfaces/IMandateEngine.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Contracts
import {
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Types
import {
    Mandate,
    ActionData,
    ActionSigilData,
    OutcomeSigilData,
    SignatureSigilData,
    MultichainMandateBinding,
    ChainBind,
    MandateId
} from "@types/MandateTypes.sol";

// Mocks
import { MockSwapRouter } from "@test/mock/MockSwapRouter.sol";
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title Daimon multichain BIND (sign-once, verify-everywhere) Integration Tests
/// @author highskore.eth
/// @notice Proves the MULTICHAIN bind sub-mode (0x02): a ROOT signs ONE array of per-chain bind digests under a
///         fixed, chain-independent domain; THIS chain verifies its own entry against the digest it recomputes
///         locally and checks the single ROOT signature over the re-derived array digest. The single-chain BIND
///         path (covered in executeWithSig.t.sol) is untouched — this is a NEW opt-in path.
contract Daimon_multichainBind_Integration_Test is Daimon_Integration_Test {
    /// @dev ERC-7579 execution mode: single call (first byte = call type 0).
    bytes32 internal constant MODE_SINGLE = bytes32(0);

    /// @dev `Executed(uint256 indexed nonce)`.
    event Executed(uint256 indexed nonce);

    /// @dev An OTHER chain id carried in the multichain array alongside `block.chainid` (this chain).
    uint64 internal constant OTHER_CHAIN = 10;

    /// @dev A bind deadline used by the deadline test.
    uint48 internal constant EXPIRY = 1_000_000;

    address internal constant RELAYER = address(0xCAFE);
    uint256 internal constant AMOUNT_IN = 100e6;
    uint256 internal constant AMOUNT_OUT_MIN = 1;

    MockSwapRouter internal swapRouter;
    MockERC20 internal tokenIn;
    MockERC20 internal tokenOut;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
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

    /// @notice Happy path: a 2-chain array (this chain + one other), ROOT signs the array digest ONCE; the bind
    ///         succeeds on this chain (the mandate is enabled) AND the carried swap executes in the same call.
    function test_multichainBind_happyPath_enablesAndExecutes() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes memory sig = _mcBindSig(s, _twoChainThisFirst(s), 0, _execDigest(mode, ed, execNonce));
        uint256 inBefore = tokenIn.balanceOf(address(daimon));

        vm.expectEmit(true, true, true, true, address(daimon));
        emit Executed(execNonce);
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);

        assertTrue(
            daimon.isMandateBound(pid), "multichain bind must enable the mandate on this chain"
        );
        assertEq(
            tokenOut.balanceOf(address(daimon)), AMOUNT_IN, "the carried swap must deliver output"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(address(daimon)),
            AMOUNT_IN,
            "the router must pull amountIn from the account"
        );
    }

    /// @notice Sign-once, enable-EVERYWHERE — end to end. ROOT signs ONE array digest covering chain A
    ///         (`block.chainid`) AND chain B (`OTHER_CHAIN`), then the SAME signature enables the mandate on
    ///         BOTH chains — each selecting its own entry. Chain B is simulated on the same CREATE2 account
    ///         address with independent, never-bound storage (the per-mandate enable flag + nonce zeroed, as a
    ///         second-chain deployment starts), and `vm.chainId` switches the account's EIP-712 domain so each
    ///         chain recomputes — and matches — its own per-chain bind digest. This is the headline property the
    ///         per-entry tests only cover by decomposition.
    function test_multichainBind_sameSignatureEnablesOnTwoChains() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);
        uint64 chainA = uint64(block.chainid);

        // Real per-chain bind digests at nonce 0 — each computed under THAT chain's EIP-712 domain (chainId).
        bytes32 digestA = _bindDigest(s, 0);
        vm.chainId(OTHER_CHAIN);
        bytes32 digestB = _bindDigest(s, 0);
        vm.chainId(chainA);

        ChainBind[] memory perChain = new ChainBind[](2);
        perChain[0] = ChainBind({ chainId: chainA, bindDigest: digestA });
        perChain[1] = ChainBind({ chainId: OTHER_CHAIN, bindDigest: digestB });

        // THE one signature: ROOT signs the chain-independent array digest a single time. Reused verbatim below.
        bytes memory rootSig = _sign(rootPk, HashLib.multichainBindDigest(perChain));

        // Snapshot the pristine, never-bound account so the chain-B leg runs against a GENUINELY fresh account
        // (same CREATE2 address, ZERO leftover chain-A registration — not just zeroed flags). This way a bug
        // where the multichain bind fails to fully register a fresh account cannot be masked by chain-A state.
        uint256 pristine = vm.snapshotState();

        // ── Chain A: enable via entry 0 ──
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes memory sigA = _mcSigWith(s, perChain, 0, rootSig, _execDigest(mode, ed, 1));
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sigA);
        assertTrue(daimon.isMandateBound(pid), "enabled on chain A");

        // ── Chain B: revert to the pristine account, switch chain, replay the SAME rootSig via entry 1 ──
        vm.revertToState(pristine);
        vm.chainId(OTHER_CHAIN);
        assertFalse(daimon.isMandateBound(pid), "chain B starts from a fresh, unbound account");

        bytes memory sigB = _mcSigWith(s, perChain, 1, rootSig, _execDigest(mode, ed, 1));
        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, 1, type(uint256).max, sigB);
        assertTrue(
            daimon.isMandateBound(pid), "the SAME root signature enabled the mandate on chain B"
        );
    }

    /// @notice The bind works regardless of WHERE this chain sits in the array: put this chain SECOND and point
    ///         `chainIndex` at it — still enables (proves index selection, not position-zero assumption).
    function test_multichainBind_thisChainSecondIndex_succeeds() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);

        // [OTHER, THIS] — this chain is index 1.
        ChainBind[] memory perChain = new ChainBind[](2);
        perChain[0] = ChainBind({ chainId: OTHER_CHAIN, bindDigest: bytes32(uint256(0xABCD)) });
        perChain[1] = ChainBind({ chainId: uint64(block.chainid), bindDigest: _bindDigest(s, 0) });

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes memory sig = _mcBindSig(s, perChain, 1, _execDigest(mode, ed, execNonce));

        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
        assertTrue(daimon.isMandateBound(pid), "this chain at index 1 must still bind");
    }

    /// @notice Same-chain replay: submitting the SAME multichain bind twice reverts on the 2nd — the per-mandate
    ///         nonce incremented, so the locally-recomputed digest no longer equals the (nonce-0) array entry,
    ///         surfacing as {ChainBindMismatch}.
    function test_multichainBind_sameChainReplay_revertsChainBindMismatch() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);
        ChainBind[] memory perChain = _twoChainThisFirst(s);

        // First bind consumes nonce 0.
        uint256 n0 = 1;
        (bytes32 m0, bytes memory ed0) = _swapExec(address(daimon));
        vm.prank(RELAYER);
        daimon.executeWithSig(
            m0, ed0, n0, type(uint256).max, _mcBindSig(s, perChain, 0, _execDigest(m0, ed0, n0))
        );
        assertTrue(daimon.isMandateBound(pid), "first multichain bind enables the mandate");

        // Replaying the SAME array (built at nonce 0) now mismatches: the engine is at nonce 1.
        uint256 n1 = 2;
        (bytes32 m1, bytes memory ed1) = _swapExec(address(daimon));
        bytes memory sig = _mcBindSig(s, perChain, 0, _execDigest(m1, ed1, n1));
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.ChainBindMismatch.selector, pid));
        daimon.executeWithSig(m1, ed1, n1, type(uint256).max, sig);
    }

    /// @notice Wrong chainIndex: pointing `chainIndex` at the OTHER chain's entry reverts {ChainBindMismatch}
    ///         (its chainId is not `block.chainid`).
    function test_multichainBind_wrongChainIndex_revertsChainBindMismatch() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);
        // [THIS, OTHER] but select index 1 (the OTHER chain).
        ChainBind[] memory perChain = _twoChainThisFirst(s);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes memory sig = _mcBindSig(s, perChain, 1, _execDigest(mode, ed, execNonce));
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.ChainBindMismatch.selector, pid));
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
    }

    /// @notice Tampered array: flipping a byte in a NON-this-chain entry's `bindDigest` AFTER the ROOT signed
    ///         changes the re-derived array digest, so the ROOT signature no longer verifies — {UnauthorizedBind}.
    ///         (This chain's own entry still matches, so it is the array-integrity check that catches it.)
    function test_multichainBind_tamperedOtherEntry_revertsUnauthorized() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);

        // ROOT signs the HONEST array [THIS, OTHER].
        ChainBind[] memory honest = _twoChainThisFirst(s);
        bytes memory rootSig = _sign(rootPk, HashLib.multichainBindDigest(honest));

        // The relayer tampers the OTHER chain's digest (this chain's entry is left intact so its local check
        // passes — only the array-integrity (ROOT sig) check can catch this).
        ChainBind[] memory tampered = _twoChainThisFirst(s);
        tampered[1].bindDigest = bytes32(uint256(tampered[1].bindDigest) ^ 1);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        MultichainMandateBinding memory en = MultichainMandateBinding({
            session: s,
            rootValidator: address(root1),
            rootSignature: rootSig,
            perChain: tampered,
            chainIndex: 0
        });
        bytes memory keySig = _sign(agentPk, _execDigest(mode, ed, execNonce));
        bytes memory sig = abi.encodePacked(bytes1(0x01), bytes1(0x02), abi.encode(en, keySig));

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.UnauthorizedBind.selector, pid));
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
    }

    /// @notice Forged this-chain digest: setting THIS chain's entry to a digest that does not match the locally
    ///         recomputed value reverts {ChainBindMismatch} (the local-to-signed tie). We sign the forged array
    ///         so the ROOT signature itself is valid — proving it is the local digest check that catches it.
    function test_multichainBind_forgedThisChainDigest_revertsChainBindMismatch() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);

        ChainBind[] memory forged = _twoChainThisFirst(s);
        forged[0].bindDigest = bytes32(uint256(0xDEAD)); // wrong digest for THIS chain
        bytes memory rootSig = _sign(rootPk, HashLib.multichainBindDigest(forged));

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        MultichainMandateBinding memory en = MultichainMandateBinding({
            session: s,
            rootValidator: address(root1),
            rootSignature: rootSig,
            perChain: forged,
            chainIndex: 0
        });
        bytes memory keySig = _sign(agentPk, _execDigest(mode, ed, execNonce));
        bytes memory sig = abi.encodePacked(bytes1(0x01), bytes1(0x02), abi.encode(en, keySig));

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.ChainBindMismatch.selector, pid));
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
    }

    /// @notice An out-of-range `chainIndex` reverts {ChainBindMismatch} (the bounds guard) — not a low-level
    ///         array-OOB panic.
    function test_multichainBind_indexOutOfRange_revertsChainBindMismatch() external {
        Mandate memory s = _mcSession();
        MandateId pid = _mandateId(s);
        ChainBind[] memory perChain = _twoChainThisFirst(s);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes memory sig = _mcBindSig(s, perChain, 2, _execDigest(mode, ed, execNonce)); // len == 2
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.ChainBindMismatch.selector, pid));
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
    }

    /// @notice Bind-time deadline: a multichain bind submitted after the signed `validUntil` reverts
    ///         {BindExpired}, exactly like the single-chain path. `validUntil` is committed to each per-chain
    ///         bindDigest (hence to the signed array), so the relayer cannot extend it.
    function test_multichainBind_afterValidUntil_revertsBindExpired() external {
        vm.warp(uint256(EXPIRY) + 100);
        Mandate memory s = _mcSession();
        s.validUntil = EXPIRY; // signed deadline now in the past
        MandateId pid = _mandateId(s);

        uint256 execNonce = 1;
        (bytes32 mode, bytes memory ed) = _swapExec(address(daimon));
        bytes memory sig = _mcBindSig(s, _twoChainThisFirst(s), 0, _execDigest(mode, ed, execNonce));
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IMandateEngine.BindExpired.selector, pid, EXPIRY));
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
        assertFalse(
            daimon.isMandateBound(pid), "an expired multichain bind must not enable the mandate"
        );
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A recipient-locked swap mandate over the LIVE router, with a distinct salt from the other suites.
    function _mcSession() internal view returns (Mandate memory s) {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 96,
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
            salt: bytes32(uint256(0x6C6C61)), // distinct id ("multichain")
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev A 2-entry array with THIS chain first (real bind digest at nonce 0) + a placeholder OTHER chain.
    function _twoChainThisFirst(Mandate memory s)
        internal
        view
        returns (ChainBind[] memory perChain)
    {
        perChain = new ChainBind[](2);
        perChain[0] = ChainBind({ chainId: uint64(block.chainid), bindDigest: _bindDigest(s, 0) });
        perChain[1] = ChainBind({ chainId: OTHER_CHAIN, bindDigest: bytes32(uint256(0xABCD)) });
    }

    /// @dev Build a MULTICHAIN BIND signature: `[0x01][0x02][abi.encode(MultichainMandateBinding, keySig)]`.
    ///      ROOT signs the array digest once; the session key signs the exec `digest`.
    function _mcBindSig(
        Mandate memory s,
        ChainBind[] memory perChain,
        uint256 chainIndex,
        bytes32 digest
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory rootSig = _sign(rootPk, HashLib.multichainBindDigest(perChain));
        MultichainMandateBinding memory en = MultichainMandateBinding({
            session: s,
            rootValidator: address(root1),
            rootSignature: rootSig,
            perChain: perChain,
            chainIndex: chainIndex
        });
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(0x01), bytes1(0x02), abi.encode(en, keySig));
    }

    /// @dev Assemble a MULTICHAIN BIND signature reusing a PRE-COMPUTED root signature (so the SAME ROOT sig can
    ///      be verified on multiple chains in one test), rather than re-signing like {_mcBindSig}.
    function _mcSigWith(
        Mandate memory s,
        ChainBind[] memory perChain,
        uint256 chainIndex,
        bytes memory rootSig,
        bytes32 digest
    )
        internal
        view
        returns (bytes memory)
    {
        MultichainMandateBinding memory en = MultichainMandateBinding({
            session: s,
            rootValidator: address(root1),
            rootSignature: rootSig,
            perChain: perChain,
            chainIndex: chainIndex
        });
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(0x01), bytes1(0x02), abi.encode(en, keySig));
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

    /// @dev A single-call execution routing the swap to `recipient`.
    function _swapExec(address recipient)
        internal
        view
        returns (bytes32 mode, bytes memory executionData)
    {
        mode = MODE_SINGLE;
        executionData = abi.encodePacked(address(swapRouter), uint256(0), _swapData(recipient));
    }

    /// @dev The EIP-712 execution digest the session key signs (mirrors executeWithSig.t.sol's `_execDigest`).
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
        bytes32 ds = keccak256(
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
        return keccak256(abi.encodePacked("\x19\x01", ds, structHash));
    }
}
