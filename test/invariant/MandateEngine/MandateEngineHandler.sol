// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";

// Libraries
import { HashLib } from "@lib/HashLib.sol";
import { IdLib } from "@lib/IdLib.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";
import { IDaimon } from "@interfaces/IDaimon.sol";
import { IMandateEngine } from "@interfaces/IMandateEngine.sol";

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

/// @title MandateEngineHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the engine's two replay guards, driving the REAL account through the
///         direct-call (`executeWithSig`) path with REAL ROOT + session-key signatures:
///           - EXEC nonce (single-use): {directExec} submits a ROOT-signed benign call over a SMALL nonce
///             range, so the fuzz naturally re-picks a burned nonce — which MUST revert. Oracle: success ⟺ the
///             nonce was fresh in the INDEPENDENT ghost.
///           - ENABLE nonce (monotone / bind-sig non-replayable): {bind} binds a pool mandate at its CURRENT
///             nonce (MUST succeed, advancing the ghost), and {staleBind} re-submits a bind signed at a PAST
///             nonce (MUST revert {UnauthorizedBind}).
///           - REVOKE (no nonce reset): {revoke} kills a bound mandate via a ROOT-signed `revokeMandate`
///             self-call (it MUST end up disabled), and {revokeThenReplayStaleBind} proves a bind signature
///             committed BEFORE the revoke can never re-enable the mandate (the enable nonce is not reset by a
///             revoke, so the stale signature still fails {UnauthorizedBind}).
///         Benign executions hit a {MockSink} so a submission's outcome turns only on the nonce/auth logic.
///         Branch counters prove the fuzz reached each state.
contract MandateEngineHandler is CommonBase, StdCheats, StdUtils {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant MODE_SINGLE = bytes32(0);
    uint8 private constant MODE_ROOT = 0x00;
    uint8 private constant MODE_MANDATE = 0x01;
    uint8 private constant SUBMODE_BIND = 0x01;

    /// @dev Small direct-exec nonce space so the fuzz frequently re-picks a burned nonce (exercises the revert).
    uint256 private constant EXEC_SLOTS = 4;
    /// @dev Distinct mandates (by salt) the bind invariants advance independently.
    uint256 private constant POOL = 3;
    /// @dev Bind executions draw nonces from here so they never collide with the EXEC_SLOTS range.
    uint256 private constant BIND_NONCE_BASE = 1 << 128;

    address private constant RELAYER = address(0xCAFE);

    Daimon internal immutable daimon;
    address internal immutable root1; // ROOT validator scheme
    address internal immutable sessionValidator;
    address internal immutable sudo; // allow-all sigil for the fallback action
    address internal immutable sink; // benign call target
    uint256 internal immutable rootPk;
    uint256 internal immutable agentPk;
    address internal immutable agent;
    bytes32 internal immutable domainSeparator;

    // ── independent ghost of the two nonce spaces ──
    mapping(uint256 => bool) public ghostExecUsed;
    uint256[] public consumed; // every direct-exec nonce the ghost has seen burned
    mapping(MandateId => uint256) public ghostEnableNonce;

    uint256 private bindNonceCounter; // monotonic source of fresh bind-exec nonces

    // ── coverage telemetry: asserted > 0 in afterInvariant ──
    uint256 public execSucceeded;
    uint256 public execRejectedAsUsed;
    uint256 public bindDone;
    uint256 public bindRejectedStale;
    uint256 public revokeDone;
    uint256 public revokeReplayRejected;

    constructor(
        Daimon _daimon,
        address _root1,
        uint256 _rootPk,
        uint256 _agentPk,
        address _sessionValidator,
        address _sudo,
        address _sink
    ) {
        daimon = _daimon;
        root1 = _root1;
        rootPk = _rootPk;
        agentPk = _agentPk;
        agent = vm.addr(_agentPk);
        sessionValidator = _sessionValidator;
        sudo = _sudo;
        sink = _sink;

        (, string memory name, string memory version, uint256 chainId, address vc,,) =
            _daimon.eip712Domain();
        domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                vc
            )
        );
    }

    /*·:⛧:·──────── VIEWS (for the invariant) ────────:⛧:·*/

    function poolLength() external pure returns (uint256) {
        return POOL;
    }

    function consumedLength() external view returns (uint256) {
        return consumed.length;
    }

    /// @notice The MandateId of pool slot `i` (so the invariant can read on-chain vs. ghost enable nonces).
    function pidAt(uint256 i) external view returns (MandateId) {
        return IdLib.toMandateId(_mandate(i));
    }

    /*·:⛧:·──────── ACTIONS ────────:⛧:·*/

    /// @notice Submit a ROOT-signed benign execution over a SMALL nonce range; a re-picked (burned) nonce MUST
    ///         revert, a fresh one MUST succeed. The ghost is the oracle.
    function directExec(uint256 seed) external {
        uint256 nonce = bound(seed, 0, EXEC_SLOTS - 1);
        (bytes32 mode, bytes memory ed) = _benignExec();
        bytes memory sig = _rootSig(_execDigest(mode, ed, nonce));
        bool wasUsed = ghostExecUsed[nonce];

        vm.prank(RELAYER);
        try daimon.executeWithSig(mode, ed, nonce, type(uint256).max, sig) {
            require(!wasUsed, "REPLAY ALLOWED: a consumed exec nonce re-executed");
            _markConsumed(nonce);
            ++execSucceeded;
        } catch (bytes memory err) {
            require(wasUsed, "SPURIOUS REVERT: a fresh exec nonce was rejected");
            require(
                keccak256(err)
                    == keccak256(abi.encodeWithSelector(IDaimon.ExecNonceUsed.selector, nonce)),
                "exec replay rejected for the WRONG reason (not ExecNonceUsed)"
            );
            ++execRejectedAsUsed;
        }
    }

    /// @notice Bind a pool mandate at its CURRENT enable nonce — MUST succeed and advance the nonce by one.
    function bind(uint256 seed) external {
        _doBind(bound(seed, 0, POOL - 1));
    }

    /// @notice Replay a bind signed at a PAST enable nonce — MUST revert {UnauthorizedBind} (the engine
    ///         recomputes the digest at the now-advanced nonce, so the stale signature no longer verifies).
    function staleBind(uint256 seed) external {
        uint256 slot = bound(seed, 0, POOL - 1);
        Mandate memory s = _mandate(slot);
        MandateId pid = IdLib.toMandateId(s);
        if (ghostEnableNonce[pid] == 0) _doBind(slot); // ensure a prior (now-stale) nonce exists

        uint256 staleNonce = ghostEnableNonce[pid] - 1;
        uint256 execNonce = _freshBindNonce();
        (bytes32 mode, bytes memory ed) = _benignExec();
        bytes memory sig = _bindSig(s, pid, staleNonce, _execDigest(mode, ed, execNonce));

        vm.prank(RELAYER);
        try daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig) {
            revert("STALE BIND ALLOWED: a bind signed at a past nonce succeeded");
        } catch (bytes memory err) {
            // MUST be UnauthorizedBind — not e.g. an exec-nonce clash (the bind exec nonce is always fresh).
            require(
                keccak256(err)
                    == keccak256(
                        abi.encodeWithSelector(IMandateEngine.UnauthorizedBind.selector, pid)
                    ),
                "stale bind rejected for the WRONG reason (not UnauthorizedBind)"
            );
            // The whole tx reverted, so the (fresh) exec nonce burn was rolled back — do NOT mark it consumed.
            ++bindRejectedStale;
        }
    }

    /// @notice Revoke a (first ensured-bound) pool mandate via a ROOT-signed `revokeMandate` self-call. The
    ///         per-mandate enable nonce is intentionally NOT reset by a revoke, so the ghost stays in lock-step
    ///         (it only advanced on the bind) — {invariant_enableNonceMatchesGhost} keeps holding across the
    ///         revoke, and the mandate must end up disabled.
    function revoke(uint256 seed) external {
        uint256 slot = bound(seed, 0, POOL - 1);
        Mandate memory s = _mandate(slot);
        MandateId pid = IdLib.toMandateId(s);
        if (ghostEnableNonce[pid] == 0) _doBind(slot); // ensure something is bound to revoke

        _doRevoke(pid);
        require(!daimon.isMandateBound(pid), "REVOKE FAILED: mandate still enabled after revoke");
        ++revokeDone;
    }

    /// @notice The I-1 replay property under a REVOKE: bind (nonce N-1 → N), revoke, then re-submit the bind
    ///         signature committed to the now-stale nonce N-1. The engine never reset `enableNonce` on revoke,
    ///         so the recomputed digest is at the advanced nonce and the stale signature MUST be rejected — a
    ///         revoked mandate can never be re-enabled by replaying an OLD enable signature.
    function revokeThenReplayStaleBind(uint256 seed) external {
        uint256 slot = bound(seed, 0, POOL - 1);
        Mandate memory s = _mandate(slot);
        MandateId pid = IdLib.toMandateId(s);

        // Ensure at least one prior bind exists (advances the ghost), capturing the now-stale nonce.
        if (ghostEnableNonce[pid] == 0) _doBind(slot);
        uint256 staleNonce = ghostEnableNonce[pid] - 1;

        // Revoke the live mandate (does NOT touch the enable nonce).
        _doRevoke(pid);
        require(!daimon.isMandateBound(pid), "REVOKE FAILED: mandate still enabled after revoke");

        // Replay the bind signed at the stale (pre-revoke) nonce — MUST revert UnauthorizedBind.
        uint256 execNonce = _freshBindNonce();
        (bytes32 mode, bytes memory ed) = _benignExec();
        bytes memory sig = _bindSig(s, pid, staleNonce, _execDigest(mode, ed, execNonce));

        vm.prank(RELAYER);
        try daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig) {
            revert("REVOKE REPLAY ALLOWED: a pre-revoke bind signature re-enabled the mandate");
        } catch (bytes memory err) {
            require(
                keccak256(err)
                    == keccak256(
                        abi.encodeWithSelector(IMandateEngine.UnauthorizedBind.selector, pid)
                    ),
                "revoke-replay rejected for the WRONG reason (not UnauthorizedBind)"
            );
            // The mandate stays revoked (the stale-sig rebind was rejected).
            require(
                !daimon.isMandateBound(pid), "mandate re-enabled despite the rejected stale bind"
            );
            ++revokeReplayRejected;
        }
    }

    /*·:⛧:·──────── INTERNAL ────────:⛧:·*/

    /// @dev ROOT-signed `revokeMandate(pid)` self-call over a fresh exec nonce (must succeed).
    function _doRevoke(MandateId pid) internal {
        uint256 execNonce = _freshBindNonce();
        bytes32 mode = MODE_SINGLE;
        bytes memory ed = abi.encodePacked(
            address(daimon), uint256(0), abi.encodeWithSelector(IDaimon.revokeMandate.selector, pid)
        );
        bytes memory sig = _rootSig(_execDigest(mode, ed, execNonce));

        vm.prank(RELAYER);
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
        _markConsumed(execNonce);
    }

    function _doBind(uint256 slot) internal {
        Mandate memory s = _mandate(slot);
        MandateId pid = IdLib.toMandateId(s);
        uint256 nonce = ghostEnableNonce[pid]; // mirrors the on-chain current nonce
        uint256 execNonce = _freshBindNonce();
        (bytes32 mode, bytes memory ed) = _benignExec();
        bytes memory sig = _bindSig(s, pid, nonce, _execDigest(mode, ed, execNonce));

        vm.prank(RELAYER);
        // correct nonce + benign exec ⇒ must succeed
        daimon.executeWithSig(mode, ed, execNonce, type(uint256).max, sig);
        ++ghostEnableNonce[pid];
        _markConsumed(execNonce);
        ++bindDone;
    }

    function _markConsumed(uint256 nonce) private {
        if (!ghostExecUsed[nonce]) {
            ghostExecUsed[nonce] = true;
            consumed.push(nonce);
        }
    }

    function _freshBindNonce() private returns (uint256) {
        return BIND_NONCE_BASE + (bindNonceCounter++);
    }

    /// @dev A mandate whose only action is an allow-all (SudoSigil) fallback, so the benign sink execution is
    ///      always permitted; salted per slot for a distinct MandateId.
    function _mandate(uint256 slot) internal view returns (Mandate memory s) {
        ActionSigilData[] memory fb = new ActionSigilData[](1);
        fb[0] = ActionSigilData({ sigil: sudo, initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: FALLBACK_TARGET_FLAG, selector: bytes4(0), sigils: fb });
        s = Mandate({
            sessionValidator: ISessionValidator(sessionValidator),
            sessionValidatorInitData: abi.encode(agent),
            salt: bytes32(slot),
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @dev A single benign call: `sink`, value 0, arbitrary calldata the sink accepts.
    function _benignExec() private view returns (bytes32 mode, bytes memory ed) {
        mode = MODE_SINGLE;
        ed = abi.encodePacked(sink, uint256(0), bytes4(0xdeadbeef));
    }

    function _execDigest(
        bytes32 mode,
        bytes memory ed,
        uint256 nonce
    )
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                HashLib.execStructHash(mode, ed, nonce, type(uint256).max)
            )
        );
    }

    function _bindDigest(
        MandateId pid,
        Mandate memory s,
        uint256 nonce
    )
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, HashLib.bindStructHash(pid, s, nonce))
        );
    }

    /// @dev ROOT-mode exec signature: `[0x00][20-byte validator][r,s,v]`.
    function _rootSig(bytes32 digest) private view returns (bytes memory) {
        return abi.encodePacked(bytes1(MODE_ROOT), bytes20(root1), _sign(rootPk, digest));
    }

    /// @dev SESSION BIND-mode signature: `[0x01][0x01][abi.encode(MandateBinding, sessionKeySig)]`. ROOT signs
    ///      the bind digest at `bindNonce`; the session key signs the exec `digest`.
    function _bindSig(
        Mandate memory s,
        MandateId pid,
        uint256 bindNonce,
        bytes32 digest
    )
        private
        view
        returns (bytes memory)
    {
        bytes memory rootSig = _sign(rootPk, _bindDigest(pid, s, bindNonce));
        MandateBinding memory en =
            MandateBinding({ session: s, rootValidator: root1, rootSignature: rootSig });
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(MODE_MANDATE), bytes1(SUBMODE_BIND), abi.encode(en, keySig));
    }

    function _sign(uint256 pk, bytes32 hash) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }
}
