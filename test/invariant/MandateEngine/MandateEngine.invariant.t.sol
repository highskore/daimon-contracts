// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";
import { LibClone } from "solady/utils/LibClone.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";
import { MockSink } from "@test/mock/MockSink.sol";

// Handlers
import { MandateEngineHandler } from "./MandateEngineHandler.sol";

// Types
import { Mandate, MandateId } from "@types/MandateTypes.sol";

/// @title MandateEngine Nonce-Replay Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the engine's two replay guards, driving the REAL account through the
///         direct-call (`executeWithSig`) path with real ROOT + session-key signatures:
///           (1) a burned direct-call nonce STAYS burned — a consumed `executeWithSig` nonce can never
///               re-execute (single-use);
///           (2) the per-mandate enable nonce is strictly monotone and equals an INDEPENDENT ghost — a bind
///               signature is single-use (a stale-nonce bind is rejected), AND a REVOKE never resets it, so a
///               bind signature committed BEFORE a revoke can never replay to re-enable the killed mandate.
/// @dev FALSIFICATION PROTOCOL (designed to FAIL on a broken SUT):
///        - Remove the `if (execNonceUsed[nonce]) revert ExecNonceUsed` guard in {Daimon.executeWithSig} →
///          the handler's "REPLAY ALLOWED" oracle trips (a consumed nonce re-executes).
///        - Drop `$.enableNonce[pid]++` in {MandateEngine._bindMandate} → after a successful bind the ghost
///          advances but the chain does not → {invariant_enableNonceMatchesGhost} trips (and the stale-bind
///          replay starts succeeding → handler "STALE BIND ALLOWED").
///        - Reset `$.enableNonce[pid] = 0` in {MandateEngine._revokeMandate} → the post-revoke stale bind
///          signature (at the old nonce) starts verifying again → handler "REVOKE REPLAY ALLOWED" trips and
///          {invariant_enableNonceMatchesGhost} diverges (the monotone ghost never resets).
contract MandateEngine_Invariant_Test is Test {
    Daimon internal daimon;
    MandateEngineHandler internal handler;

    function setUp() public {
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        ECDSAValidator root1 = new ECDSAValidator();
        ECDSASessionValidator sessionValidator = new ECDSASessionValidator();
        SudoSigil sudo = new SudoSigil();
        MockSink sink = new MockSink();

        (address rootSigner, uint256 rootPk) = makeAddrAndKey("root");
        (, uint256 agentPk) = makeAddrAndKey("agent");

        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);
        daimon.initialize(vs, ds, new Mandate[](0));

        handler = new MandateEngineHandler(
            daimon,
            address(root1),
            rootPk,
            agentPk,
            address(sessionValidator),
            address(sudo),
            address(sink)
        );

        targetContract(address(handler));
    }

    /// @notice SINGLE-USE: every direct-call nonce the ghost has seen burned is still burned on-chain — a
    ///         consumed `executeWithSig` nonce can never be un-burned (re-executed). Independent ghost vs. chain.
    function invariant_consumedExecNoncesStayBurned() public view {
        uint256 n = handler.consumedLength();
        for (uint256 i; i < n; ++i) {
            assertTrue(
                daimon.execNonceUsed(handler.consumed(i)), "a consumed exec nonce was un-burned"
            );
        }
    }

    /// @notice MONOTONE + REPLAY-SAFE: the on-chain per-mandate enable nonce equals the independent ghost (which
    ///         only ever increments on a successful bind), so a bind signature committed to a past nonce can
    ///         never replay.
    function invariant_enableNonceMatchesGhost() public view {
        uint256 n = handler.poolLength();
        for (uint256 i; i < n; ++i) {
            MandateId pid = handler.pidAt(i);
            assertEq(
                daimon.mandateEnableNonce(pid),
                handler.ghostEnableNonce(pid),
                "on-chain enable nonce diverged from the monotone ghost"
            );
        }
    }

    /// @notice COVERAGE: the fuzz actually reached every interesting branch.
    function afterInvariant() public view {
        assertGt(handler.execSucceeded(), 0, "no fresh direct-exec explored");
        assertGt(handler.execRejectedAsUsed(), 0, "exec-nonce replay rejection never exercised");
        assertGt(handler.bindDone(), 0, "no binds explored");
        assertGt(handler.bindRejectedStale(), 0, "stale-bind replay rejection never exercised");
        assertGt(handler.revokeDone(), 0, "no revokes explored");
        assertGt(
            handler.revokeReplayRejected(),
            0,
            "revoke -> stale-bind replay rejection never exercised"
        );
    }
}
