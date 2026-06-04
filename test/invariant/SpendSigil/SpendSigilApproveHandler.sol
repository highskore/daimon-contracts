// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

// Contracts
import { SpendSigil, Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Mocks
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title SpendSigilApproveHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the {SpendSigil}'s approval-safety guards (the part the rolling-cap suite
///         does not cover): every approve the execution grants on the budgeted token is metered AND must net to
///         zero by post-check, and the blanket-grant primitives are blocked outright. Actions:
///           - {approveAndReset}: `approve(spender, A)` + `approve(spender, 0)` in one batch — charged `A`, but
///             the allowance is reset, so the dangling scan passes (accepted iff within cap).
///           - {approveDangling}: a single `approve(spender, A>0)` with NO reset — MUST revert
///             ({DanglingAllowance} within cap, {SpendCapExceeded} over cap).
///           - {blanketGrant}: `setApprovalForAll` / `permit` / `authorizeOperator` on the budgeted token — MUST
///             revert {BlanketGrantBlocked}.
///           - {permit2Grant}: a Permit2 `approve` of the budgeted token — MUST revert {Permit2GrantBlocked}.
/// @dev The handler is BOTH the multiplexer and the account (`msg.sender == account`), and is its own oracle:
///      each catch asserts the EXACT revert reason. The independent `(spent, lastUpdated)` ghost advances only on
///      an accepted {approveAndReset}; the reverting actions leave on-chain state (and the ghost) untouched.
contract SpendSigilApproveHandler is CommonBase, StdCheats, StdUtils {
    SpendSigil internal immutable sigil;
    MockERC20 internal immutable token;
    ConfigId internal immutable cid;
    address internal immutable account;
    uint256 internal immutable cap;
    Period internal immutable period;
    uint256 internal immutable maxWarp;

    /// @dev The approve-spender named by every grant (its dangling allowance is what the scan checks).
    address private constant SPENDER = address(0x5E9de4);
    /// @dev A stand-in Permit2 contract address (the Permit2-approve target; its code is irrelevant — the sigil
    ///      blocks on the selector + token arg, never calling it).
    address private constant PERMIT2 = address(0x9E207);

    bytes4 private constant APPROVE = 0x095ea7b3;
    bytes4 private constant SET_APPROVAL_FOR_ALL = 0xa22cb465;
    bytes4 private constant PERMIT = 0xd505accf;
    bytes4 private constant AUTHORIZE_OPERATOR = 0x959b8c3f;
    bytes4 private constant PERMIT2_APPROVE = 0x87517c45;
    bytes32 private constant MODE_SINGLE = bytes32(0);
    bytes32 private constant MODE_BATCH = bytes32(uint256(1) << 248);

    /// @dev One ERC-7579 batch entry (matches solady `LibERC7579`'s `abi.encode(Call[])` layout).
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    // ── ghost mirror of the on-chain (spent, lastUpdated); advances only on an accepted approveAndReset ──
    uint256 public ghostSpent;
    uint256 public ghostLastUpdated;

    // ── coverage telemetry: asserted > 0 in afterInvariant ──
    uint256 public approveResetAccepted;
    uint256 public rejectedOverCap;
    uint256 public danglingRejected;
    uint256 public blanketRejected;
    uint256 public permit2Rejected;
    uint256 public warps;

    constructor(
        SpendSigil _sigil,
        MockERC20 _token,
        ConfigId _cid,
        uint256 _cap,
        Period _period,
        uint256 _maxWarp
    ) {
        sigil = _sigil;
        token = _token;
        cid = _cid;
        cap = _cap;
        period = _period;
        maxWarp = _maxWarp;
        account = address(this); // multiplexer == account == this handler
    }

    /// @notice Grant then reset an allowance in one batch: charged the grant amount, but reset to zero so the
    ///         dangling scan passes (accepted iff within cap).
    /// @param amount The fuzzed grant amount (bounded to straddle under / at / over the cap).
    function approveAndReset(uint256 amount) external {
        amount = bound(amount, 0, cap * 2);
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(token), 0, abi.encodeWithSelector(APPROVE, SPENDER, amount));
        calls[1] = Call(address(token), 0, abi.encodeWithSelector(APPROVE, SPENDER, uint256(0)));
        bytes memory ed = abi.encode(calls);

        // `effective` rolls the window like _accrue; this suite asserts approval safety, not the rollover count.
        uint256 windowStart = sigil.startOfPeriod(period, block.timestamp);
        uint256 effective = ghostLastUpdated < windowStart ? 0 : ghostSpent;
        uint256 predicted = effective + amount;

        sigil.preCheck(cid, account);
        uint256 snap = vm.snapshotState();
        token.approve(SPENDER, amount);
        token.approve(SPENDER, 0);
        try sigil.postCheck(cid, account, MODE_BATCH, ed) {
            require(predicted <= cap, "CAP BYPASSED: approveAndReset accepted an over-cap charge");
            ghostSpent = predicted;
            ghostLastUpdated = block.timestamp;
            ++approveResetAccepted;
        } catch (bytes memory err) {
            vm.revertToState(snap);
            require(
                predicted > cap, "SPURIOUS REVERT: approveAndReset rejected a within-cap charge"
            );
            require(
                keccak256(err)
                    == keccak256(
                        abi.encodeWithSelector(
                            SpendSigil.SpendCapExceeded.selector, cid, predicted, cap
                        )
                    ),
                "approveAndReset over-cap rejected for the WRONG reason"
            );
            ++rejectedOverCap;
        }
    }

    /// @notice A single non-reset `approve(spender, A>0)` — MUST revert: {DanglingAllowance} within cap, or
    ///         {SpendCapExceeded} when the metered grant itself is over cap.
    /// @param amount The fuzzed grant amount (always > 0, so the allowance always dangles).
    function approveDangling(uint256 amount) external {
        amount = bound(amount, 1, cap * 2);
        bytes memory ed = abi.encodePacked(
            address(token), uint256(0), abi.encodeWithSelector(APPROVE, SPENDER, amount)
        );

        uint256 windowStart = sigil.startOfPeriod(period, block.timestamp);
        uint256 effective = ghostLastUpdated < windowStart ? 0 : ghostSpent;
        uint256 predicted = effective + amount;

        sigil.preCheck(cid, account);
        uint256 snap = vm.snapshotState();
        token.approve(SPENDER, amount);
        try sigil.postCheck(cid, account, MODE_SINGLE, ed) {
            revert("DANGLING ALLOWED: a non-reset approve passed postCheck");
        } catch (bytes memory err) {
            vm.revertToState(snap); // undo the real approve so no allowance dangles into the next action
            bytes memory expected = predicted > cap
                ? abi.encodeWithSelector(SpendSigil.SpendCapExceeded.selector, cid, predicted, cap)
                : abi.encodeWithSelector(
                    SpendSigil.DanglingAllowance.selector, cid, SPENDER, amount
                );
            require(keccak256(err) == keccak256(expected), "dangling rejected for the WRONG reason");
            ++danglingRejected;
        }
    }

    /// @notice A blanket-grant primitive on the budgeted token — MUST revert {BlanketGrantBlocked}.
    /// @param seed Selects which primitive (setApprovalForAll / permit / authorizeOperator).
    function blanketGrant(uint256 seed) external {
        bytes4[3] memory sels = [SET_APPROVAL_FOR_ALL, PERMIT, AUTHORIZE_OPERATOR];
        bytes4 sel = sels[bound(seed, 0, 2)];
        bytes memory inner;
        if (sel == SET_APPROVAL_FOR_ALL) {
            inner = abi.encodeWithSelector(sel, SPENDER, true);
        } else if (sel == AUTHORIZE_OPERATOR) {
            inner = abi.encodeWithSelector(sel, SPENDER);
        } else {
            inner = abi.encodeWithSelector(
                sel, account, SPENDER, uint256(1), uint256(0), uint8(0), bytes32(0), bytes32(0)
            );
        }
        bytes memory ed = abi.encodePacked(address(token), uint256(0), inner);

        sigil.preCheck(cid, account);
        try sigil.postCheck(cid, account, MODE_SINGLE, ed) {
            revert("BLANKET ALLOWED: a blanket grant passed postCheck");
        } catch (bytes memory err) {
            require(
                keccak256(err)
                    == keccak256(abi.encodeWithSelector(SpendSigil.BlanketGrantBlocked.selector)),
                "blanket grant rejected for the WRONG reason"
            );
            ++blanketRejected;
        }
    }

    /// @notice A Permit2 `approve` of the budgeted token — MUST revert {Permit2GrantBlocked} (the allowance
    ///         would live inside Permit2, invisible to the post-check's dangling scan).
    /// @param amount The fuzzed grant amount (irrelevant to the block, which is on the token + selector).
    function permit2Grant(uint256 amount) external {
        amount = bound(amount, 0, cap * 2);
        bytes memory inner = abi.encodeWithSelector(
            PERMIT2_APPROVE, address(token), SPENDER, uint160(amount), uint48(0)
        );
        bytes memory ed = abi.encodePacked(PERMIT2, uint256(0), inner);

        sigil.preCheck(cid, account);
        try sigil.postCheck(cid, account, MODE_SINGLE, ed) {
            revert("PERMIT2 ALLOWED: a Permit2 grant of the budgeted token passed");
        } catch (bytes memory err) {
            require(
                keccak256(err)
                    == keccak256(abi.encodeWithSelector(SpendSigil.Permit2GrantBlocked.selector)),
                "Permit2 grant rejected for the WRONG reason"
            );
            ++permit2Rejected;
        }
    }

    /// @notice Advance the clock so the rolling window can roll over between charges.
    /// @param secs The fuzzed advance (bounded by `maxWarp`).
    function warp(uint256 secs) external {
        secs = bound(secs, 1, maxWarp);
        vm.warp(block.timestamp + secs);
        ++warps;
    }
}
