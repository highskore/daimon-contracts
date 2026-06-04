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

/// @title SpendSigilHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the {SpendSigil} rolling-cap invariants. Three bounded, guided actions
///         drive the REAL preCheck→postCheck accrual — a charge metered from the parsed `transfer` calldata
///         ({spend}), a charge metered from the REAL balance delta ({spendViaBalance}, exercising the
///         `max(byCalldata, delta)` backstop), and a clock warp ({warp}) — while an INDEPENDENT ghost mirrors
///         the on-chain `(spent, lastUpdated)` and branch counters record that the fuzz actually reached the
///         interesting states (both meter paths, an over-cap rejection, a window rollover).
/// @dev The handler is itself an oracle: a charge the ghost predicts is within cap MUST be accepted, and one it
///      predicts is over cap MUST revert — any disagreement reverts the handler ("CAP BYPASSED" / "SPURIOUS
///      REVERT"), failing the run independently of the top-level invariants. The handler is BOTH the multiplexer
///      and the account (matching the engine's runtime where `msg.sender == account`).
///      DELEGATED CORRECTNESS: the ghost reuses `sigil.startOfPeriod(...)` for the window boundary rather than
///      re-implementing the calendar math — that pure function's correctness is owned by its own unit suite
///      (`test/unit/SpendSigil/startOfPeriod`), so do not delete that suite thinking it is redundant.
contract SpendSigilHandler is CommonBase, StdCheats, StdUtils {
    SpendSigil internal immutable sigil;
    MockERC20 internal immutable token;
    ConfigId internal immutable cid;
    address internal immutable account;
    uint256 internal immutable cap;
    Period internal immutable period;
    uint256 internal immutable maxWarp; // upper bound on a single {warp}, sized to straddle the period boundary

    /// @dev ERC-20 `transfer(address,uint256)`.
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;
    /// @dev The transfer recipient — any address other than the metered account.
    address private constant SINK = address(0x5121);

    // ── ghost mirror of the on-chain (spent, lastUpdated) after each successful accrue ──
    uint256 public ghostSpent;
    uint256 public ghostLastUpdated;

    // ── coverage telemetry: asserted > 0 in afterInvariant so a no-op fuzz run fails loudly ──
    uint256 public successfulSpends;
    uint256 public rejectedOverCap;
    uint256 public rollovers;
    uint256 public warps;
    uint256 public calldataSpends; // metered via the parsed calldata sum
    uint256 public deltaSpends; // metered via the real balance-delta backstop

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

    /// @notice Charge metered from the PARSED `transfer` calldata (no real token moves → balance delta 0), so
    ///         the calldata-sum branch of `max(byCalldata, delta)` dominates.
    /// @param amount The fuzzed charge amount (bounded to straddle under / at / over the cap).
    function spend(uint256 amount) external {
        amount = bound(amount, 0, cap * 2);
        bytes memory ed = abi.encodePacked(
            address(token), uint256(0), abi.encodeWithSelector(TRANSFER_SELECTOR, SINK, amount)
        );
        if (_charge(amount, ed, false)) ++calldataSpends;
    }

    /// @notice Charge metered from the REAL balance delta: tokens leave the account via a path the itemizer does
    ///         NOT parse (a bare call to a non-token target), so `byCalldata == 0` and the outflow is the
    ///         balance delta — exercising the `max(...)` backstop the calldata path never reaches.
    /// @param amount The fuzzed charge amount (bounded to straddle under / at / over the cap).
    function spendViaBalance(uint256 amount) external {
        amount = bound(amount, 0, cap * 2);
        // A single call to SINK with empty data: not a budgeted-token transfer, so the itemizer sums 0.
        bytes memory ed = abi.encodePacked(SINK, uint256(0), bytes(""));
        if (_charge(amount, ed, true)) ++deltaSpends;
    }

    /// @notice Advance the clock so the rolling window can roll over between charges.
    /// @param secs The fuzzed advance (bounded by `maxWarp`, sized to straddle the configured period boundary).
    function warp(uint256 secs) external {
        secs = bound(secs, 1, maxWarp);
        vm.warp(block.timestamp + secs);
        ++warps;
    }

    /// @dev Drive one preCheck→(optional real move)→postCheck bracket and reconcile against the ghost. When
    ///      `realMove` is set the outflow is a genuine `token.transfer`, kept atomic with postCheck via a
    ///      state snapshot (an over-cap reject rolls the transfer back, exactly as the engine's bracket would).
    /// @return success Whether the charge was accepted (so the caller can tally the metered path).
    function _charge(uint256 amount, bytes memory ed, bool realMove)
        private
        returns (bool success)
    {
        // Independent ghost prediction: mirror _accrue's "roll the window, then add", using the CONTRACT's own
        // period math (startOfPeriod) so the ghost never re-implements the month/year boundary logic. The
        // `!= 0` guard on `rolled` only affects the rollover COUNTER (a first charge is not a rollover); the
        // `effective` reset deliberately omits it because `ghostSpent` is 0 then anyway.
        uint256 windowStart = sigil.startOfPeriod(period, block.timestamp);
        bool rolled = ghostLastUpdated != 0 && ghostLastUpdated < windowStart;
        uint256 effective = ghostLastUpdated < windowStart ? 0 : ghostSpent;
        uint256 predicted = effective + amount;

        sigil.preCheck(cid, account);
        uint256 snap = vm.snapshotState();
        if (realMove && amount != 0) token.transfer(SINK, amount);
        try sigil.postCheck(cid, account, bytes32(0), ed) {
            require(predicted <= cap, "CAP BYPASSED: postCheck accepted an over-cap charge");
            ghostSpent = predicted;
            ghostLastUpdated = block.timestamp;
            ++successfulSpends;
            if (rolled) ++rollovers;
            return true;
        } catch {
            vm.revertToState(snap); // undo the real transfer so a reject leaves no net outflow
            require(predicted > cap, "SPURIOUS REVERT: postCheck rejected a within-cap charge");
            ++rejectedOverCap;
            return false;
        }
    }
}
