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

/// @title SpendSigilNativeHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the {SpendSigil} NATIVE (ETH) budget — the value-summed meter, where the
///         outflow is each call's `value` (there is no allowance/pull primitive for ETH) maxed with the native
///         balance delta. Two charge actions drive the REAL preCheck→postCheck accrual: {spendValue} declares a
///         call `value` with NO real ETH move (so the calldata `value`-sum dominates, delta 0), and
///         {spendValueReal} actually sends the ETH (so the native balance delta is exercised alongside the sum).
///         An independent ghost mirrors `(spent, lastUpdated)` and a {warp} rolls the window.
/// @dev Like the ERC-20 handler this is BOTH the multiplexer and the account (`msg.sender == account`), and is
///      its own oracle: a charge the ghost predicts within cap MUST be accepted, one over cap MUST revert
///      ("CAP BYPASSED" / "SPURIOUS REVERT"). The ghost reuses `sigil.startOfPeriod(...)` for the window
///      boundary (DELEGATED CORRECTNESS — owned by the startOfPeriod unit suite).
contract SpendSigilNativeHandler is CommonBase, StdCheats, StdUtils {
    SpendSigil internal immutable sigil;
    ConfigId internal immutable cid;
    address internal immutable account;
    uint256 internal immutable cap;
    Period internal immutable period;
    uint256 internal immutable maxWarp;

    /// @dev The native-value recipient — any address other than the metered account.
    address payable private constant SINK = payable(address(0x5121));

    // ── ghost mirror of the on-chain (spent, lastUpdated) after each successful accrue ──
    uint256 public ghostSpent;
    uint256 public ghostLastUpdated;

    // ── coverage telemetry: asserted > 0 in afterInvariant ──
    uint256 public successfulSpends;
    uint256 public rejectedOverCap;
    uint256 public rollovers;
    uint256 public warps;
    uint256 public valueSpends; // metered via the declared call value (no real move)
    uint256 public realMoveSpends; // metered with a real ETH outflow (delta exercised)

    constructor(SpendSigil _sigil, ConfigId _cid, uint256 _cap, Period _period, uint256 _maxWarp) {
        sigil = _sigil;
        cid = _cid;
        cap = _cap;
        period = _period;
        maxWarp = _maxWarp;
        account = address(this); // multiplexer == account == this handler
    }

    /// @dev The account must be able to receive ETH (the SINK refund on a reverted over-cap charge rolls back).
    receive() external payable { }

    /// @notice Charge metered from a DECLARED call `value` with no real ETH move, so the value-sum branch of
    ///         `max(valueSum, delta)` dominates (delta 0).
    /// @param amount The fuzzed charge amount (bounded to straddle under / at / over the cap).
    function spendValue(uint256 amount) external {
        amount = bound(amount, 0, cap * 2);
        bytes memory ed = abi.encodePacked(SINK, amount, bytes(""));
        if (_charge(amount, ed, false)) ++valueSpends;
    }

    /// @notice Charge with a REAL ETH outflow of `amount`, so the native balance delta is exercised alongside
    ///         the declared `value` sum (they agree, as they must in the real EVM).
    /// @param amount The fuzzed charge amount (bounded to straddle under / at / over the cap).
    function spendValueReal(uint256 amount) external {
        amount = bound(amount, 0, cap * 2);
        bytes memory ed = abi.encodePacked(SINK, amount, bytes(""));
        if (_charge(amount, ed, true)) ++realMoveSpends;
    }

    /// @notice Advance the clock so the rolling window can roll over between charges.
    /// @param secs The fuzzed advance (bounded by `maxWarp`, sized to straddle the configured period boundary).
    function warp(uint256 secs) external {
        secs = bound(secs, 1, maxWarp);
        vm.warp(block.timestamp + secs);
        ++warps;
    }

    /// @dev Drive one preCheck→(optional real ETH move)→postCheck bracket and reconcile against the ghost. A
    ///      real move is kept atomic with postCheck via a state snapshot, so an over-cap reject rolls the ETH
    ///      outflow back exactly as the engine's bracket would.
    /// @return success Whether the charge was accepted.
    function _charge(uint256 amount, bytes memory ed, bool realMove)
        private
        returns (bool success)
    {
        uint256 windowStart = sigil.startOfPeriod(period, block.timestamp);
        bool rolled = ghostLastUpdated != 0 && ghostLastUpdated < windowStart;
        uint256 effective = ghostLastUpdated < windowStart ? 0 : ghostSpent;
        uint256 predicted = effective + amount;

        sigil.preCheck(cid, account);
        uint256 snap = vm.snapshotState();
        if (realMove && amount != 0) {
            (bool ok,) = SINK.call{ value: amount }("");
            require(ok, "native sink transfer failed");
        }
        try sigil.postCheck(cid, account, bytes32(0), ed) {
            require(predicted <= cap, "CAP BYPASSED: postCheck accepted an over-cap native charge");
            ghostSpent = predicted;
            ghostLastUpdated = block.timestamp;
            ++successfulSpends;
            if (rolled) ++rollovers;
            return true;
        } catch {
            vm.revertToState(snap); // undo the real ETH move so a reject leaves no net outflow
            require(
                predicted > cap, "SPURIOUS REVERT: postCheck rejected a within-cap native charge"
            );
            ++rejectedOverCap;
            return false;
        }
    }
}
