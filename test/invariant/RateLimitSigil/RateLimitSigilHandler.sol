// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

// Contracts
import { RateLimitSigil } from "@sigils/RateLimitSigil/RateLimitSigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title RateLimitSigilHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the {RateLimitSigil} rolling-frequency invariants. Five bounded, guided
///         actions drive the REAL checkAction state machine — an action at the CURRENT time ({actNow}, which
///         reaches the count cap and the too-soon cooldown reject), an action exactly `cooldown` later
///         ({actAfterCooldown}, which reliably ACCUMULATES the count toward the cap so the over-cap branch is
///         always reached), an action a full window later ({actNextWindow}, which forces a rollover), and a free
///         clock warp ({warp}) — while an INDEPENDENT ghost mirrors the on-chain `(windowStart, count,
///         lastActionAt)` and branch counters record that the fuzz actually reached every interesting state.
/// @dev The handler is itself an oracle: a decision the ghost predicts (permit / reject) MUST match the
///      contract's, or the handler reverts ("RATE BYPASSED"), failing the run independently of the top-level
///      invariants. Splitting the action into the four guided drivers (rather than one random act) makes the
///      over-cap / cooldown / rollover coverage dims hit RELIABLY (not seed-flaky) while the random {warp}
///      still injects arbitrary interleavings. The handler is BOTH the multiplexer and the account (matching
///      the engine's runtime where `msg.sender == account`). The ghost re-implements the SAME fixed-window +
///      cooldown logic the SUT uses — deliberately, so a divergence (a deleted reset, an off-by-one cap) is caught.
contract RateLimitSigilHandler is CommonBase, StdCheats, StdUtils {
    RateLimitSigil internal immutable sigil;
    ConfigId internal immutable cid;
    address internal immutable account;
    uint32 internal immutable maxActions;
    uint32 internal immutable windowSeconds;
    uint32 internal immutable cooldown;
    uint256 internal immutable maxWarp; // upper bound on a single {warp}, sized to straddle the window boundary

    // ── ghost mirror of the on-chain (windowStart, count, lastActionAt) ──
    uint32 public ghostWindowStart;
    uint32 public ghostCount;
    uint32 public ghostLastActionAt;
    bool internal ghostEverActed;

    // ── coverage telemetry: asserted > 0 in afterInvariant so a no-op fuzz run fails loudly ──
    uint256 public successfulActs;
    uint256 public rejectedOverCap;
    uint256 public rejectedCooldown;
    uint256 public rollovers;
    uint256 public warps;

    constructor(
        RateLimitSigil _sigil,
        ConfigId _cid,
        uint32 _maxActions,
        uint32 _windowSeconds,
        uint32 _cooldown,
        uint256 _maxWarp
    ) {
        sigil = _sigil;
        cid = _cid;
        maxActions = _maxActions;
        windowSeconds = _windowSeconds;
        cooldown = _cooldown;
        maxWarp = _maxWarp;
        account = address(this); // multiplexer == account == this handler
    }

    /// @notice Attempt one action at the CURRENT timestamp — reaches the count cap (consecutive within a window)
    ///         and the too-soon cooldown reject (when called right after another action).
    function actNow() external {
        _attempt();
    }

    /// @notice Advance exactly `cooldown` seconds, then act — so the cooldown never blocks and the count
    ///         RELIABLY accumulates toward `maxActions`, guaranteeing the over-cap branch is reached.
    function actAfterCooldown() external {
        if (cooldown != 0) vm.warp(block.timestamp + cooldown);
        _attempt();
    }

    /// @notice Advance a full window, then act — forcing a rollover (count reset) on the next attempt.
    function actNextWindow() external {
        vm.warp(block.timestamp + windowSeconds);
        _attempt();
    }

    /// @notice Deterministically exercise the cooldown reject: roll to a fresh window so the count is below the
    ///         cap, take ONE permitted action, then attempt a SECOND at the SAME timestamp (gap 0 < cooldown).
    ///         With a non-zero cooldown the second attempt is necessarily a cooldown reject (not an over-cap one,
    ///         since the count is 1 < maxActions) — so that branch is reached on EVERY call. A no-op when the
    ///         instance has no cooldown.
    function actWithinCooldown() external {
        if (cooldown == 0) return;
        vm.warp(block.timestamp + windowSeconds + 1); // fresh window: count starts at 0
        _attempt(); // permitted → count 1
        _attempt(); // same timestamp, gap 0 < cooldown, count 1 < cap → cooldown reject
    }

    /// @notice Deterministically fill the current window to the cap and then exceed it: roll to a fresh window,
    ///         then attempt `maxActions + 1` actions, each `cooldown` apart so the cooldown never blocks. The
    ///         final attempt is necessarily an over-cap reject — so the over-cap branch is reached on EVERY call,
    ///         making that coverage dim reliable rather than seed-dependent.
    function fillToCapAndExceed() external {
        // Open a guaranteed-fresh window so the cap is full from a known floor (the `+ 1` keeps the cooldown
        // from coinciding with the just-elapsed boundary on the first attempt).
        vm.warp(block.timestamp + windowSeconds + 1);
        uint32 gap = cooldown == 0 ? 1 : cooldown;
        for (uint256 i; i <= maxActions; ++i) {
            if (i != 0) vm.warp(block.timestamp + gap);
            _attempt();
        }
    }

    /// @notice Advance the clock by a free fuzzed amount, injecting arbitrary interleavings between actions.
    /// @param secs The fuzzed advance (bounded by `maxWarp`, sized to straddle the window/cooldown boundaries).
    function warp(uint256 secs) external {
        secs = bound(secs, 1, maxWarp);
        vm.warp(block.timestamp + secs);
        ++warps;
    }

    /// @dev Run one checkAction and reconcile the contract's verdict against the independent ghost (which mirrors
    ///      the SAME fixed-window + cooldown logic). A permit commits the ghost to the new state; a reject must
    ///      leave both the contract AND the ghost untouched.
    function _attempt() private {
        uint32 nowTs = uint32(block.timestamp);

        // Independent ghost prediction: mirror checkAction's "roll the window, then gate on count + cooldown".
        uint32 windowStart = ghostWindowStart;
        uint32 count = ghostCount;
        // Subtraction form (not `windowStart + windowSeconds`) to match the sigil's overflow-hardened rollover,
        // so the ghost can't itself overflow uint32 and mispredict at a near-max window.
        bool rolled = ghostEverActed && count != 0 && nowTs - windowStart >= windowSeconds;
        if (count == 0 || nowTs - windowStart >= windowSeconds) {
            windowStart = nowTs;
            count = 0;
        }
        bool overCap = count >= maxActions;
        // Mirror the sigil's first-action cooldown exemption (`lastActionAt != 0`), so a low start timestamp
        // can't make the ghost predict a reject the contract permits.
        bool cooledDown =
            cooldown == 0 || ghostLastActionAt == 0 || nowTs - ghostLastActionAt >= cooldown;
        bool predictPermit = !overCap && cooledDown;

        uint256 code = sigil.checkAction(cid, account, address(0xBEEF), 0, hex"");

        if (predictPermit) {
            require(
                code == VALIDATION_SUCCESS,
                "RATE BYPASSED: contract rejected an action the ghost permitted"
            );
            ghostWindowStart = windowStart;
            ghostCount = count + 1;
            ghostLastActionAt = nowTs;
            ghostEverActed = true;
            ++successfulActs;
            if (rolled) ++rollovers;
        } else {
            require(
                code != VALIDATION_SUCCESS,
                "RATE BYPASSED: contract permitted an action the ghost rejected"
            );
            // A reject must NOT mutate the contract's state — the ghost stays put too. The over-cap branch is
            // checked FIRST in the SUT, so attribute the reject the same way for accurate coverage telemetry.
            if (overCap) ++rejectedOverCap;
            else ++rejectedCooldown;
        }
    }
}
