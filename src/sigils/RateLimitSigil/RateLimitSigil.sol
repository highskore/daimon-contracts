// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import {
    IActionSigil,
    ISigilBase,
    IERC165,
    ConfigId,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "@interfaces/ISigil.sol";

// Libraries
import {
    RateLimitConfigLib,
    RateLimitConfig,
    RateLimitState
} from "@sigils/RateLimitSigil/lib/RateLimitConfigLib.sol";

// forgefmt: disable-start
/// ______       _       _     _           _ _   ______ _       _ _
/// | ___ \     | |     | |   (_)         (_) | | ___ \ |     (_) |
/// | |_/ /__ _ | |_ ___| |    _ _ __ ___  _| |_| |_/ / |__   _ _| |
/// |    // _` || __/ _ \ |   | | '_ ` _ \| | __|    /| '_ \ | | | |
/// | |\ \ (_| || ||  __/ |___| | | | | | | | |_| |\ \| | | |/ /| |
/// \_| \_\__,_(_)__\___\_____/_|_| |_| |_|_|\__\_| \_|_| |_/___|_|
///
///   checkAction ─ roll window if now ≥ windowStart + windowSeconds (count=0, windowStart=now)
///               ─ permit iff count < maxActions AND (cooldown==0 || now − lastActionAt ≥ cooldown)
///               ─ on pass: ++count, lastActionAt = now           ·  on fail: NO state mutation
// forgefmt: disable-end
/// @title RateLimitSigil — a stateful action-FREQUENCY cap (per-call action guard)
/// @author highskore.eth
/// @notice An {IActionSigil} that bounds how OFTEN a guarded action may fire — at most `maxActions` per rolling
///         `windowSeconds`, plus an optional `minCooldownSeconds` minimum gap between consecutive actions. It
///         fills the gap the value caps ({SpendSigil}, {NativeValueLimitSigil}) leave open: a looping or
///         compromised agent that stays UNDER the value cap but fires unbounded actions (burning gas, churning
///         positions, repeatedly hitting a slippage edge) is unbounded by a value cap but bounded here. Compose
///         it alongside the value/arg sigils to add a frequency bound — e.g.
///         `[OmniSigil(...) + RateLimitSigil(maxActions, windowSeconds, cooldown)]`.
/// @dev Action-tier is correct here (unlike {SpendSigil}, whose VALUE cap had to be the outcome tier so value
///      can't leak via approvals/indirect transfers): action COUNT is inherently per-call, so {checkAction}
///      observes it directly. Each permitted action mutates the rolling {RateLimitState} — {checkAction} is the
///      state-changing per-call hook the engine runs inline in the `executeWithSig` path, so persisting the
///      counter here is sound, exactly as {OmniSigil}'s cumulative `usage.used` counter writes.
///
///      WINDOW SEMANTICS (documented honestly): this is a FIXED / TUMBLING window anchored at the FIRST action
///      in each window — NOT a true sliding window. After the first action at `t0`, the window is
///      `[t0, t0 + windowSeconds)`; the first action AT OR AFTER `t0 + windowSeconds` opens a fresh window
///      (`count` reset to 0, `windowStart` re-anchored to `now`). The cost: up to `2·maxActions` actions can
///      occur across a single `windowSeconds`-length span that straddles a boundary (the tail of one window plus
///      the head of the next). A true sliding window would require unbounded per-action timestamp storage, which
///      is out of scope; this mirrors {SpendSigil}'s reset-on-rollover model. The `minCooldownSeconds` gap is the
///      complementary control that smooths bursts WITHIN a window.
///
///      Fail-closed default: an unconfigured entry has `windowSeconds == 0` (never initialized), so {checkAction}
///      reverts {PolicyNotInitialized} for it — an action is denied until a real config is bound. A rejected action
///      does NOT mutate state (it is not counted), so probing the limit can't burn the budget.
///
///      Like every action sigil it keys config + state by `(configId, msg.sender, account)`. This is a PURE
///      action sigil: it has no ERC-1271 tier (a signature carries no notion of an executed action, so a
///      frequency cap cannot constrain signing) and no outcome tier; it advertises ONLY the action tier via
///      ERC-165, so the engine's per-tier bind guard reverts {MandateEngine.UnsupportedSigil} if it is placed in
///      a signature or outcome slot of a mandate.
contract RateLimitSigil is IActionSigil {
    using RateLimitConfigLib for ConfigId;

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice The configured rate limit for `(id, multiplexer, account)`. Mirrors a public-mapping getter over
    ///         the {RateLimitConfig} struct.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the account/engine).
    /// @param account The guarded account.
    /// @return maxActions The max actions permitted per rolling window.
    /// @return windowSeconds The rolling window length (seconds) the count resets on.
    /// @return minCooldownSeconds The minimum seconds between consecutive actions (`0` = no cooldown).
    function configs(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint32 maxActions, uint32 windowSeconds, uint32 minCooldownSeconds)
    {
        RateLimitConfig storage cfg = id.getConfig(multiplexer, account);
        return (cfg.maxActions, cfg.windowSeconds, cfg.minCooldownSeconds);
    }

    /// @notice The rolling rate state for `(id, multiplexer, account)`. Mirrors a public-mapping getter over the
    ///         {RateLimitState} struct.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the account/engine).
    /// @param account The guarded account.
    /// @return windowStart The unix-seconds anchor of the current window.
    /// @return count The actions charged within the current window.
    /// @return lastActionAt The unix-seconds timestamp of the last permitted action.
    function states(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint32 windowStart, uint32 count, uint32 lastActionAt)
    {
        RateLimitState storage st = id.getState(multiplexer, account);
        return (st.windowStart, st.count, st.lastActionAt);
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
    /// @dev Decodes + stores a {RateLimitConfig}, rejecting `maxActions == 0` ({InvalidMaxActions}) or
    ///      `windowSeconds == 0` ({InvalidWindow}). Emits {SigilSet}. Does NOT reset the rolling state.
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
    {
        configId.initialize(msg.sender, account, initData);
        emit ISigilBase.SigilSet(configId, msg.sender, account);
    }

    /*·:⛧:·──────── CHECK ────────:⛧:·*/

    /// @inheritdoc IActionSigil
    /// @dev Permits iff, after rolling the window when `now ≥ windowStart + windowSeconds`, the running
    ///      `count < maxActions` AND (no cooldown, or `now − lastActionAt ≥ minCooldownSeconds`). On a pass it
    ///      charges the action (`++count`, `lastActionAt = now`) and returns {VALIDATION_SUCCESS}; on a reject it
    ///      returns {VALIDATION_FAILED} WITHOUT mutating state (a denied action is not counted). Reads neither
    ///      `target`, `value`, nor `data` — only the action's OCCURRENCE matters to a frequency cap. Reverts
    ///      {PolicyNotInitialized} for an unconfigured `(id, msg.sender, account)` (fail closed).
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256,
        bytes calldata
    )
        external
        returns (uint256)
    {
        RateLimitConfig storage cfg = id.getConfig(msg.sender, account);
        // Reject if the sigil was never configured for this (id, multiplexer, account) — windowSeconds is the
        // never-initialized marker (initialize rejects a zero window, so a real config always has one).
        if (cfg.windowSeconds == 0) revert PolicyNotInitialized(id, msg.sender, account);

        uint32 nowTs = uint32(block.timestamp);
        RateLimitState storage st = id.getState(msg.sender, account);

        // Roll the window when the current one has fully elapsed: the count resets and the window re-anchors to
        // now. A FIXED window (anchored at the first action), reset-on-rollover — see the contract @dev. The
        // `count == 0` guard treats the never-charged state (windowStart == 0) as already-rolled so the first
        // action opens a window at `now` rather than at the unix epoch.
        uint32 windowStart = st.windowStart;
        uint32 count = st.count;
        // `count != 0` guarantees `windowStart` is a prior `nowTs` (`<= nowTs`), so `nowTs - windowStart` cannot
        // underflow; written as a subtraction (not `windowStart + windowSeconds`) so a near-uint32-max window can
        // never overflow and brick the action. The `count == 0` branch treats the never-charged state
        // (windowStart == 0) as already-rolled, opening the first window at `now` rather than at the unix epoch.
        if (count == 0 || nowTs - windowStart >= cfg.windowSeconds) {
            windowStart = nowTs;
            count = 0;
        }

        // Per-window count cap.
        if (count >= cfg.maxActions) return VALIDATION_FAILED;
        // Minimum gap between consecutive actions. Skipped when disabled, and the explicit `lastActionAt != 0`
        // guard makes the first-ever action unconditionally exempt (no reliance on `nowTs` dwarfing the cooldown);
        // `lastActionAt` is then always a prior `nowTs`, so the subtraction cannot underflow.
        if (
            cfg.minCooldownSeconds != 0 && st.lastActionAt != 0
                && nowTs - st.lastActionAt < cfg.minCooldownSeconds
        ) {
            return VALIDATION_FAILED;
        }

        // Charge the permitted action: advance the window anchor (if rolled), bump the count, stamp the time.
        st.windowStart = windowStart;
        st.count = count + 1;
        st.lastActionAt = nowTs;
        return VALIDATION_SUCCESS;
    }

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the action tier only: {IERC165}, {ISigilBase}, {IActionSigil}. Placed in the signature or
    ///      outcome tier of a mandate it would fail the engine's per-tier bind guard ({UnsupportedSigil}).
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IActionSigil).interfaceId;
    }
}
