// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import {
    IActionSigil,
    I1271Sigil,
    ISigilBase,
    IERC165,
    ConfigId,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "@interfaces/ISigil.sol";

// Libraries
import {
    TimeFrameConfigLib,
    TimeFrameConfig
} from "@sigils/TimeFrameSigil/lib/TimeFrameConfigLib.sol";

// forgefmt: disable-start
///  ________ _____ _____ _____ ___________  ___  ___  ___ _____
/// |_   _|_   _|  \/  ||  ___|  ___| ___ \/ _ \ |  \/  ||  ___|
///   | |   | | | .  . || |__ | |_  | |_/ / /_\ \| .  . || |__
///   | |   | | | |\/| ||  __||  _| |    /|  _  || |\/| ||  __|
///   | |  _| |_| |  | || |___| |   | |\ \| | | || |  | || |___
///   \_/  \___/\_|  |_/\____/\_|   \_| \_\_| |_/\_|  |_/\____/
///
///   time window ─ permits an action only inside [validAfter, validUntil]; reads NO calldata
// forgefmt: disable-end
/// @title TimeFrameSigil — the time-window sigil
/// @author highskore.eth
/// @notice An action + signature sigil ({IActionSigil} + {I1271Sigil}) that permits its `(target, selector)`
///         action — and gates the ERC-1271 signing path — ONLY while `block.timestamp` is inside the
///         configured `[validAfter, validUntil]` window, reading no calldata. It is the on-chain expression of
///         "this mandate's actions are valid for a bounded time" — the sigil-shaped replacement for the old
///         baked-in mandate `validUntil` field. In Daimon "everything is a sigil": time bounds are now just
///         another sigil attached to the action(s), enforced per-action at check time rather than as a special
///         field in the mandate-bind digest + storage.
/// @dev Window semantics (BOTH bounds inclusive):
///      - `block.timestamp >= validAfter` — `validAfter == 0` means no lower bound (permitted immediately).
///      - `validUntil == 0` is the sentinel for NO UPPER BOUND — the action never expires. Otherwise the
///        action is permitted iff `block.timestamp <= validUntil`. This mirrors the old mandate convention
///        where a `validUntil` of 0 meant "no expiry", so a no-time-bound action and an explicit
///        `validUntil == 0` are indistinguishable (both = open-ended), as intended.
///      A window with `validAfter > validUntil` (and `validUntil != 0`) is unsatisfiable — it permits the
///        action at no timestamp. Such a config is REJECTED at init ({TimeFrameConfigLib.initialize} reverts
///        {TimeFrameConfigLib.UnsatisfiableWindow}) rather than binding a permanently-inert mandate.
///
///      Lineage: ports the `TimeFramePolicy` pattern from erc7579/smartsessions (a policy enforcing a
///      `[validAfter, validUntil]` validation window) to the Daimon sigil surface, under MIT.
///      A sigil is the symbol that binds a daimon to its allowed behavior; this one binds it to a time window.
///      It is the one sigil that serves BOTH tiers: {checkAction} for the action path and {check1271} for the
///      ERC-1271 path, both a real time-gate — so it advertises {IActionSigil} AND {I1271Sigil} via ERC-165.
///
///      Storage: like {SpendSigil}/{OmniSigil} it stores its config per `(configId, msg.sender, account)` and
///      is configured by the MANDATE engine via {initializeWithMultiplexer}; since the engine is baked into the
///      account, `msg.sender == account` at runtime. Reads NO calldata in either check path — the window is the
///      only constraint; the action's `(target, selector)` scope (enforced by the engine) is the rest.
contract TimeFrameSigil is IActionSigil, I1271Sigil {
    using TimeFrameConfigLib for ConfigId;

    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown at config time when `validAfter > validUntil` with a non-zero `validUntil` — an
    ///         unsatisfiable window. Shares the {UnsatisfiableWindow} selector reverted by
    ///         {TimeFrameConfigLib.initialize} (the configure path), so a revert there is observable as
    ///         `TimeFrameSigil.UnsatisfiableWindow` (mirrors {SpendSigil.InvalidToken}).
    /// @param validAfter The lower bound that exceeded the upper bound.
    /// @param validUntil The non-zero upper bound.
    error UnsatisfiableWindow(uint48 validAfter, uint48 validUntil);

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice The time-window configuration for `(id, multiplexer, account)`. Mirrors a public-mapping getter:
    ///         returns the zero window for a never-configured triple.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return validAfter The window's lower bound (0 ⇒ no lower bound).
    /// @return validUntil The window's upper bound (0 ⇒ no upper bound).
    function timeFrameConfigs(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint48 validAfter, uint48 validUntil)
    {
        TimeFrameConfig storage cfg = id.get(multiplexer, account);
        return (cfg.validAfter, cfg.validUntil);
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
    /// @dev Decodes `initData` as `abi.encode(uint48 validAfter, uint48 validUntil)` and stores it for
    ///      (configId, msg.sender, account) via {TimeFrameConfigLib}. Accepts any window — including the
    ///      open-ended `(0, 0)` and the unsatisfiable `validAfter > validUntil` (which simply denies forever);
    ///      the engine, not this sigil, is the authority on whether a mandate's window is sensible. Emits
    ///      {SigilSet} like every sigil.
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
    /// @dev Permits the action iff `block.timestamp` is inside the configured `[validAfter, validUntil]` window
    ///      (both bounds inclusive; `validUntil == 0` ⇒ no upper bound). Reads NO `data` and enforces NO `value`
    ///      cap — the time window is the only constraint this sigil adds on top of the action scope.
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256,
        bytes calldata
    )
        external
        view
        returns (uint256)
    {
        return _check(id.get(msg.sender, account));
    }

    /// @inheritdoc I1271Sigil
    /// @dev Mirrors {checkAction}: enforces the same `[validAfter, validUntil]` window on the ERC-1271 path,
    ///      reading no `content`. A signed message authorized under this policy is only valid inside the window.
    ///
    ///      TIME-ONLY gate: because `content` is ignored, placing this sigil ALONE in a mandate's signature
    ///      slot would authorize signing ANY digest for ANY requesting dApp within the window — it is a
    ///      REFINEMENT of the signing scope, not a standalone authorization. It must always be composed with
    ///      a content/sender-binding signature sigil ({AttestationSigil} or {Eip3009Sigil}) that constrains
    ///      WHAT can be signed; TimeFrameSigil then constrains WHEN.
    function check1271(
        ConfigId id,
        address account,
        bytes calldata
    )
        external
        view
        returns (uint256)
    {
        return _check(id.get(msg.sender, account));
    }

    /// @dev The shared window check used by BOTH {checkAction} and {check1271}.
    ///      Returns {VALIDATION_SUCCESS} iff `block.timestamp >= validAfter` AND
    ///      (`validUntil == 0` OR `block.timestamp <= validUntil`); otherwise {VALIDATION_FAILED}.
    ///
    ///      FAIL-OPEN DEFAULT: this is the only sigil with no initialized-guard. An unconfigured
    ///      `(validAfter=0, validUntil=0)` config returns VALIDATION_SUCCESS — fail-open. This is safe only
    ///      because the engine guarantees {initializeWithMultiplexer} runs for every bound action/signature
    ///      sigil under the matching configId before any check; do NOT invoke `_check` on a possibly-
    ///      uninitialized triple from any other call path. A `(0,0)` window is also intentionally bindable
    ///      as "open-ended" (no lower bound, no upper bound), so the fail-open default and a deliberate
    ///      open-ended binding are indistinguishable by design.
    /// @param cfg The stored time-window config for (id, multiplexer, account).
    /// @return A validation code: `VALIDATION_SUCCESS` (in window) or `VALIDATION_FAILED` (outside).
    function _check(TimeFrameConfig storage cfg) private view returns (uint256) {
        if (block.timestamp < cfg.validAfter) return VALIDATION_FAILED;
        // `validUntil == 0` is the open-ended sentinel: no upper bound, the action never expires.
        if (cfg.validUntil != 0 && block.timestamp > cfg.validUntil) return VALIDATION_FAILED;
        return VALIDATION_SUCCESS;
    }

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises BOTH tiers it serves: {IERC165}, {ISigilBase}, {IActionSigil}, and {I1271Sigil} — so the
    ///      engine's per-tier bind guard accepts it in the action slot AND the signature slot.
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IActionSigil).interfaceId
            || interfaceID == type(I1271Sigil).interfaceId;
    }
}
