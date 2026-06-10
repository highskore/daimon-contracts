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
    NativeValueLimitConfigLib,
    NativeValueLimitConfig
} from "@sigils/NativeValueLimitSigil/lib/NativeValueLimitConfigLib.sol";

/// @title NativeValueLimitSigil — a composable native-value (ETH) cap
/// @author highskore.eth
/// @notice An {IActionSigil} that ONLY enforces `value <= limit` on a guarded action — it reads no calldata and runs no
///         argument logic. Compose it alongside an argument sigil to add a native-value bound:
///         `[SudoSigil + NativeValueLimitSigil(0)]` permits any arguments but NO ETH (closing the SudoSigil
///         value-drain), and `[OmniSigil(...) + NativeValueLimitSigil(N)]` keeps the arg rules while capping value at N.
/// @dev Separating the value cap from the argument rules keeps it reusable across any action sigil rather than
///      baking a value limit into each one. Configured per account by the MANDATE engine via
///      {initializeWithMultiplexer}; `checkAction` reads `(configId, msg.sender, account)`.
///
///      Fail-closed default: an unconfigured entry has `limit == 0`, so it permits only `value == 0` — identical
///      to an explicit `NativeValueLimitSigil(0)`. This is a pure action sigil ({IActionSigil}): a signature carries no
///      native value, so a value cap cannot constrain signing — it has no ERC-1271 tier and reverts
///      {MandateEngine.UnsupportedSigil} if placed in a mandate's signature slot.
contract NativeValueLimitSigil is IActionSigil {
    using NativeValueLimitConfigLib for ConfigId;

    /*·:⛧:·──────── VIEW ────────:⛧:·*/

    /// @notice The configured native-value cap for (id, multiplexer, account).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the account/engine).
    /// @param account The guarded account.
    /// @return limit The max native value (wei) one action may carry (`0` = no ETH).
    function nativeValueLimits(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256 limit)
    {
        return id.get(multiplexer, account).limit;
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
    /// @dev Decodes + stores a {NativeValueLimitConfig} (`uint256 limit`). Emits {SigilSet}.
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
    /// @dev Permits iff `value <= limit`. Reads no `data` (no argument logic) — native value is the only
    ///      constraint. This bound is PER-CALL, not per-execution: in a K-call batch each individual call
    ///      may carry up to `limit` wei, so the total native outflow in one execution can reach K·limit.
    ///      For a cumulative per-execution or per-period native ceiling, compose with a NATIVE-budget
    ///      {SpendSigil} (set `token` to the NATIVE sentinel `0xEeee…EEeE`).
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256 value,
        bytes calldata
    )
        external
        view
        returns (uint256)
    {
        return value <= id.get(msg.sender, account).limit ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the action tier only: {IERC165}, {ISigilBase}, {IActionSigil}.
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IActionSigil).interfaceId;
    }
}
