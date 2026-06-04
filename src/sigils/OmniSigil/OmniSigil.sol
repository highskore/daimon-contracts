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
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";
import { OmniSigilConfigLib } from "@sigils/OmniSigil/lib/OmniSigilConfigLib.sol";

// Types
import {
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/lib/OmniSigilTypes.sol";

// forgefmt: disable-start
///  ________  ___ _   _ _____ _____ _____ _____ _____ _
/// |  _  |  \/  || \ | |_   _/  ___|_   _|  __ \_   _| |
/// | | | | .  . ||  \| | | | \ `--.  | | | |  \/ | | | |
/// | | | | |\/| || . ` | | |  `--. \ | | | | __  | | | |
/// \ \_/ / |  | || |\  |_| |_/\__/ /_| |_| |_\ \_| |_| |____
///  \___/\_|  |_/\_| \_/\___/\____/ \___/ \____/\___/\_____/
///
///   rule tree (AND / OR / NOT) over calldata args, e.g.:
///                  AND
///                 ╱   ╲
///       recipient==self   amountIn ≤ cap
// forgefmt: disable-end
/// @title OmniSigil — the generic calldata-argument policy
/// @author highskore.eth
/// @notice The most powerful {IActionSigil}: validates a function's calldata arguments against a tree of rules
///         combined with AND / OR / NOT, with arbitrary nesting. Each rule checks one argument against a
///         condition (equality, ranges, thresholds) and may enforce a cumulative usage limit. This is what
///         expresses a mandate's recipient-locks, amount caps, and allowlists.
/// @dev Lineage: adapted from `ArgPolicy` (MIT) in erc7579/smartsessions; remains MIT-licensed for Daimon.
///      A sigil is the symbol that binds a daimon to its allowed behavior.
///
///      Rule offsets are STATIC: a rule reads a fixed 32-byte word at `4 + offset`. This targets top-level
///      statically-typed arguments; it does not target values nested in dynamic ABI data (e.g. the recipient
///      inside Uniswap UniversalRouter `execute(bytes,bytes[])`), which require ABI/dynamic-type awareness.
contract OmniSigil is IActionSigil {
    using OmniSigilTreeLib for *;
    using OmniSigilConfigLib for ConfigId;

    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown when an action's ETH value exceeds the configured per-use limit.
    /// @param id The configuration id.
    /// @param value The value supplied.
    /// @param limit The configured per-use limit.
    error ValueLimitExceeded(ConfigId id, uint256 value, uint256 limit);

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice The configuration for `(id, multiplexer, account)`. Mirrors a public-mapping getter over the
    ///         {ActionConfig} struct: returns its non-array members (the dynamic `paramRules.rules` /
    ///         `paramRules.packedNodes` are omitted, exactly as a Solidity auto-getter would).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return valueLimitPerUse The per-use ETH value cap.
    /// @return rootNodeIndex The index of the expression tree's root node.
    function actionConfigs(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256 valueLimitPerUse, uint8 rootNodeIndex)
    {
        ActionConfig storage config = id.get(multiplexer, account);
        return (config.valueLimitPerUse, config.paramRules.rootNodeIndex);
    }

    /// @notice The cumulative usage of a limited rule for `(id, multiplexer, account)` — the `used`/`limit`
    ///         pair a {ParamRule}'s rolling-free cumulative cap accrues against (`isLimited` rules only;
    ///         an unlimited rule reads back `(0, 0)`).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @param ruleIndex The index of the rule in `paramRules.rules`.
    /// @return used The cumulative value charged against the rule so far.
    /// @return limit The rule's cumulative cap.
    function usageOf(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 ruleIndex
    )
        external
        view
        returns (uint256 used, uint256 limit)
    {
        LimitUsage storage u = id.get(multiplexer, account).paramRules.rules[ruleIndex].usage;
        return (u.used, u.limit);
    }

    /*·:⛧:·──────── CHECK ────────:⛧:·*/

    /// @inheritdoc IActionSigil
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256)
    {
        ActionConfig storage config = id.get(msg.sender, account);

        // Reject if the sigil was never configured for this (id, multiplexer, account).
        if (config.paramRules.rules.length == 0 || config.paramRules.packedNodes.length == 0) {
            revert PolicyNotInitialized(id, msg.sender, account);
        }
        // Enforce the per-use ETH value cap.
        if (value > config.valueLimitPerUse) {
            revert ValueLimitExceeded(id, value, config.valueLimitPerUse);
        }
        // Evaluate the boolean expression tree over the calldata arguments.
        return
            config.paramRules.evaluateExpressionTree(data) ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
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

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the action tier only: {IERC165}, {ISigilBase}, {IActionSigil}. Placed in the signature
    ///      tier of a mandate it would fail the engine's per-tier bind guard ({UnsupportedSigil}).
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IActionSigil).interfaceId;
    }
}
