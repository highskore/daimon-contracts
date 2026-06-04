// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/*·:⛧:·──────── STRUCTS ────────:⛧:·*/

/// @notice Configuration for an {OmniSigil} instance.
/// @param valueLimitPerUse Maximum ETH value allowed per action.
/// @param paramRules The parameter rules + their logical expression tree.
struct ActionConfig {
    uint256 valueLimitPerUse;
    ParamRules paramRules;
}

/// @notice A rule set and the boolean expression tree relating the rules.
/// @param rootNodeIndex Index of the root node in the expression tree.
/// @param rules The parameter rules referenced by leaf nodes.
/// @param packedNodes Bit-packed nodes of the expression tree.
struct ParamRules {
    uint8 rootNodeIndex;
    ParamRule[] rules;
    uint256[] packedNodes;
}

/// @notice A single check against one calldata argument.
/// @param condition The comparison applied to the extracted argument.
/// @param offset Offset of the argument in calldata, relative to *after* the 4-byte selector.
/// @param isLimited Whether this argument accrues against a cumulative usage limit.
/// @param ref The reference value compared against (for IN_RANGE, packs min<<128 | max).
/// @param usage Cumulative limit + amount used (only when `isLimited`).
struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    bool isLimited;
    bytes32 ref;
    LimitUsage usage;
}

/// @notice Cumulative usage tracking for a limited argument.
/// @param limit Maximum allowed cumulative value.
/// @param used Amount used so far.
struct LimitUsage {
    uint256 limit;
    uint256 used;
}

/*·:⛧:·──────── ENUMS ────────:⛧:·*/

/// @notice Comparison operators a {ParamRule} may apply to an extracted argument.
enum ParamCondition {
    EQUAL, // Parameter == ref
    GREATER_THAN, // Parameter > ref
    LESS_THAN, // Parameter < ref
    GREATER_THAN_OR_EQUAL, // Parameter >= ref
    LESS_THAN_OR_EQUAL, // Parameter <= ref
    NOT_EQUAL, // Parameter != ref
    IN_RANGE // ref packs min/max, Parameter must be within range
}
