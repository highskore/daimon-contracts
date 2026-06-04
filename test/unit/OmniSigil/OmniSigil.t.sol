// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import {
    OmniSigil,
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title OmniSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for OmniSigil unit suites: deploys the sigil and provides the rule-config
///         + check helpers each function suite reuses.
abstract contract OmniSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant ATTACKER = address(0xBEEF);
    address internal constant TOKEN_IN = address(0x1111);
    address internal constant TOKEN_OUT = address(0x2222);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    OmniSigil internal omni;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        omni = new OmniSigil();
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Install a single EQUAL rule on `ID` that locks the word at `offset` to `account`.
    /// @param offset Calldata offset (relative to after the selector) the rule pins.
    /// @param account The address the word must equal.
    function _lockRecipient(uint64 offset, address account) internal {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: offset,
            isLimited: false,
            ref: bytes32(uint256(uint160(account))),
            usage: LimitUsage({ limit: 0, used: 0 })
        });

        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);

        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: type(uint256).max,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice Run the installed rule set against `data` for action ID `ID`.
    /// @param data The inner call data being authorized.
    /// @return The sigil's validation result (0 = success, 1 = failed).
    function _check(bytes memory data) internal returns (uint256) {
        return omni.checkAction(ID, ACCOUNT, address(0), 0, data);
    }

    /// @notice The offset (relative to after the 4-byte selector) of the first 32-byte word == `target`.
    /// @param data The encoded call data to scan.
    /// @param target The word to find.
    /// @return The matching offset; reverts if absent.
    function _findWordOffset(bytes memory data, bytes32 target) internal pure returns (uint64) {
        for (uint256 p = 4; p + 32 <= data.length; p += 32) {
            bytes32 w;
            assembly {
                w := mload(add(add(data, 0x20), p))
            }
            if (w == target) return uint64(p - 4);
        }
        revert("target word not found");
    }

    /*//////////////////////////////////////////////////////////////
                          RULE / TREE BUILDERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Build one unlimited {ParamRule}.
    /// @param condition The comparison the rule applies.
    /// @param offset Calldata offset (relative to after the selector) the rule reads.
    /// @param ref The reference value compared against (for IN_RANGE: min<<128 | max).
    /// @return The assembled rule.
    function _rule(
        ParamCondition condition,
        uint64 offset,
        bytes32 ref
    )
        internal
        pure
        returns (ParamRule memory)
    {
        return ParamRule({
            condition: condition,
            offset: offset,
            isLimited: false,
            ref: ref,
            usage: LimitUsage({ limit: 0, used: 0 })
        });
    }

    /// @notice Build one limited {ParamRule} (accrues `used` against `limit`).
    /// @param condition The comparison the rule applies.
    /// @param offset Calldata offset (relative to after the selector) the rule reads.
    /// @param ref The reference value compared against.
    /// @param limit The cumulative usage cap.
    /// @return The assembled rule.
    function _limitedRule(
        ParamCondition condition,
        uint64 offset,
        bytes32 ref,
        uint256 limit
    )
        internal
        pure
        returns (ParamRule memory)
    {
        return ParamRule({
            condition: condition,
            offset: offset,
            isLimited: true,
            ref: ref,
            usage: LimitUsage({ limit: limit, used: 0 })
        });
    }

    /// @notice Install a config of exactly one rule wrapped in a single leaf node, with `valueLimitPerUse`.
    /// @param rule The single rule to install.
    /// @param valueLimitPerUse The per-action ETH value cap.
    function _installSingle(ParamRule memory rule, uint256 valueLimitPerUse) internal {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = rule;

        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);

        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: valueLimitPerUse,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice Install a config of one rule (single leaf), with an unbounded value cap.
    /// @param rule The single rule to install.
    function _installSingle(ParamRule memory rule) internal {
        _installSingle(rule, type(uint256).max);
    }

    /// @notice Install a config of `rules` combined under a caller-built `nodes` tree.
    /// @param rules The rule set referenced by the tree's leaf nodes.
    /// @param nodes The packed expression-tree nodes.
    /// @param rootNodeIndex Index of the tree's root node.
    /// @param valueLimitPerUse The per-action ETH value cap.
    function _installTree(
        ParamRule[] memory rules,
        uint256[] memory nodes,
        uint8 rootNodeIndex,
        uint256 valueLimitPerUse
    )
        internal
    {
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: valueLimitPerUse,
            paramRules: ParamRules({
                rootNodeIndex: rootNodeIndex, rules: rules, packedNodes: nodes
            })
        });
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice Build calldata-shaped content: a 4-byte selector followed by `args` 32-byte words.
    /// @param selector The leading 4-byte selector.
    /// @param args The 32-byte argument words, in order; word `i` sits at offset `i * 32`.
    /// @return The packed calldata.
    function _calldata(bytes4 selector, bytes32[] memory args)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory out = abi.encodePacked(selector);
        for (uint256 i = 0; i < args.length; i++) {
            out = abi.encodePacked(out, args[i]);
        }
        return out;
    }

    /// @notice One-word calldata: selector + a single 32-byte argument at offset 0.
    /// @param selector The leading 4-byte selector.
    /// @param word The single argument word.
    /// @return The packed calldata.
    function _calldata1(bytes4 selector, bytes32 word) internal pure returns (bytes memory) {
        bytes32[] memory args = new bytes32[](1);
        args[0] = word;
        return _calldata(selector, args);
    }

    /// @notice Left-pad an address into a 32-byte word (the ABI encoding the rule reads).
    /// @param account The address to encode.
    /// @return The word form of `account`.
    function _word(address account) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }

    /// @notice Pack a uint into a 32-byte word.
    /// @param value The value to encode.
    /// @return The word form of `value`.
    function _word(uint256 value) internal pure returns (bytes32) {
        return bytes32(value);
    }

    /// @notice Pack a `[min, max]` range into a single IN_RANGE ref word (min<<128 | max).
    /// @param min The inclusive lower bound (fits in 128 bits).
    /// @param max The inclusive upper bound (fits in 128 bits).
    /// @return The packed range ref.
    function _range(uint128 min, uint128 max) internal pure returns (bytes32) {
        return bytes32((uint256(min) << 128) | uint256(max));
    }
}
