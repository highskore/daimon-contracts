// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamRule, ParamRules, ActionConfig, ParamCondition } from "./OmniSigilTypes.sol";

/// @title OmniSigilTreeLib
/// @author highskore.eth
/// @notice Parameter-rule checks + boolean expression-tree evaluation for {OmniSigil}.
/// @dev Lineage: adapted by the author from `ArgPolicyTreeLib` (MIT) in
/// erc7579/smartsessions; remains MIT-licensed for Daimon. Holds rule evaluation, tree validation,
/// and node-packing helpers.
library OmniSigilTreeLib {
    using OmniSigilTreeLib for *;

    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown when the expression tree has no nodes.
    error EmptyExpressionTree();
    /// @notice Thrown when the root node index is out of bounds.
    error RootNodeIndexOutOfBounds();
    /// @notice Thrown when there are more rules than {MAX_RULES}.
    error TooManyRules();
    /// @notice Thrown when there are more nodes than {MAX_NODES}.
    error TooManyNodes();
    /// @notice Thrown when a node references a child index out of bounds.
    error NodeChildIndexOutOfBounds();
    /// @notice Thrown when a node references a child index that is not strictly less than its own index — a
    ///         forward/self reference that would let the node graph contain a cycle.
    error NodeChildIndexNotDescending();
    /// @notice Thrown when a leaf node references a rule index out of bounds.
    error RuleIndexOutOfBounds();

    /*·:⛧:·──────── CONSTANTS ────────:⛧:·*/

    uint8 internal constant NODE_TYPE_RULE = 0; // Leaf node referencing a rule
    uint8 internal constant NODE_TYPE_NOT = 1; // NOT operator (unary)
    uint8 internal constant NODE_TYPE_AND = 2; // AND operator (binary)
    uint8 internal constant NODE_TYPE_OR = 3; // OR operator (binary)

    uint8 internal constant NODE_TYPE_SHIFT = 0;
    uint8 internal constant RULE_INDEX_SHIFT = 2;
    uint8 internal constant LEFT_CHILD_SHIFT = 10;
    uint8 internal constant RIGHT_CHILD_SHIFT = 18;

    uint256 internal constant NODE_TYPE_MASK = 0x3; // 2 bits
    uint256 internal constant RULE_INDEX_MASK = 0xFF; // 8 bits
    uint256 internal constant LEFT_CHILD_MASK = 0xFF; // 8 bits
    uint256 internal constant RIGHT_CHILD_MASK = 0xFF; // 8 bits

    uint256 internal constant MAX_RULES = 128;
    uint256 internal constant MAX_NODES = 256;

    /*·:⛧:·──────── VALIDATE ────────:⛧:·*/

    /// @notice Check a single parameter rule against the calldata.
    /// @dev Extracts a 32-byte word at `4 + rule.offset` (skipping the selector) and applies the
    /// condition, then (if limited) accrues + bounds the cumulative usage.
    /// @param rule The rule to evaluate.
    /// @param data The action calldata.
    /// @return True iff the rule passes.
    function check(ParamRule storage rule, bytes calldata data) internal returns (bool) {
        uint64 offset = rule.offset;
        ParamCondition condition = rule.condition;
        bytes32 ref = rule.ref;
        bytes32 param = bytes32(data[4 + offset:4 + offset + 32]);

        if (condition == ParamCondition.EQUAL && param != ref) {
            return false;
        } else if (condition == ParamCondition.GREATER_THAN && param <= ref) {
            return false;
        } else if (condition == ParamCondition.LESS_THAN && param >= ref) {
            return false;
        } else if (condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < ref) {
            return false;
        } else if (condition == ParamCondition.LESS_THAN_OR_EQUAL && param > ref) {
            return false;
        } else if (condition == ParamCondition.NOT_EQUAL && param == ref) {
            return false;
        } else if (condition == ParamCondition.IN_RANGE) {
            // rule.ref packs min (high 128 bits) and max (low 128 bits).
            if (
                param < (ref >> 128)
                    || param
                        > (ref & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            ) {
                return false;
            }
        }

        if (rule.isLimited) {
            if (rule.usage.used + uint256(param) > rule.usage.limit) {
                return false;
            }
            rule.usage.used += uint256(param);
        }
        return true;
    }

    /// @notice Validate that the expression tree is well-formed (bounds + child/rule indices) AND acyclic.
    /// @dev Acyclicity: every child index must be STRICTLY LESS than its parent node's own index. This single
    ///      topological constraint guarantees the node graph is a DAG (it admits no self- or back-edge), which
    ///      bounds {evaluateNode}'s recursion depth to `nodeCount` — closing the unbounded-recursion (OOG) brick
    ///      where a node whose child points to itself or an ancestor (e.g. an AND at index 0 with `leftChild == 0`)
    ///      would pass the bounds check yet recurse forever. The constraint is free for every real tree: the SDK
    ///      builders emit nodes children-first (a leaf/subtree always precedes the operator that consumes it), so
    ///      a child index is already < its parent's. The out-of-bounds checks run FIRST, so a child index
    ///      `>= nodeCount` still reverts {NodeChildIndexOutOfBounds}; an in-bounds non-descending child reverts
    ///      {NodeChildIndexNotDescending}.
    /// @param rules The rule set + tree to validate.
    function validateExpressionTree(ParamRules memory rules) internal pure {
        uint256 nodeCount = rules.packedNodes.length;
        uint256 ruleCount = rules.rules.length;

        require(nodeCount != 0, EmptyExpressionTree());
        require(rules.rootNodeIndex < nodeCount, RootNodeIndexOutOfBounds());
        require(ruleCount <= MAX_RULES, TooManyRules());
        require(nodeCount <= MAX_NODES, TooManyNodes());

        for (uint256 i = 0; i < nodeCount; i++) {
            uint256 node = rules.packedNodes[i];
            uint8 nodeType = node.getNodeType();

            if (nodeType == NODE_TYPE_RULE) {
                require(node.getRuleIndex() < ruleCount, RuleIndexOutOfBounds());
            } else if (nodeType == NODE_TYPE_NOT) {
                uint8 left = node.getLeftChildIndex();
                require(left < nodeCount, NodeChildIndexOutOfBounds());
                require(left < i, NodeChildIndexNotDescending());
            } else {
                uint8 left = node.getLeftChildIndex();
                uint8 right = node.getRightChildIndex();
                require(left < nodeCount && right < nodeCount, NodeChildIndexOutOfBounds());
                require(left < i && right < i, NodeChildIndexNotDescending());
            }
        }
    }

    /*·:⛧:·──────── EVALUATE ────────:⛧:·*/

    /// @notice Evaluate the expression tree from its root node.
    /// @param rules The rule set + tree.
    /// @param data The action calldata.
    /// @return The boolean result of the expression.
    function evaluateExpressionTree(
        ParamRules storage rules,
        bytes calldata data
    )
        internal
        returns (bool)
    {
        return evaluateNode(rules.packedNodes, rules.rootNodeIndex, rules.rules, data);
    }

    /// @notice Recursively evaluate one node, with short-circuiting AND/OR.
    /// @param packedNodes The bit-packed nodes.
    /// @param nodeIndex The node to evaluate.
    /// @param rules The rule set referenced by leaf nodes.
    /// @param data The action calldata.
    /// @return The boolean result of the subtree rooted at `nodeIndex`.
    function evaluateNode(
        uint256[] storage packedNodes,
        uint8 nodeIndex,
        ParamRule[] storage rules,
        bytes calldata data
    )
        internal
        returns (bool)
    {
        uint256 node = packedNodes[nodeIndex];
        uint8 nodeType = node.getNodeType();

        if (nodeType == NODE_TYPE_RULE) {
            return rules[node.getRuleIndex()].check(data);
        } else if (nodeType == NODE_TYPE_NOT) {
            return !evaluateNode(packedNodes, node.getLeftChildIndex(), rules, data);
        } else if (nodeType == NODE_TYPE_AND) {
            if (!evaluateNode(packedNodes, node.getLeftChildIndex(), rules, data)) return false;
            return evaluateNode(packedNodes, node.getRightChildIndex(), rules, data);
        } else if (nodeType == NODE_TYPE_OR) {
            if (evaluateNode(packedNodes, node.getLeftChildIndex(), rules, data)) return true;
            return evaluateNode(packedNodes, node.getRightChildIndex(), rules, data);
        }
        return false;
    }

    /*·:⛧:·──────── FILL ────────:⛧:·*/

    /// @notice Copy a memory config into storage (clean slate).
    /// @dev `delete $config.paramRules.rules` followed by re-pushing resets each rule's cumulative
    ///      `usage.used` counter to 0. This DIFFERS from {SpendSigil} and {RateLimitSigil}, which
    ///      deliberately preserve their rolling state across re-init so a re-bind cannot clear an exhausted
    ///      budget. OmniSigil's cumulative argument-level limits ARE reset on every ROOT re-bind — intentional
    ///      clean-slate semantics, restricted to the ROOT tier.
    /// @param $config The destination storage config.
    /// @param config The source memory config.
    function fill(ActionConfig storage $config, ActionConfig memory config) internal {
        $config.valueLimitPerUse = config.valueLimitPerUse;
        $config.paramRules.rootNodeIndex = config.paramRules.rootNodeIndex;

        delete $config.paramRules.rules;
        delete $config.paramRules.packedNodes;

        for (uint256 i = 0; i < config.paramRules.rules.length; i++) {
            $config.paramRules.rules.push(config.paramRules.rules[i]);
        }
        for (uint256 i = 0; i < config.paramRules.packedNodes.length; i++) {
            $config.paramRules.packedNodes.push(config.paramRules.packedNodes[i]);
        }
    }

    /*·:⛧:·──────── NODE HELPERS ────────:⛧:·*/

    /// @notice Pack a leaf (RULE) node referencing `ruleIndex`.
    function createRuleNode(uint8 ruleIndex) internal pure returns (uint256) {
        return uint256(NODE_TYPE_RULE) | (uint256(ruleIndex) << RULE_INDEX_SHIFT);
    }

    /// @notice Pack a unary NOT node over `leftChildIndex`.
    function createNotNode(uint8 leftChildIndex) internal pure returns (uint256) {
        return uint256(NODE_TYPE_NOT) | (uint256(leftChildIndex) << LEFT_CHILD_SHIFT);
    }

    /// @notice Pack a binary AND node over its children.
    function createAndNode(
        uint8 leftChildIndex,
        uint8 rightChildIndex
    )
        internal
        pure
        returns (uint256)
    {
        return uint256(NODE_TYPE_AND) | (uint256(leftChildIndex) << LEFT_CHILD_SHIFT)
            | (uint256(rightChildIndex) << RIGHT_CHILD_SHIFT);
    }

    /// @notice Pack a binary OR node over its children.
    function createOrNode(
        uint8 leftChildIndex,
        uint8 rightChildIndex
    )
        internal
        pure
        returns (uint256)
    {
        return uint256(NODE_TYPE_OR) | (uint256(leftChildIndex) << LEFT_CHILD_SHIFT)
            | (uint256(rightChildIndex) << RIGHT_CHILD_SHIFT);
    }

    /// @notice Extract the 2-bit node type from a packed node.
    function getNodeType(uint256 packedNode) internal pure returns (uint8) {
        return uint8(packedNode & NODE_TYPE_MASK);
    }

    /// @notice Extract the rule index from a packed leaf node.
    function getRuleIndex(uint256 packedNode) internal pure returns (uint8) {
        return uint8((packedNode >> RULE_INDEX_SHIFT) & RULE_INDEX_MASK);
    }

    /// @notice Extract the left child index from a packed node.
    function getLeftChildIndex(uint256 packedNode) internal pure returns (uint8) {
        return uint8((packedNode >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);
    }

    /// @notice Extract the right child index from a packed node.
    function getRightChildIndex(uint256 packedNode) internal pure returns (uint8) {
        return uint8((packedNode >> RIGHT_CHILD_SHIFT) & RIGHT_CHILD_MASK);
    }
}
