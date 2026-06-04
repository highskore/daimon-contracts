// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { OmniSigil_Unit_Test } from "../OmniSigil.t.sol";

// Contracts
import {
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Interfaces
import { ISigilBase } from "@interfaces/ISigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title OmniSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Config installation: a well-formed config is validated, stored, and announced via SigilSet;
///         every {OmniSigilTreeLib.validateExpressionTree} guard rejects a malformed expression tree
///         (empty tree, bad root, too many rules/nodes, out-of-bounds rule/child indices).
contract OmniSigil_initializeWithMultiplexer_Unit_Test is OmniSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Generic single-arg selector used by the well-formed-config check.
    bytes4 internal constant SEL = 0x12345678;

    /*//////////////////////////////////////////////////////////////
                            WELL-FORMED CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice A well-formed config emits SigilSet keyed by (id, multiplexer, account).
    function test_initializeWithMultiplexer_emitsSigilSet() external {
        // Arrange
        ActionConfig memory cfg = _singleRuleConfig();

        // Act & Assert
        vm.expectEmit(true, true, true, true, address(omni));
        emit ISigilBase.SigilSet(ID, address(this), ACCOUNT);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice A well-formed config is persisted: a subsequent check resolves against the stored rules.
    function test_initializeWithMultiplexer_storesConfig() external {
        // Arrange
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(_singleRuleConfig()));

        // Act & Assert: the EQUAL(word0 == 1) rule now resolves for ID (no PolicyNotInitialized revert).
        assertEq(
            _check(_calldata1(SEL, _word(uint256(1)))), VALIDATION_SUCCESS, "stored rule resolves"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        VALIDATE EXPRESSION TREE
    //////////////////////////////////////////////////////////////*/

    /// @notice A tree with zero nodes is rejected.
    function test_initializeWithMultiplexer_revertsWhen_emptyTree() external {
        // Arrange: one rule, but no nodes.
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        uint256[] memory nodes = new uint256[](0);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.EmptyExpressionTree.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice A root node index at/over the node count is rejected.
    function test_initializeWithMultiplexer_revertsWhen_rootOutOfBounds() external {
        // Arrange: a single node, but rootNodeIndex points at index 1 (== nodeCount).
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 1, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.RootNodeIndexOutOfBounds.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice More than MAX_RULES (128) rules is rejected.
    function test_initializeWithMultiplexer_revertsWhen_tooManyRules() external {
        // Arrange: 129 rules (> MAX_RULES), with a valid single-node tree.
        ParamRule[] memory rules = new ParamRule[](129);
        for (uint256 i = 0; i < rules.length; i++) {
            rules[i] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        }
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.TooManyRules.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice More than MAX_NODES (256) nodes is rejected.
    function test_initializeWithMultiplexer_revertsWhen_tooManyNodes() external {
        // Arrange: 257 nodes (> MAX_NODES), one rule, root at index 0.
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        uint256[] memory nodes = new uint256[](257);
        for (uint256 i = 0; i < nodes.length; i++) {
            nodes[i] = OmniSigilTreeLib.createRuleNode(0);
        }
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.TooManyNodes.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice A leaf node referencing a non-existent rule index is rejected.
    function test_initializeWithMultiplexer_revertsWhen_ruleIndexOutOfBounds() external {
        // Arrange: one rule (index 0), but the leaf references rule index 1.
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(1);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.RuleIndexOutOfBounds.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice A NOT node whose child index is out of bounds is rejected.
    function test_initializeWithMultiplexer_revertsWhen_notChildOutOfBounds() external {
        // Arrange: 2 nodes; the NOT at index 1 points at child index 2 (== nodeCount).
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        uint256[] memory nodes = new uint256[](2);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        nodes[1] = OmniSigilTreeLib.createNotNode(2);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 1, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.NodeChildIndexOutOfBounds.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice An AND node whose child index is out of bounds is rejected.
    function test_initializeWithMultiplexer_revertsWhen_andChildOutOfBounds() external {
        // Arrange: 3 nodes; the AND at index 2 points at right child index 3 (== nodeCount).
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(1)));
        uint256[] memory nodes = new uint256[](3);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        nodes[1] = OmniSigilTreeLib.createRuleNode(0);
        nodes[2] = OmniSigilTreeLib.createAndNode(0, 3);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 2, rules: rules, packedNodes: nodes })
        });

        // Act & Assert
        vm.expectRevert(OmniSigilTreeLib.NodeChildIndexOutOfBounds.selector);
        omni.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A minimal valid config: a single EQUAL(word0 == 1) rule under one leaf node.
    function _singleRuleConfig() internal pure returns (ActionConfig memory cfg) {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0,
            isLimited: false,
            ref: bytes32(uint256(1)),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });
    }
}
