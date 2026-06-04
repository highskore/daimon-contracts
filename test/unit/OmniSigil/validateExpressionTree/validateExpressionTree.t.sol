// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { OmniSigil_Unit_Test } from "../OmniSigil.t.sol";

// Contracts
import { OmniSigil, ParamRule, ParamCondition } from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title OmniSigil.validateExpressionTree Unit Tests
/// @author highskore.eth
/// @notice Regression coverage for the tree-validation loop. Building a tree at the {MAX_NODES} (256)
///         ceiling must terminate: an earlier loop counter typed `uint8` wrapped 255 -> 0 at 256 nodes,
///         spinning forever (OOG). The counter is now `uint256`.
contract OmniSigil_validateExpressionTree_Unit_Test is OmniSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Single-arg selector for the leaf rule the chain bottoms out on.
    bytes4 internal constant SEL = 0x12345678;

    /// @dev The maximum number of nodes a tree may hold (mirrors {OmniSigilTreeLib.MAX_NODES}).
    uint256 internal constant MAX_NODES = 256;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A tree of exactly {MAX_NODES} nodes installs (validation terminates) and evaluates.
    /// @dev The validation loop iterates every node, so 256 nodes is what overflowed the old `uint8`
    ///      counter (255 -> 0, never reaching `nodeCount`). All 256 nodes are RULE leaves over the same
    ///      satisfied rule; the root is node 0, keeping evaluation shallow so this isolates the loop
    ///      regression rather than recursion depth.
    function test_validateExpressionTree_at256Nodes_terminatesAndValidates() external {
        // Arrange: one leaf rule the calldata word satisfies (EQUAL to the target word).
        bytes32 target = _word(uint256(42));
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, target);

        // 256 RULE-leaf nodes (all referencing rule 0). Validation visits all 256; the old counter hung here.
        uint256[] memory nodes = new uint256[](MAX_NODES);
        for (uint256 i = 0; i < MAX_NODES; i++) {
            nodes[i] = OmniSigilTreeLib.createRuleNode(0);
        }

        // Act: install with root at node 0. With the old uint8 counter, validation never returned (OOG).
        _installTree(rules, nodes, 0, type(uint256).max);

        // Assert: a 256-node config installs and the satisfied leaf passes (validation terminated).
        bytes memory data = _calldata1(SEL, target);
        assertEq(
            omni.checkAction(ID, ACCOUNT, address(0), 0, data),
            VALIDATION_SUCCESS,
            "256-node tree must validate + evaluate, not hang"
        );
    }
}
