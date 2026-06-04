// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { OmniSigil_Unit_Test } from "../OmniSigil.t.sol";

// Contracts
import { OmniSigil, ParamRule, ParamCondition } from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";
import { ISigilBase } from "@interfaces/ISigil.sol";

/// @title OmniSigil.checkAction Unit Tests
/// @author highskore.eth
/// @notice The mutating (action) evaluation path. Covers: the static-offset recipient lock and where it
///         breaks on dynamic ABI data, every {ParamCondition}, AND/OR/NOT tree composition,
///         the per-use ETH `valueLimitPerUse` cap, cumulative `isLimited` accrual, and the
///         not-initialized guard.
contract OmniSigil_checkAction_Unit_Test is OmniSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Generic single-arg selector used by the condition/tree/limit tests (offset 0 = first word).
    bytes4 internal constant SEL = 0x12345678;

    /*//////////////////////////////////////////////////////////////
                            NOT INITIALIZED
    //////////////////////////////////////////////////////////////*/

    /// @notice An action checked against an id that was never configured reverts (not silently allowed).
    function test_checkAction_revertsWhen_uninitialized() external {
        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISigilBase.PolicyNotInitialized.selector,
                ConfigId.wrap(bytes32(uint256(99))),
                address(this),
                ACCOUNT
            )
        );
        omni.checkAction(
            ConfigId.wrap(bytes32(uint256(99))), ACCOUNT, address(0), 0, _calldata1(SEL, 0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       STATIC-OFFSET RECIPIENT LOCK
    //////////////////////////////////////////////////////////////*/

    /// @notice A v2-router swap whose `to` equals the locked account passes the static-offset rule.
    function test_checkAction_v2Router_selfRecipient_passes() external {
        // Arrange
        bytes memory swap = _v2Swap(ACCOUNT);
        uint64 off = _findWordOffset(swap, bytes32(uint256(uint160(ACCOUNT))));
        assertEq(off, 96, "v2 recipient should sit at the fixed offset 96");
        _lockRecipient(off, ACCOUNT);

        // Act & Assert
        assertEq(_check(swap), VALIDATION_SUCCESS, "self-recipient swap must pass");
    }

    /// @notice The same locked rule rejects a v2-router swap routed to an attacker.
    function test_checkAction_v2Router_attackerRecipient_fails() external {
        // Arrange
        _lockRecipient(96, ACCOUNT);

        // Act & Assert
        assertEq(_check(_v2Swap(ATTACKER)), VALIDATION_FAILED, "attacker-recipient swap must fail");
    }

    /// @notice A UniversalRouter recipient lives in dynamic bytes, so its offset shifts with the
    ///         `commands` length — a rule tuned for one encoding wrongly rejects another valid one.
    function test_checkAction_universalRouter_dynamicOffset_breaks() external {
        // Arrange: two valid encodings of the same self-recipient call, differing only in commands length.
        bytes memory shapeA = _universalRouter(hex"00", ACCOUNT); // 1-byte commands
        bytes memory shapeB = _universalRouter(new bytes(33), ACCOUNT); // 33-byte commands shifts the tail
        uint64 offA = _findWordOffset(shapeA, bytes32(uint256(uint160(ACCOUNT))));
        uint64 offB = _findWordOffset(shapeB, bytes32(uint256(uint160(ACCOUNT))));
        assertTrue(offA != offB, "recipient offset must shift between valid encodings");

        // Act: lock to the offset observed for shape A.
        _lockRecipient(offA, ACCOUNT);

        // Assert: the rule holds for shape A (incl. rejecting an attacker) but breaks the legit shape B.
        assertEq(_check(shapeA), VALIDATION_SUCCESS, "shape A self-recipient passes");
        assertEq(
            _check(_universalRouter(hex"00", ATTACKER)),
            VALIDATION_FAILED,
            "shape A attacker-recipient rejected"
        );
        assertEq(
            _check(shapeB), VALIDATION_FAILED, "shape B legit call wrongly rejected by shape-A rule"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            PARAM CONDITIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice EQUAL passes when the param equals the ref.
    function test_checkAction_equal_match_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_SUCCESS, "equal match");
    }

    /// @notice EQUAL fails when the param differs from the ref.
    function test_checkAction_equal_mismatch_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(101)))), VALIDATION_FAILED, "equal mismatch");
    }

    /// @notice GREATER_THAN passes when the param is strictly greater than the ref.
    function test_checkAction_greaterThan_above_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.GREATER_THAN, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(101)))), VALIDATION_SUCCESS, "gt above");
    }

    /// @notice GREATER_THAN fails when the param equals the ref (strict).
    function test_checkAction_greaterThan_equal_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.GREATER_THAN, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_FAILED, "gt equal");
    }

    /// @notice LESS_THAN passes when the param is strictly less than the ref.
    function test_checkAction_lessThan_below_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.LESS_THAN, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(99)))), VALIDATION_SUCCESS, "lt below");
    }

    /// @notice LESS_THAN fails when the param equals the ref (strict).
    function test_checkAction_lessThan_equal_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.LESS_THAN, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_FAILED, "lt equal");
    }

    /// @notice GREATER_THAN_OR_EQUAL passes at the boundary (param == ref).
    function test_checkAction_greaterThanOrEqual_equal_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.GREATER_THAN_OR_EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_SUCCESS, "gte equal");
    }

    /// @notice GREATER_THAN_OR_EQUAL fails strictly below the ref.
    function test_checkAction_greaterThanOrEqual_below_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.GREATER_THAN_OR_EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(99)))), VALIDATION_FAILED, "gte below");
    }

    /// @notice LESS_THAN_OR_EQUAL passes at the boundary (param == ref).
    function test_checkAction_lessThanOrEqual_equal_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.LESS_THAN_OR_EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_SUCCESS, "lte equal");
    }

    /// @notice LESS_THAN_OR_EQUAL fails strictly above the ref.
    function test_checkAction_lessThanOrEqual_above_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.LESS_THAN_OR_EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(101)))), VALIDATION_FAILED, "lte above");
    }

    /// @notice NOT_EQUAL passes when the param differs from the ref.
    function test_checkAction_notEqual_different_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.NOT_EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(101)))), VALIDATION_SUCCESS, "neq different");
    }

    /// @notice NOT_EQUAL fails when the param equals the ref.
    function test_checkAction_notEqual_equal_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.NOT_EQUAL, 0, _word(uint256(100))));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_FAILED, "neq equal");
    }

    /// @notice IN_RANGE passes when the param sits inside the inclusive range.
    function test_checkAction_inRange_inside_passes() external {
        // Arrange
        _installSingle(_rule(ParamCondition.IN_RANGE, 0, _range(10, 20)));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(15)))), VALIDATION_SUCCESS, "in range");
    }

    /// @notice IN_RANGE fails below the minimum bound.
    function test_checkAction_inRange_belowMin_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.IN_RANGE, 0, _range(10, 20)));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(9)))), VALIDATION_FAILED, "below min");
    }

    /// @notice IN_RANGE fails above the maximum bound.
    function test_checkAction_inRange_aboveMax_fails() external {
        // Arrange
        _installSingle(_rule(ParamCondition.IN_RANGE, 0, _range(10, 20)));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(21)))), VALIDATION_FAILED, "above max");
    }

    /*//////////////////////////////////////////////////////////////
                           TREE COMPOSITION
    //////////////////////////////////////////////////////////////*/

    /// @notice AND passes only when both child rules pass.
    function test_checkAction_andTree_bothPass_passes() external {
        // Arrange: word0 >= 10 AND word1 <= 20.
        _installAnd();

        // Act & Assert
        assertEq(_check(_two(10, 20)), VALIDATION_SUCCESS, "both branches hold");
    }

    /// @notice AND fails when only one child rule passes.
    function test_checkAction_andTree_oneFails_fails() external {
        // Arrange
        _installAnd();

        // Act & Assert: word0 ok (>=10), word1 too big (>20).
        assertEq(_check(_two(10, 21)), VALIDATION_FAILED, "one branch fails -> AND fails");
    }

    /// @notice OR fails when neither child rule passes.
    function test_checkAction_orTree_neitherPass_fails() external {
        // Arrange: word0 >= 10 OR word1 <= 20.
        _installOr();

        // Act & Assert: word0 too small (<10) and word1 too big (>20).
        assertEq(_check(_two(9, 21)), VALIDATION_FAILED, "neither branch holds -> OR fails");
    }

    /// @notice OR passes when exactly one child rule passes.
    function test_checkAction_orTree_onePass_passes() external {
        // Arrange
        _installOr();

        // Act & Assert: word0 too small (<10) but word1 ok (<=20).
        assertEq(_check(_two(9, 20)), VALIDATION_SUCCESS, "one branch holds -> OR passes");
    }

    /// @notice NOT inverts a failing inner rule into a pass.
    function test_checkAction_notTree_innerFails_passes() external {
        // Arrange: NOT (word0 == 100).
        _installNot();

        // Act & Assert: word0 != 100 so inner fails, NOT -> pass.
        assertEq(_check(_calldata1(SEL, _word(uint256(7)))), VALIDATION_SUCCESS, "NOT of fail");
    }

    /// @notice NOT inverts a passing inner rule into a fail.
    function test_checkAction_notTree_innerPasses_fails() external {
        // Arrange
        _installNot();

        // Act & Assert: word0 == 100 so inner passes, NOT -> fail.
        assertEq(_check(_calldata1(SEL, _word(uint256(100)))), VALIDATION_FAILED, "NOT of pass");
    }

    /// @notice A nested tree ((A AND B) OR (NOT C)) passes via the left AND branch.
    function test_checkAction_nestedTree_leftBranch_passes() external {
        // Arrange
        _installNested();

        // Act & Assert: word0>=10 AND word1<=20 holds; word2 irrelevant (short-circuit OR).
        assertEq(_check(_three(10, 20, 0)), VALIDATION_SUCCESS, "left AND branch satisfies tree");
    }

    /// @notice A nested tree ((A AND B) OR (NOT C)) passes via the right NOT branch alone.
    function test_checkAction_nestedTree_rightBranch_passes() external {
        // Arrange
        _installNested();

        // Act & Assert: AND fails (word1>20) but NOT(word2==100) holds since word2 != 100.
        assertEq(_check(_three(10, 21, 7)), VALIDATION_SUCCESS, "right NOT branch satisfies tree");
    }

    /// @notice A nested tree ((A AND B) OR (NOT C)) fails when neither branch holds.
    function test_checkAction_nestedTree_neitherBranch_fails() external {
        // Arrange
        _installNested();

        // Act & Assert: AND fails (word1>20) AND NOT(word2==100) fails (word2==100).
        assertEq(_check(_three(10, 21, 100)), VALIDATION_FAILED, "neither branch satisfies tree");
    }

    /*//////////////////////////////////////////////////////////////
                          VALUE LIMIT PER USE
    //////////////////////////////////////////////////////////////*/

    /// @notice An action whose ETH value sits at the cap passes the value gate.
    function test_checkAction_valueLimit_atCap_passes() external {
        // Arrange: always-true rule, value cap of 1 ether.
        _installSingle(_rule(ParamCondition.EQUAL, 0, _word(uint256(1))), 1 ether);

        // Act & Assert
        assertEq(
            omni.checkAction(ID, ACCOUNT, address(0), 1 ether, _calldata1(SEL, _word(uint256(1)))),
            VALIDATION_SUCCESS,
            "value at cap passes"
        );
    }

    /// @notice An action whose ETH value exceeds the cap reverts before rule evaluation.
    function test_checkAction_revertsWhen_valueOverCap() external {
        // Arrange
        _installSingle(_rule(ParamCondition.EQUAL, 0, _word(uint256(1))), 1 ether);

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(OmniSigil.ValueLimitExceeded.selector, ID, 1 ether + 1, 1 ether)
        );
        omni.checkAction(ID, ACCOUNT, address(0), 1 ether + 1, _calldata1(SEL, _word(uint256(1))));
    }

    /*//////////////////////////////////////////////////////////////
                          LIMITED RULE ACCRUAL
    //////////////////////////////////////////////////////////////*/

    /// @notice A single limited use within the cumulative cap passes (and accrues).
    function test_checkAction_limited_withinCap_passes() external {
        // Arrange: word0 accrues against a cumulative limit of 100.
        _installSingle(_limitedRule(ParamCondition.LESS_THAN_OR_EQUAL, 0, _word(uint256(100)), 100));

        // Act & Assert
        assertEq(_check(_calldata1(SEL, _word(uint256(40)))), VALIDATION_SUCCESS, "40 <= 100");
    }

    /// @notice A single limited use over the cumulative cap fails.
    function test_checkAction_limited_overCap_fails() external {
        // Arrange
        _installSingle(_limitedRule(ParamCondition.LESS_THAN_OR_EQUAL, 0, _word(uint256(200)), 100));

        // Act & Assert: passes the per-call condition (<=200) but overflows the cumulative limit (100).
        assertEq(_check(_calldata1(SEL, _word(uint256(101)))), VALIDATION_FAILED, "101 > limit 100");
    }

    /// @notice Accrual carries across calls: two uses that individually fit overflow when summed.
    function test_checkAction_limited_accruesAcrossTwoCalls() external {
        // Arrange: cumulative limit 100; condition wide enough to never gate on its own.
        _installSingle(
            _limitedRule(ParamCondition.LESS_THAN_OR_EQUAL, 0, _word(uint256(1000)), 100)
        );

        // Act & Assert: first 60 accrues (used=60); second 60 would push used to 120 > 100 -> fail.
        assertEq(
            _check(_calldata1(SEL, _word(uint256(60)))), VALIDATION_SUCCESS, "first 60 accrues"
        );
        assertEq(
            _check(_calldata1(SEL, _word(uint256(60)))),
            VALIDATION_FAILED,
            "second 60 overflows accrued total"
        );
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Install AND tree: (word0 >= 10) AND (word1 <= 20).
    function _installAnd() internal {
        ParamRule[] memory rules = new ParamRule[](2);
        rules[0] = _rule(ParamCondition.GREATER_THAN_OR_EQUAL, 0, _word(uint256(10)));
        rules[1] = _rule(ParamCondition.LESS_THAN_OR_EQUAL, 32, _word(uint256(20)));
        uint256[] memory nodes = new uint256[](3);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        nodes[1] = OmniSigilTreeLib.createRuleNode(1);
        nodes[2] = OmniSigilTreeLib.createAndNode(0, 1);
        _installTree(rules, nodes, 2, type(uint256).max);
    }

    /// @dev Install OR tree: (word0 >= 10) OR (word1 <= 20).
    function _installOr() internal {
        ParamRule[] memory rules = new ParamRule[](2);
        rules[0] = _rule(ParamCondition.GREATER_THAN_OR_EQUAL, 0, _word(uint256(10)));
        rules[1] = _rule(ParamCondition.LESS_THAN_OR_EQUAL, 32, _word(uint256(20)));
        uint256[] memory nodes = new uint256[](3);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        nodes[1] = OmniSigilTreeLib.createRuleNode(1);
        nodes[2] = OmniSigilTreeLib.createOrNode(0, 1);
        _installTree(rules, nodes, 2, type(uint256).max);
    }

    /// @dev Install NOT tree: NOT (word0 == 100).
    function _installNot() internal {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = _rule(ParamCondition.EQUAL, 0, _word(uint256(100)));
        uint256[] memory nodes = new uint256[](2);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        nodes[1] = OmniSigilTreeLib.createNotNode(0);
        _installTree(rules, nodes, 1, type(uint256).max);
    }

    /// @dev Install nested tree: ((word0 >= 10 AND word1 <= 20) OR NOT(word2 == 100)).
    function _installNested() internal {
        ParamRule[] memory rules = new ParamRule[](3);
        rules[0] = _rule(ParamCondition.GREATER_THAN_OR_EQUAL, 0, _word(uint256(10)));
        rules[1] = _rule(ParamCondition.LESS_THAN_OR_EQUAL, 32, _word(uint256(20)));
        rules[2] = _rule(ParamCondition.EQUAL, 64, _word(uint256(100)));
        uint256[] memory nodes = new uint256[](6);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0); // A
        nodes[1] = OmniSigilTreeLib.createRuleNode(1); // B
        nodes[2] = OmniSigilTreeLib.createRuleNode(2); // C
        nodes[3] = OmniSigilTreeLib.createAndNode(0, 1); // A AND B
        nodes[4] = OmniSigilTreeLib.createNotNode(2); // NOT C
        nodes[5] = OmniSigilTreeLib.createOrNode(3, 4); // (A AND B) OR (NOT C)
        _installTree(rules, nodes, 5, type(uint256).max);
    }

    /// @dev calldata-shaped content with two arg words.
    function _two(uint256 w0, uint256 w1) internal pure returns (bytes memory) {
        bytes32[] memory args = new bytes32[](2);
        args[0] = bytes32(w0);
        args[1] = bytes32(w1);
        return _calldata(SEL, args);
    }

    /// @dev calldata-shaped content with three arg words.
    function _three(uint256 w0, uint256 w1, uint256 w2) internal pure returns (bytes memory) {
        bytes32[] memory args = new bytes32[](3);
        args[0] = bytes32(w0);
        args[1] = bytes32(w1);
        args[2] = bytes32(w2);
        return _calldata(SEL, args);
    }

    /// @dev Encode a v2-style `swapExactTokensForTokens` with `recipient` as the static `to` arg.
    function _v2Swap(address recipient) internal view returns (bytes memory) {
        address[] memory path = new address[](2);
        path[0] = TOKEN_IN;
        path[1] = TOKEN_OUT;
        return abi.encodeWithSignature(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            uint256(100e6),
            uint256(1),
            path,
            recipient,
            block.timestamp
        );
    }

    /// @dev Encode a UniversalRouter `execute` with `recipient` buried inside dynamic `inputs[0]`.
    function _universalRouter(
        bytes memory commands,
        address recipient
    )
        internal
        view
        returns (bytes memory)
    {
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(recipient, uint256(100e6), uint256(1), TOKEN_IN, TOKEN_OUT, true);
        return abi.encodeWithSignature(
            "execute(bytes,bytes[],uint256)", commands, inputs, block.timestamp
        );
    }
}
