// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { OmniSigil_Unit_Test } from "../OmniSigil.t.sol";

// Contracts
import { ParamCondition } from "@sigils/OmniSigil/OmniSigil.sol";

/// @title OmniSigil view-getter Unit Tests
/// @author highskore.eth
/// @notice The public mapping-getter surface: {actionConfigs} (the per-use value cap + root node index) and
///         {usageOf} (a limited rule's accrued `used` / configured `limit`). These mirror Solidity auto-getters
///         over the stored {ActionConfig}, so the SDK / a relayer can read back an installed config.
contract OmniSigil_views_Unit_Test is OmniSigil_Unit_Test {
    uint256 internal constant VALUE_CAP = 5 ether;
    uint256 internal constant RULE_LIMIT = 1000;

    /// @notice {actionConfigs} returns the configured per-use value cap and the tree's root node index.
    function test_actionConfigs_returnsValueCapAndRoot() external {
        _installSingle(_rule(ParamCondition.EQUAL, 0, _word(uint256(42))), VALUE_CAP);

        (uint256 valueLimitPerUse, uint8 rootNodeIndex) =
            omni.actionConfigs(ID, address(this), ACCOUNT);
        assertEq(valueLimitPerUse, VALUE_CAP, "value cap");
        assertEq(rootNodeIndex, 0, "root node index");
    }

    /// @notice {usageOf} returns the accrued `used` and configured `limit` after a charge accrues against a
    ///         limited rule (a GREATER_THAN_OR_EQUAL-0 rule that always matches, so only the cumulative cap
    ///         gates).
    function test_usageOf_returnsAccruedAndLimit() external {
        _installSingle(
            _limitedRule(ParamCondition.GREATER_THAN_OR_EQUAL, 0, bytes32(0), RULE_LIMIT)
        );

        // Before any charge: used == 0, limit == RULE_LIMIT.
        (uint256 used0, uint256 limit0) = omni.usageOf(ID, address(this), ACCOUNT, 0);
        assertEq(used0, 0, "used starts at 0");
        assertEq(limit0, RULE_LIMIT, "limit configured");

        // Charge 100 against the rule (param at offset 0 == 100), then read it back.
        _check(_calldata1(bytes4(0xdeadbeef), _word(uint256(100))));
        (uint256 used1, uint256 limit1) = omni.usageOf(ID, address(this), ACCOUNT, 0);
        assertEq(used1, 100, "used accrued");
        assertEq(limit1, RULE_LIMIT, "limit unchanged");
    }

    /// @notice An UNLIMITED rule reads back `(0, 0)` from {usageOf} (no usage struct populated).
    function test_usageOf_unlimitedRule_readsZero() external {
        _installSingle(_rule(ParamCondition.EQUAL, 0, _word(uint256(42))));

        (uint256 used, uint256 limit) = omni.usageOf(ID, address(this), ACCOUNT, 0);
        assertEq(used, 0, "unlimited used is 0");
        assertEq(limit, 0, "unlimited limit is 0");
    }
}
