// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

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

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Handlers
import { OmniSigilLimitHandler } from "./OmniSigilLimitHandler.sol";

/// @title OmniSigil LimitUsage Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the OmniSigil cumulative-arg-cap (`isLimited` rule) SAFETY: across any
///         sequence of charges, the on-chain `used` (1) never exceeds the limit and (2) always equals an
///         independently-tracked ghost. Unlike SpendSigil there is no rolling window — `used` is a monotone
///         running total with no reset — so the proof is the cumulative cap itself.
/// @dev FALSIFICATION PROTOCOL (these invariants are designed to FAIL on a broken SUT):
///        - Delete the `if (rule.usage.used + param > rule.usage.limit) return false;` guard in
///          {OmniSigilTreeLib} → the handler's "LIMIT BYPASSED" oracle + {invariant_usedNeverExceedsLimit} trip.
///        - Delete the `rule.usage.used += param` accrual → the ghost climbs while on-chain `used` stays 0 →
///          {invariant_usedMatchesGhost} trips (and eventually "LIMIT BYPASSED" once the ghost passes the limit
///          but the contract keeps accepting).
contract OmniSigil_Invariant_Test is Test {
    OmniSigil internal sigil;
    OmniSigilLimitHandler internal handler;

    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0x11)));
    uint256 internal constant LIMIT = 1000e18;

    function setUp() public {
        sigil = new OmniSigil();
        handler = new OmniSigilLimitHandler(sigil, CID, LIMIT);

        // A single LIMITED rule on offset 0: condition GREATER_THAN_OR_EQUAL 0 (always true on the param), so
        // only the cumulative `isLimited` cap gates acceptance. The handler is the multiplexer (msg.sender ==
        // this test contract here at config time) — so configure with this contract as multiplexer + account,
        // and the handler calls checkAction with that same (multiplexer, account) pair.
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.GREATER_THAN_OR_EQUAL,
            offset: 0,
            isLimited: true,
            ref: bytes32(0),
            usage: LimitUsage({ limit: LIMIT, used: 0 })
        });
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: type(uint256).max,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        // multiplexer == msg.sender == account == the handler (the engine's baked-in runtime). Configure AS the
        // handler so checkAction's (id, msg.sender, account) keying matches.
        vm.prank(address(handler));
        sigil.initializeWithMultiplexer(address(handler), CID, abi.encode(cfg));

        targetContract(address(handler));
    }

    /// @notice SAFETY: the rule's cumulative `used` never exceeds its limit, whatever the charge sequence.
    function invariant_usedNeverExceedsLimit() public view {
        (uint256 used,) = sigil.usageOf(CID, address(handler), address(handler), 0);
        assertLe(used, LIMIT, "used exceeded limit");
    }

    /// @notice CORRECTNESS: on-chain `used` exactly equals the independent ghost (Σ accepted charges).
    function invariant_usedMatchesGhost() public view {
        (uint256 used,) = sigil.usageOf(CID, address(handler), address(handler), 0);
        assertEq(used, handler.ghostUsed(), "used diverged from ghost");
    }

    /// @notice COVERAGE: the fuzz actually reached both branches — accepted charges AND over-limit denials.
    function afterInvariant() public view {
        assertGt(handler.successfulCharges(), 0, "no accepted charges explored");
        assertGt(handler.deniedCharges(), 0, "no over-limit denials explored");
    }
}
