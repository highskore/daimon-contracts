// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { OmniSigil } from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Types
import {
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/lib/OmniSigilTypes.sol";

// Interfaces
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title OmniSigil_Symbolic_Test — machine-proven ∀-calldata arg-policy soundness (RESTRICTED)
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) that {OmniSigil}'s calldata-argument gate cannot be
///         bypassed by ANY calldata, for a RESTRICTED single-rule tree:
///        1. {check_checkAction_recipientLock_notBypassable}: a recipient-locked leaf (one EQUAL rule
///           at offset 0) permits the action ⟺ the symbolic calldata arg EQUALS the locked value — so
///           no calldata word can route the call anywhere but the locked recipient.
///        2. {check_checkAction_limitedRule_boundsUsage}: the {LimitUsage} bound — a single
///           `isLimited` rule (used == 0) permits the action ⟺ `param <= limit`, i.e. SUCCESS ⟹
///           `used + param <= limit`. Proven over a symbolic `param` and a symbolic `limit`.
/// @dev WHY RESTRICTED (documented limitation): {OmniSigil} reads a 32-byte word at a STATIC offset
///      `data[4+offset:36+offset]` and evaluates an arbitrarily-shaped AND/OR/NOT tree over a fully
///      DYNAMIC `bytes calldata`. A general proof over symbolic dynamic-length calldata + a symbolic
///      rule tree blows up the solver (symbolic slicing of variable-length bytes + a recursive
///      packed-node interpreter). We therefore prove the SOUNDNESS of the security-critical leaf
///      shapes — a recipient lock and a usage limit — over a FIXED-SHAPE calldata (`selector ++ one
///      32-byte word`, the word symbolic) and a FIXED single-leaf tree. This is exactly the shape a
///      real recipient-lock / amount-cap mandate compiles to. The general N-rule tree over fully
///      symbolic dynamic calldata is left deferred (needs a tool with first-class dynamic-bytes
///      reasoning, e.g. Certora) — see the symbolic README.
///
///      SYMBOLIC BOUND:
///        - Calldata is FIXED 36 bytes: a concrete 4-byte selector ++ one SYMBOLIC 32-byte word. The
///          arg word is fully symbolic (2^256 values); only the length is concrete (so the static
///          `data[4:36]` slice is well-defined and the solver does not branch on length).
///        - The rule tree is a FIXED single leaf node referencing one rule. AND/OR/NOT composition and
///          multi-rule trees are out of scope of THIS proof (deferred).
contract OmniSigil_Symbolic_Test is Test {
    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0x7A86E7);
    bytes4 internal constant SEL = 0x12345678;

    OmniSigil internal sigil;

    function setUp() public {
        sigil = new OmniSigil();
    }

    /// @notice ∀ calldata arg word: a recipient-locked EQUAL leaf permits the action ⟺ the arg equals
    ///         the (symbolic) locked recipient. No calldata can bypass the lock.
    /// @param locked The symbolic locked recipient value (the rule's `ref`).
    /// @param arg The symbolic 32-byte calldata argument at offset 0.
    function check_checkAction_recipientLock_notBypassable(bytes32 locked, bytes32 arg) public {
        // One unlimited EQUAL rule at offset 0, ref == locked, wrapped in a single leaf node.
        _installSingleEqual(locked);

        // Fixed-shape calldata: selector ++ the symbolic arg word (36 bytes, only content symbolic).
        bytes memory data = abi.encodePacked(SEL, arg);
        uint256 code = sigil.checkAction(ID, ACCOUNT, TARGET, 0, data);

        // SUCCESS iff the supplied arg equals the locked recipient — the lock binds, ∀ calldata.
        assert((code == VALIDATION_SUCCESS) == (arg == locked));
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }

    /// @notice ∀ (limit, arg): a single LIMITED rule (used == 0, primary condition always-true)
    ///         permits the action ⟺ `param <= limit` — the {LimitUsage} bound `used + param <= limit`.
    /// @param limit The symbolic cumulative cap.
    /// @param arg The symbolic 32-byte calldata argument at offset 0 (the accrued `param`).
    function check_checkAction_limitedRule_boundsUsage(uint256 limit, uint256 arg) public {
        // A limited rule whose PRIMARY condition is always true (GTE 0), so only the limit gate decides.
        // used starts at 0, so the gate is exactly `param <= limit`.
        _installSingleLimited(limit);

        bytes memory data = abi.encodePacked(SEL, bytes32(arg));
        uint256 code = sigil.checkAction(ID, ACCOUNT, TARGET, 0, data);

        // SUCCESS iff under the cumulative cap (used == 0 ⟹ param <= limit).
        assert((code == VALIDATION_SUCCESS) == (arg <= limit));
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }

    /*·:⛧:·──────── CONFIG BUILDERS ────────:⛧:·*/

    /// @dev Install one unlimited EQUAL rule at offset 0 with ref `ref`, as a single-leaf tree.
    function _installSingleEqual(bytes32 ref) internal {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0,
            isLimited: false,
            ref: ref,
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);

        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });
        sigil.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @dev Install one LIMITED rule (used == 0, cap `limit`) whose primary condition is always true
    ///      (GREATER_THAN_OR_EQUAL ref 0 — every uint256 is >= 0), so only the usage gate decides.
    function _installSingleLimited(uint256 limit) internal {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.GREATER_THAN_OR_EQUAL,
            offset: 0,
            isLimited: true,
            ref: bytes32(0),
            usage: LimitUsage({ limit: limit, used: 0 })
        });
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);

        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: 0,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });
        sigil.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }
}
