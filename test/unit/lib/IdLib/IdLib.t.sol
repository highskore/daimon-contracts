// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { LibHarness } from "@test/mock/LibHarness.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Types
import { Mandate, MandateId, ActionId } from "@types/MandateTypes.sol";

/// @title IdLib Unit Tests
/// @author highskore.eth
/// @notice The pure id derivations used by the MANDATE layer: mandate ids (from session config + salt),
///         action ids (from target + selector), and per-(mandate, action) config ids.
contract IdLib_Unit_Test is Test {
    LibHarness internal h;

    function setUp() public {
        h = new LibHarness();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The same mandate always derives the same id.
    function test_toMandateId_isDeterministic() external view {
        Mandate memory m = _mandate(bytes32(uint256(1)));
        assertEq(
            MandateId.unwrap(h.toMandateId(m)), MandateId.unwrap(h.toMandateId(m)), "stable id"
        );
    }

    /// @notice A different salt yields a different mandate id.
    function test_toMandateId_saltChangesId() external view {
        assertTrue(
            MandateId.unwrap(h.toMandateId(_mandate(bytes32(uint256(1)))))
                != MandateId.unwrap(h.toMandateId(_mandate(bytes32(uint256(2))))),
            "salt must change the id"
        );
    }

    /// @notice A different selector yields a different action id.
    function test_toActionId_selectorChangesId() external view {
        assertTrue(
            ActionId.unwrap(h.toActionId(address(0xA), 0x11111111))
                != ActionId.unwrap(h.toActionId(address(0xA), 0x22222222)),
            "selector must change the id"
        );
    }

    /// @notice The same (mandateId, actionId) always derives the same config id.
    function test_toConfigId_isDeterministic() external view {
        MandateId pid = h.toMandateId(_mandate(bytes32(0)));
        ActionId aid = h.toActionId(address(0xB), 0x33333333);
        assertEq(
            ConfigId.unwrap(h.toConfigId(pid, aid)),
            ConfigId.unwrap(h.toConfigId(pid, aid)),
            "stable config id"
        );
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A minimal mandate; `toMandateId` keys only on validator + initData + salt.
    function _mandate(bytes32 salt) internal pure returns (Mandate memory m) {
        m.sessionValidator = ISessionValidator(address(0xCAFE));
        m.sessionValidatorInitData = abi.encode(address(0xBEEF));
        m.salt = salt;
    }
}
