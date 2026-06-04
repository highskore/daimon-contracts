// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { LibHarness } from "@test/mock/LibHarness.sol";

/// @title ModeLib Unit Tests
/// @author highskore.eth
/// @notice The modal-dispatch bytes shared by the account, the engine, and the SDK. Pinning the values
///         here guards against drift in the on-chain dispatch.
contract ModeLib_Unit_Test is Test {
    LibHarness internal h;

    function setUp() public {
        h = new LibHarness();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The mode bytes match the documented dispatch (ROOT/MANDATE, USE/BIND).
    function test_modeBytes_matchTheDispatch() external view {
        assertEq(uint256(h.modeRoot()), 0, "MODE_ROOT");
        assertEq(uint256(h.modeMandate()), 1, "MODE_MANDATE");
        assertEq(uint256(h.mandateUse()), 0, "MANDATE_USE");
        assertEq(uint256(h.mandateBind()), 1, "MANDATE_BIND");
    }
}
