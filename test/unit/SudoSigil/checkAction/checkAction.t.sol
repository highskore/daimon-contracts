// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SudoSigil_Unit_Test } from "../SudoSigil.t.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title SudoSigil.checkAction Unit Tests
/// @author highskore.eth
/// @notice The action evaluation path of the allow-all sigil: it returns success for ANY calldata (including
///         empty and 4-byte selector-only calldata, which OmniSigil's reverting slice cannot read) and ANY
///         ETH value, reading no calldata and reverting on nothing — even when never initialized.
contract SudoSigil_checkAction_Unit_Test is SudoSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev A 4-byte selector used to shape selector-only calldata.
    bytes4 internal constant SEL = 0x12345678;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice An arbitrary multi-word calldata payload is permitted.
    function test_checkAction_arbitraryData_returnsSuccess() external view {
        bytes memory data = abi.encodePacked(SEL, uint256(0xdead), uint256(0xbeef), address(this));
        assertEq(
            sudo.checkAction(ID, ACCOUNT, TARGET, 0, data),
            VALIDATION_SUCCESS,
            "arbitrary calldata must be allowed"
        );
    }

    /// @notice Selector-only calldata (a 0-argument call) is permitted — the case OmniSigil's `data[4:36]`
    ///         slice reverts on.
    function test_checkAction_selectorOnly_returnsSuccess() external view {
        assertEq(
            sudo.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "4-byte (0-arg) calldata must be allowed"
        );
    }

    /// @notice Fully empty calldata is permitted (no revert reading a non-existent word).
    function test_checkAction_emptyData_returnsSuccess() external view {
        assertEq(
            sudo.checkAction(ID, ACCOUNT, TARGET, 0, ""),
            VALIDATION_SUCCESS,
            "empty calldata must be allowed"
        );
    }

    /// @notice A non-zero ETH value is permitted — the allow-all sigil enforces no value cap.
    function test_checkAction_withValue_returnsSuccess() external view {
        assertEq(
            sudo.checkAction(ID, ACCOUNT, TARGET, 1 ether, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "non-zero value must be allowed"
        );
    }

    /// @notice The sigil need not be initialized: an arbitrary config id permits the action all the same
    ///         (there is no `PolicyNotInitialized` guard — uninitialized and initialized behave identically).
    function test_checkAction_uninitializedId_returnsSuccess() external view {
        ConfigId unconfigured = ConfigId.wrap(bytes32(uint256(0xFFFF)));
        assertEq(
            sudo.checkAction(unconfigured, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "an unconfigured id must still be allowed"
        );
    }

    /// @notice Fuzz: any calldata, any value, any caller-shaped inputs return success and never revert.
    function testFuzz_checkAction_alwaysSucceeds(
        bytes32 id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        view
    {
        assertEq(
            sudo.checkAction(ConfigId.wrap(id), account, target, value, data),
            VALIDATION_SUCCESS,
            "checkAction must always succeed"
        );
    }
}
