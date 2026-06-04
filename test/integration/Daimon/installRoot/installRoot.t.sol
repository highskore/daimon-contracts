// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Contracts
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";

/// @title Daimon.installRoot Integration Tests
/// @author highskore.eth
/// @notice Covers ROOT-set growth: who may add a scheme to the set.
contract Daimon_installRoot_Integration_Test is Daimon_Integration_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The owner (the account itself, via a ROOT-authed self-call) may install a new ROOT scheme,
    ///         growing the active set.
    function test_installRoot_whenOwner_installs() external {
        // Arrange
        ECDSAValidator v3 = new ECDSAValidator();

        // Act
        vm.prank(address(daimon));
        daimon.installRoot(address(v3), abi.encode(makeAddr("signer3")));

        // Assert
        assertTrue(daimon.isRootInstalled(address(v3)), "v3 installed");
        assertEq(daimon.rootValidators().length, 3, "three roots active");
    }

    /// @notice A caller that is not the owner (the account itself) cannot install a scheme.
    function test_installRoot_revertsWhen_notOwner() external {
        // Arrange
        ECDSAValidator v3 = new ECDSAValidator();

        // Act & Assert
        vm.expectRevert();
        daimon.installRoot(address(v3), abi.encode(rootSigner));
    }
}
