// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { ECDSAValidator_Unit_Test } from "../ECDSAValidator.t.sol";

// Contracts
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";

/// @title ECDSAValidator.onInstall Unit Tests
/// @author highskore.eth
/// @notice Credential install/teardown: the account's signer is `abi.encode(address)`, stored keyed by the
///         calling account (`msg.sender`). A zero signer is rejected; uninstall clears it.
contract ECDSAValidator_onInstall_Unit_Test is ECDSAValidator_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A valid signer is stored keyed by the calling account.
    function test_onInstall_setsSigner() external {
        // Arrange & Act
        validator.onInstall(abi.encode(signer));

        // Assert
        assertEq(validator.signerOf(address(this)), signer, "signer stored for the account");
    }

    /// @notice Installing the zero address as signer reverts.
    function test_onInstall_revertsWhen_zeroSigner() external {
        // Act & Assert
        vm.expectRevert(ECDSAValidator.InvalidSigner.selector);
        validator.onInstall(abi.encode(address(0)));
    }

    /// @notice Uninstall clears the stored signer.
    function test_onUninstall_clearsSigner() external {
        // Arrange
        validator.onInstall(abi.encode(signer));
        assertEq(validator.signerOf(address(this)), signer, "precondition: signer set");

        // Act
        validator.onUninstall("");

        // Assert
        assertEq(validator.signerOf(address(this)), address(0), "signer cleared");
    }
}
