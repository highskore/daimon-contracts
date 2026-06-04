// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { WebAuthnValidator_Unit_Test } from "../WebAuthnValidator.t.sol";

// Contracts
import { WebAuthnValidator } from "@validators/WebAuthnValidator.sol";

/// @title WebAuthnValidator.onInstall Unit Tests
/// @author highskore.eth
/// @notice Credential install/teardown: the account's passkey is `abi.encode(bytes32 x, bytes32 y)`, stored
///         keyed by the calling account. A *half-zero* key (either coordinate zero) is rejected — a zero
///         coordinate is never a valid P256 point and would collide with the "uninstalled" sentinel that
///         `isValidSignature` keys on. Uninstall clears it.
contract WebAuthnValidator_onInstall_Unit_Test is WebAuthnValidator_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A fully non-zero key is stored keyed by the calling account.
    function test_onInstall_setsPubKey() external {
        // Arrange & Act
        validator.onInstall(_pubKey(PUBKEY_X, PUBKEY_Y));

        // Assert
        (bytes32 x, bytes32 y) = validator.pubKeyOf(address(this));
        assertEq(x, PUBKEY_X, "x stored");
        assertEq(y, PUBKEY_Y, "y stored");
    }

    /// @notice A key with x == 0 (half-zero) is rejected.
    function test_onInstall_revertsWhen_xZero() external {
        // Act & Assert
        vm.expectRevert(WebAuthnValidator.InvalidPubKey.selector);
        validator.onInstall(_pubKey(bytes32(0), PUBKEY_Y));
    }

    /// @notice A key with y == 0 (half-zero) is rejected.
    function test_onInstall_revertsWhen_yZero() external {
        // Act & Assert
        vm.expectRevert(WebAuthnValidator.InvalidPubKey.selector);
        validator.onInstall(_pubKey(PUBKEY_X, bytes32(0)));
    }

    /// @notice A fully zero key is rejected.
    function test_onInstall_revertsWhen_bothZero() external {
        // Act & Assert
        vm.expectRevert(WebAuthnValidator.InvalidPubKey.selector);
        validator.onInstall(_pubKey(bytes32(0), bytes32(0)));
    }

    /// @notice Uninstall clears the stored key.
    function test_onUninstall_clearsPubKey() external {
        // Arrange
        validator.onInstall(_pubKey(PUBKEY_X, PUBKEY_Y));
        (bytes32 x0,) = validator.pubKeyOf(address(this));
        assertEq(x0, PUBKEY_X, "precondition: key set");

        // Act
        validator.onUninstall("");

        // Assert
        (bytes32 x, bytes32 y) = validator.pubKeyOf(address(this));
        assertEq(x, bytes32(0), "x cleared");
        assertEq(y, bytes32(0), "y cleared");
    }
}
