// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RootRegistry_Unit_Test } from "../RootRegistry.t.sol";

// Interfaces
import { IRootRegistry } from "@interfaces/IRootRegistry.sol";

/// @title RootRegistry._removeRoot Unit Tests
/// @author highskore.eth
/// @notice The uninstall path: a scheme can be torn down, but the *last* scheme is protected — its
///         removal would leave the account with no owner (bricked). The guard keys on the installed-set
///         size being 1. Backs `Daimon.removeRoot`.
contract RootRegistry_removeRoot_Unit_Test is RootRegistry_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Removing a never-installed scheme reverts.
    function test_removeRoot_revertsWhen_notInstalled() external {
        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(IRootRegistry.RootNotInstalled.selector, address(validatorA))
        );
        registry.removeRoot(address(validatorA), "");
    }

    /// @notice Removing the sole scheme reverts (would brick the account).
    function test_removeRoot_revertsWhen_last() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));

        // Act & Assert
        vm.expectRevert(IRootRegistry.CannotRemoveLastRoot.selector);
        registry.removeRoot(address(validatorA), "");
    }

    /// @notice With two schemes, removing one uninstalls it and clears its credential.
    function test_removeRoot_oneOfTwo_uninstalls() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        registry.installRoot(address(validatorB), _initData(signerB));

        // Act
        registry.removeRoot(address(validatorA), "");

        // Assert
        assertFalse(registry.isRootInstalled(address(validatorA)), "removed scheme uninstalled");
        assertEq(validatorA.signerOf(address(registry)), address(0), "credential cleared");
    }

    /// @notice With two schemes, removing one leaves the other installed (and thus active).
    function test_removeRoot_oneOfTwo_keepsOther() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        registry.installRoot(address(validatorB), _initData(signerB));

        // Act
        registry.removeRoot(address(validatorA), "");

        // Assert
        assertTrue(registry.isRootInstalled(address(validatorB)), "other scheme still installed");
        assertEq(registry.rootValidators().length, 1, "one scheme remains");
    }

    /// @notice Removal emits the uninstall event.
    function test_removeRoot_emitsUninstalled() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        registry.installRoot(address(validatorB), _initData(signerB));
        vm.expectEmit(true, true, true, true, address(registry));
        emit IRootRegistry.RootValidatorUninstalled(address(validatorA));

        // Act
        registry.removeRoot(address(validatorA), "");
    }
}
