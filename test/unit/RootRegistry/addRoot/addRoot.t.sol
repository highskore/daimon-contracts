// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RootRegistry_Unit_Test } from "../RootRegistry.t.sol";

// Interfaces
import { IRootRegistry } from "@interfaces/IRootRegistry.sol";

/// @title RootRegistry._installRoot Unit Tests
/// @author highskore.eth
/// @notice The post-bootstrap install path: a scheme added here is active immediately — there is no
///         activation delay, so the scheme can authorize the moment it is installed. The scheme is
///         installed and credential-bound in the same call. Backs `Daimon.installRoot`.
contract RootRegistry_addRoot_Unit_Test is RootRegistry_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice An added scheme is recorded as installed immediately.
    function test_installRoot_marksInstalled() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        assertTrue(registry.isRootInstalled(address(validatorA)), "scheme installed immediately");
    }

    /// @notice Install forwards init data so the scheme stores the account's credential up front.
    function test_installRoot_initializesCredential() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        assertEq(validatorA.signerOf(address(registry)), signerA, "credential set at add time");
    }

    /// @notice Install emits the install event.
    function test_installRoot_emitsInstalled() external {
        // Arrange
        vm.expectEmit(true, true, true, true, address(registry));
        emit IRootRegistry.RootValidatorInstalled(address(validatorA));

        // Act
        registry.installRoot(address(validatorA), _initData(signerA));
    }

    /// @notice An added scheme is active the moment it is installed (no timelock).
    function test_installRoot_activeImmediately() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        assertTrue(registry.isRootInstalled(address(validatorA)), "active at once");
    }

    /// @notice The owner-check authorizes the added signer's signature immediately on install.
    function test_installRoot_ownerCheckTrueImmediately() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        bytes memory sig = _sign(signerAPk, DIGEST);

        // Act & Assert
        assertTrue(
            registry.isOwnerExplicit(address(validatorA), DIGEST, sig),
            "added signer authorizes immediately"
        );
    }

    /// @notice Adding an already-installed scheme reverts.
    function test_installRoot_revertsWhen_alreadyInstalled() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(IRootRegistry.RootAlreadyInstalled.selector, address(validatorA))
        );
        registry.installRoot(address(validatorA), _initData(signerA));
    }
}
