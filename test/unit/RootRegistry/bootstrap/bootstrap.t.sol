// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RootRegistry_Unit_Test } from "../RootRegistry.t.sol";

// Interfaces
import { IRootRegistry } from "@interfaces/IRootRegistry.sol";

/// @title RootRegistry bootstrap (genesis ROOT set) Unit Tests
/// @author highskore.eth
/// @notice The account-init install path: a scheme installed at genesis is active *immediately* — an
///         installed scheme is always active, there is no activation delay. Backs `Daimon.initialize`'s
///         ROOT set.
contract RootRegistry_bootstrap_Unit_Test is RootRegistry_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A bootstrapped scheme is recorded as installed.
    function test_bootstrapRoot_marksInstalled() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        assertTrue(registry.isRootInstalled(address(validatorA)), "scheme installed");
    }

    /// @notice A bootstrapped scheme appears in the OR-set listing.
    function test_bootstrapRoot_listsInValidators() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        address[] memory vs = registry.rootValidators();
        assertEq(vs.length, 1, "one scheme listed");
        assertEq(vs[0], address(validatorA), "the bootstrapped scheme");
    }

    /// @notice A bootstrapped scheme is active immediately — installed == active.
    function test_bootstrapRoot_activeImmediately() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        assertTrue(registry.isRootInstalled(address(validatorA)), "active at once");
    }

    /// @notice Bootstrap forwards init data so the scheme stores the account's credential.
    function test_bootstrapRoot_initializesCredential() external {
        // Arrange & Act
        registry.installRoot(address(validatorA), _initData(signerA));

        // Assert
        assertEq(validatorA.signerOf(address(registry)), signerA, "credential set for the account");
    }

    /// @notice Bootstrap emits the install event.
    function test_bootstrapRoot_emitsInstalled() external {
        // Arrange
        vm.expectEmit(true, true, true, true, address(registry));
        emit IRootRegistry.RootValidatorInstalled(address(validatorA));

        // Act
        registry.installRoot(address(validatorA), _initData(signerA));
    }

    /// @notice A signature from the bootstrapped signer authorizes immediately (no warp needed).
    function test_bootstrapRoot_authorizesAtOnce() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        bytes memory sig = _sign(signerAPk, DIGEST);

        // Act & Assert
        assertTrue(
            registry.isOwnerExplicit(address(validatorA), DIGEST, sig), "signer authorizes at once"
        );
    }

    /// @notice Bootstrapping an already-installed scheme reverts.
    function test_bootstrapRoot_revertsWhen_alreadyInstalled() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(IRootRegistry.RootAlreadyInstalled.selector, address(validatorA))
        );
        registry.installRoot(address(validatorA), _initData(signerA));
    }
}
