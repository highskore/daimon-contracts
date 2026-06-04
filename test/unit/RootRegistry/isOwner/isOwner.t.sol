// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { RootRegistry_Unit_Test } from "../RootRegistry.t.sol";

/// @title RootRegistry._isOwner Unit Tests
/// @author highskore.eth
/// @notice The shared OR-set owner-check primitive used by the direct-call / ERC-1271 ROOT path (packed
///         form) and the MANDATE bind path (explicit form). The signature names which scheme to check; that
///         scheme must be installed *and* verify the signature. The check returns false (never reverts) on
///         an unknown scheme so it composes cleanly inside signature validation.
contract RootRegistry_isOwner_Unit_Test is RootRegistry_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                            PACKED FORM
    //////////////////////////////////////////////////////////////*/

    /// @notice A packed sig shorter than the 20-byte validator prefix returns false (no revert).
    function test_isOwnerPacked_revertsWhen_tooShort_returnsFalse() external view {
        // Act & Assert
        assertFalse(registry.isOwnerPacked(DIGEST, hex"deadbeef"), "short sig rejected, no revert");
    }

    /// @notice Packed: the named active scheme verifying the signature authorizes.
    function test_isOwnerPacked_validNamedScheme_true() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        bytes memory sig = _packed(address(validatorA), signerAPk, DIGEST);

        // Act & Assert
        assertTrue(registry.isOwnerPacked(DIGEST, sig), "named active scheme authorizes");
    }

    /// @notice Packed: the named scheme rejecting the signature (wrong signer) fails.
    function test_isOwnerPacked_wrongSigner_false() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        // sign with signerB's key but name validatorA (configured for signerA)
        bytes memory sig = _packed(address(validatorA), signerBPk, DIGEST);

        // Act & Assert
        assertFalse(registry.isOwnerPacked(DIGEST, sig), "wrong signer rejected");
    }

    /// @notice Packed: naming a never-installed scheme returns false.
    function test_isOwnerPacked_notInstalled_false() external {
        // Arrange — validatorA never installed
        bytes memory sig = _packed(address(validatorA), signerAPk, DIGEST);

        // Act & Assert
        assertFalse(registry.isOwnerPacked(DIGEST, sig), "uninstalled scheme rejected");
    }

    /*//////////////////////////////////////////////////////////////
                           EXPLICIT FORM
    //////////////////////////////////////////////////////////////*/

    /// @notice Explicit: a valid signature for an active scheme authorizes.
    function test_isOwnerExplicit_valid_true() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        bytes memory sig = _sign(signerAPk, DIGEST);

        // Act & Assert
        assertTrue(
            registry.isOwnerExplicit(address(validatorA), DIGEST, sig), "valid sig authorizes"
        );
    }

    /// @notice Explicit: an invalid signature for an active scheme fails.
    function test_isOwnerExplicit_invalid_false() external {
        // Arrange
        registry.installRoot(address(validatorA), _initData(signerA));
        bytes memory sig = _sign(signerBPk, DIGEST); // wrong signer

        // Act & Assert
        assertFalse(
            registry.isOwnerExplicit(address(validatorA), DIGEST, sig), "invalid sig rejected"
        );
    }

    /// @notice Explicit: a never-installed scheme returns false.
    function test_isOwnerExplicit_notInstalled_false() external {
        // Arrange
        bytes memory sig = _sign(signerAPk, DIGEST);

        // Act & Assert
        assertFalse(
            registry.isOwnerExplicit(address(validatorA), DIGEST, sig),
            "uninstalled scheme rejected"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            OR-SET (TWO)
    //////////////////////////////////////////////////////////////*/

    /// @notice OR-set: scheme A signing and being named authorizes.
    function test_isOwner_orSet_schemeAAuthorizes() external {
        // Arrange
        _installTwoActive();
        bytes memory sig = _packed(address(validatorA), signerAPk, DIGEST);

        // Act & Assert
        assertTrue(registry.isOwnerPacked(DIGEST, sig), "A authorizes");
    }

    /// @notice OR-set: scheme B signing and being named authorizes (any active scheme works).
    function test_isOwner_orSet_schemeBAuthorizes() external {
        // Arrange
        _installTwoActive();
        bytes memory sig = _packed(address(validatorB), signerBPk, DIGEST);

        // Act & Assert
        assertTrue(registry.isOwnerPacked(DIGEST, sig), "B authorizes");
    }

    /// @notice OR-set: A's signer signing while B is named fails — the *named* scheme must verify.
    function test_isOwner_orSet_crossedNamingFails() external {
        // Arrange
        _installTwoActive();
        // signerA signs, but validatorB (configured for signerB) is named
        bytes memory sig = _packed(address(validatorB), signerAPk, DIGEST);

        // Act & Assert
        assertFalse(registry.isOwnerPacked(DIGEST, sig), "named scheme must verify the sig");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Bootstrap two active schemes (A->signerA, B->signerB).
    function _installTwoActive() internal {
        registry.installRoot(address(validatorA), _initData(signerA));
        registry.installRoot(address(validatorB), _initData(signerB));
    }

    /// @dev Pack a ROOT owner-check sig: `[20-byte validator][r,s,v]`.
    function _packed(
        address validator,
        uint256 pk,
        bytes32 hash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes20(validator), _sign(pk, hash));
    }
}
