// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { WebAuthnValidator_Unit_Test } from "../WebAuthnValidator.t.sol";

/// @title WebAuthnValidator.isValidSignature Unit Tests
/// @author highskore.eth
/// @notice The P256/passkey verification path. An account with no installed key returns false (the
///         all-zero pubkey is the uninstalled sentinel). With a key installed, a well-formed but
///         cryptographically invalid {WebAuthn.WebAuthnAuth} verifies to false (no revert), while a blob
///         that cannot even be ABI-decoded as that struct reverts.
/// @dev KNOWN GAP — the full valid-P256 happy path (a real (x, y) + a genuine secp256r1 signature over the
///      challenge returning *true*) is NOT covered here. Producing a valid WebAuthn assertion needs a P256
///      signing fixture (the solady test vectors / a JS-side authenticator), which is not wired into this
///      repo's test deps. Marked explicitly rather than faked. See the `.tree` leaf tagged [KNOWN GAP].
contract WebAuthnValidator_isValidSignature_Unit_Test is WebAuthnValidator_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice An account with no installed pubkey rejects any signature (uninstalled sentinel).
    function test_isValidSignature_notInstalled_false() external view {
        // Arrange — no onInstall; supply a structurally valid (but invalid) auth blob
        bytes memory sig = _malformedAuth();

        // Act & Assert
        assertFalse(
            validator.isValidSignature(address(this), DIGEST, sig), "no credential -> false"
        );
    }

    /// @notice With a key installed, a well-formed but invalid WebAuthnAuth verifies to false (no revert).
    function test_isValidSignature_malformedAuth_false() external {
        // Arrange
        validator.onInstall(_pubKey(PUBKEY_X, PUBKEY_Y));
        bytes memory sig = _malformedAuth();

        // Act & Assert
        assertFalse(
            validator.isValidSignature(address(this), DIGEST, sig),
            "invalid assertion verifies to false"
        );
    }

    /// @notice A signature blob that cannot be ABI-decoded as a WebAuthnAuth reverts.
    function test_isValidSignature_revertsWhen_undecodable() external {
        // Arrange
        validator.onInstall(_pubKey(PUBKEY_X, PUBKEY_Y));
        // Too short to hold the struct's head (dynamic-field offsets) -> abi.decode reverts.
        bytes memory garbage = hex"01";

        // Act & Assert
        vm.expectRevert();
        validator.isValidSignature(address(this), DIGEST, garbage);
    }
}
