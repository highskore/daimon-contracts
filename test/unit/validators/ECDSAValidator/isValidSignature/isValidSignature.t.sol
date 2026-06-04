// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { ECDSAValidator_Unit_Test } from "../ECDSAValidator.t.sol";

/// @title ECDSAValidator.isValidSignature Unit Tests
/// @author highskore.eth
/// @notice The verification path: a plain secp256k1 signature packed `[r][s][v]` (the layout solady's
///         recovery expects) is valid iff it recovers to the account's installed signer. A wrong signer, a
///         wrong digest, or an account with no installed signer all return false (never revert).
contract ECDSAValidator_isValidSignature_Unit_Test is ECDSAValidator_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A valid [r,s,v] signature from the installed signer verifies.
    function test_isValidSignature_rightSigner_true() external {
        // Arrange
        validator.onInstall(abi.encode(signer));
        bytes memory sig = _sign(signerPk, DIGEST);

        // Act & Assert
        assertTrue(
            validator.isValidSignature(address(this), DIGEST, sig), "installed signer verifies"
        );
    }

    /// @notice A signature from a different signer is rejected.
    function test_isValidSignature_wrongSigner_false() external {
        // Arrange
        validator.onInstall(abi.encode(signer));
        bytes memory sig = _sign(attackerPk, DIGEST);

        // Act & Assert
        assertFalse(validator.isValidSignature(address(this), DIGEST, sig), "wrong signer rejected");
    }

    /// @notice A signature over a different digest is rejected.
    function test_isValidSignature_wrongDigest_false() external {
        // Arrange
        validator.onInstall(abi.encode(signer));
        bytes memory sig = _sign(signerPk, keccak256("other"));

        // Act & Assert
        assertFalse(
            validator.isValidSignature(address(this), DIGEST, sig), "mismatched digest rejected"
        );
    }

    /// @notice An account with no installed signer rejects any signature.
    function test_isValidSignature_notInstalled_false() external {
        // Arrange — no onInstall; sign with a valid key
        bytes memory sig = _sign(signerPk, DIGEST);

        // Act & Assert
        assertFalse(
            validator.isValidSignature(address(this), DIGEST, sig), "no credential -> false"
        );
    }
}
