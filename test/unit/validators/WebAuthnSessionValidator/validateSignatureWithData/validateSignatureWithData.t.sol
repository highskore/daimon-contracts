// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { WebAuthnSessionValidator_Unit_Test } from "../WebAuthnSessionValidator.t.sol";

/// @title WebAuthnSessionValidator.validateSignatureWithData Unit Tests
/// @author highskore.eth
/// @notice The stateless P256/passkey session-verification path. A genuine assertion over the challenge
///         verifies (the base etches the P256 verifier); an all-zero/half-zero pubkey, a mismatched challenge,
///         or a well-formed-but-invalid assertion all return false; an undecodable signature or credential
///         reverts.
contract WebAuthnSessionValidator_validateSignatureWithData_Unit_Test is
    WebAuthnSessionValidator_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A genuine P256 assertion over the challenge verifies (UP|UV set, user-verification required).
    function test_validateSignatureWithData_validAssertion_true() external view {
        // Act & Assert
        assertTrue(
            validator.validateSignatureWithData(
                DIGEST, FIXTURE_SIG, _cred(FIXTURE_X, FIXTURE_Y, true)
            ),
            "valid passkey assertion verifies"
        );
    }

    /// @notice The same valid assertion also verifies when user-verification is not required (UV bit present).
    function test_validateSignatureWithData_validAssertion_noUVRequired_true() external view {
        // Act & Assert
        assertTrue(
            validator.validateSignatureWithData(
                DIGEST, FIXTURE_SIG, _cred(FIXTURE_X, FIXTURE_Y, false)
            ),
            "valid assertion verifies when UV optional"
        );
    }

    /// @notice The valid assertion is rejected against a DIFFERENT challenge (the challenge binds the digest).
    function test_validateSignatureWithData_wrongChallenge_false() external view {
        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(
                keccak256("other"), FIXTURE_SIG, _cred(FIXTURE_X, FIXTURE_Y, true)
            ),
            "assertion over a different challenge rejected"
        );
    }

    /// @notice An all-zero pubkey (the empty/uninstalled sentinel) rejects any signature.
    function test_validateSignatureWithData_zeroPubKey_false() external view {
        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(
                DIGEST, FIXTURE_SIG, _cred(bytes32(0), bytes32(0), true)
            ),
            "zero pubkey -> false"
        );
    }

    /// @notice A half-zero pubkey (x set, y == 0) is a degenerate credential rejected by the OR guard
    ///         (mirroring {WebAuthnValidator.onInstall}), short-circuiting before WebAuthn.verify.
    function test_validateSignatureWithData_partialZeroPubKey_yZero_false() external view {
        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(
                DIGEST, FIXTURE_SIG, _cred(FIXTURE_X, bytes32(0), true)
            ),
            "half-zero (y==0) pubkey rejected by OR guard"
        );
    }

    /// @notice The symmetric half-zero case (x == 0, y set) is likewise rejected by the OR guard.
    function test_validateSignatureWithData_partialZeroPubKey_xZero_false() external view {
        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(
                DIGEST, FIXTURE_SIG, _cred(bytes32(0), FIXTURE_Y, true)
            ),
            "half-zero (x==0) pubkey rejected by OR guard"
        );
    }

    /// @notice The OR guard SHORT-CIRCUITS before signature decode: a half-zero pubkey returns false even with
    ///         an undecodable signature blob that would otherwise revert in `abi.decode` (proves the guard runs
    ///         first, not merely a downstream verify rejection).
    function test_validateSignatureWithData_partialZeroPubKey_shortCircuitsBeforeDecode()
        external
        view
    {
        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(
                DIGEST, hex"01", _cred(bytes32(0), FIXTURE_Y, true)
            ),
            "half-zero pubkey short-circuits before signature decode"
        );
    }

    /// @notice With a real pubkey, a well-formed but invalid assertion verifies to false (no revert).
    function test_validateSignatureWithData_malformedAuth_false() external view {
        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(
                DIGEST, _malformedAuth(), _cred(PUBKEY_X, PUBKEY_Y, true)
            ),
            "invalid assertion -> false"
        );
    }

    /// @notice A signature blob that cannot be ABI-decoded as a WebAuthnAuth reverts.
    function test_validateSignatureWithData_revertsWhen_undecodableSignature() external {
        // Act & Assert
        vm.expectRevert();
        validator.validateSignatureWithData(DIGEST, hex"01", _cred(PUBKEY_X, PUBKEY_Y, true));
    }

    /// @notice A credential blob that cannot be ABI-decoded as `(x, y, requireUV)` reverts.
    function test_validateSignatureWithData_revertsWhen_undecodableData() external {
        // Act & Assert
        vm.expectRevert();
        validator.validateSignatureWithData(DIGEST, _malformedAuth(), hex"01");
    }
}
