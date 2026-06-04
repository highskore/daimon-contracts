// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { ECDSASessionValidator_Unit_Test } from "../ECDSASessionValidator.t.sol";

/// @title ECDSASessionValidator.validateSignatureWithData Unit Tests
/// @author highskore.eth
/// @notice The stateless session-key verification path: the signer is decoded from `data`
///         (`abi.encode(address)`) on every call, and the [r,s,v]-packed signature must recover to it over
///         `hash`. Wrong signer, wrong hash, or a zero-address credential all return false.
contract ECDSASessionValidator_validateSignatureWithData_Unit_Test is
    ECDSASessionValidator_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A valid signature from the encoded signer over the hash verifies.
    function test_validateSignatureWithData_rightSigner_true() external view {
        // Arrange
        bytes memory data = abi.encode(agent);
        bytes memory sig = _sign(agentPk, DIGEST);

        // Act & Assert
        assertTrue(
            validator.validateSignatureWithData(DIGEST, sig, data), "encoded signer verifies"
        );
    }

    /// @notice A signature from a different signer is rejected.
    function test_validateSignatureWithData_wrongSigner_false() external view {
        // Arrange
        bytes memory data = abi.encode(agent);
        bytes memory sig = _sign(attackerPk, DIGEST);

        // Act & Assert
        assertFalse(validator.validateSignatureWithData(DIGEST, sig, data), "wrong signer rejected");
    }

    /// @notice A signature over a different hash is rejected.
    function test_validateSignatureWithData_wrongHash_false() external view {
        // Arrange
        bytes memory data = abi.encode(agent);
        bytes memory sig = _sign(agentPk, keccak256("other"));

        // Act & Assert
        assertFalse(
            validator.validateSignatureWithData(DIGEST, sig, data), "mismatched hash rejected"
        );
    }

    /// @notice A zero-address credential is rejected outright.
    function test_validateSignatureWithData_zeroSigner_false() external view {
        // Arrange
        bytes memory data = abi.encode(address(0));
        bytes memory sig = _sign(agentPk, DIGEST);

        // Act & Assert
        assertFalse(validator.validateSignatureWithData(DIGEST, sig, data), "zero signer rejected");
    }
}
