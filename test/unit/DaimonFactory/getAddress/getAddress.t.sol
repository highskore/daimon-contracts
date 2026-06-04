// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { DaimonFactory_Unit_Test } from "../DaimonFactory.t.sol";

// Types
import { Mandate } from "@types/MandateTypes.sol";

/// @title DaimonFactory.getAddress Unit Tests
/// @author highskore.eth
/// @notice The counterfactual address derivation: the predicted address commits to the salt, the full root
///         set, AND the genesis mandates, so changing any of them yields a different address. The mandate
///         commitment is the security crux for the no-signature genesis bind (a different mandate set is a
///         different account, so the permissionless deploy cannot be front-run to bind an attacker mandate).
contract DaimonFactory_getAddress_Unit_Test is DaimonFactory_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A different salt predicts a different address.
    function test_getAddress_differsBySalt() external view {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();

        // Act & Assert
        assertTrue(
            factory.getAddress(SALT, vs, ds, _noMandates())
                != factory.getAddress(bytes32(uint256(2)), vs, ds, _noMandates()),
            "salt must change the address"
        );
    }

    /// @notice A different root set predicts a different address (the salt commits to the owners).
    function test_getAddress_differsByRootSet() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();
        bytes[] memory ds2 = new bytes[](2);
        ds2[0] = abi.encode(makeAddr("other"));
        ds2[1] = ds[1];

        // Act & Assert
        assertTrue(
            factory.getAddress(SALT, vs, ds, _noMandates())
                != factory.getAddress(SALT, vs, ds2, _noMandates()),
            "root set must change the address"
        );
    }

    /// @notice The address commits to the genesis mandates: a different mandate set predicts a different
    ///         address, and any genesis mandate differs from none. This is the entire safety argument for
    ///         the no-signature genesis bind.
    function test_getAddress_commitsToGenesisMandates() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();
        Mandate[] memory a = _mandates(_mandate(makeAddr("recipientA"), bytes32(uint256(0xA))));
        Mandate[] memory b = _mandates(_mandate(makeAddr("recipientB"), bytes32(uint256(0xB))));

        address addrNone = factory.getAddress(SALT, vs, ds, _noMandates());
        address addrA = factory.getAddress(SALT, vs, ds, a);
        address addrB = factory.getAddress(SALT, vs, ds, b);

        // Act & Assert: every genesis-mandate set yields its own distinct address.
        assertTrue(addrA != addrB, "different mandate sets must change the address");
        assertTrue(addrA != addrNone, "a genesis mandate must differ from none");
        assertTrue(addrB != addrNone, "a genesis mandate must differ from none");
    }
}
