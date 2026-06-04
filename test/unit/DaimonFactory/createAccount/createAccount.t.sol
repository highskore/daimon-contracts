// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { DaimonFactory_Unit_Test } from "../DaimonFactory.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";

// Types
import { Mandate } from "@types/MandateTypes.sol";

/// @title DaimonFactory.createAccount Unit Tests
/// @author highskore.eth
/// @notice The deploy + bootstrap path: CREATE2-deploys the account at the counterfactual address that
///         commits to the root set and the genesis mandates, seeds it with the supplied roots, binds the
///         genesis mandates atomically (no separate bind tx), and returns the existing account on a repeat
///         call (idempotent).
contract DaimonFactory_createAccount_Unit_Test is DaimonFactory_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice createAccount deploys the account at exactly the address getAddress predicts.
    function test_createAccount_deploysAtPredictedAddress() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();
        address predicted = factory.getAddress(SALT, vs, ds, _noMandates());

        // Act
        address account = factory.createAccount(SALT, vs, ds, _noMandates());

        // Assert
        assertEq(account, predicted, "deployed address must match the counterfactual");
        assertGt(account.code.length, 0, "account has code");
    }

    /// @notice The deployed account is bootstrapped with the supplied root set.
    function test_createAccount_bootstrapsRootSet() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();

        // Act
        address account = factory.createAccount(SALT, vs, ds, _noMandates());

        // Assert
        assertEq(Daimon(payable(account)).rootValidators().length, 2, "two roots");
        assertTrue(Daimon(payable(account)).isRootInstalled(address(v1)), "v1 installed");
        assertEq(v1.signerOf(account), s1, "v1 signer seeded");
    }

    /// @notice Calling createAccount twice with the same inputs returns the same account (idempotent).
    function test_createAccount_isIdempotent() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();

        // Act
        address a1 = factory.createAccount(SALT, vs, ds, _noMandates());
        address a2 = factory.createAccount(SALT, vs, ds, _noMandates());

        // Assert
        assertEq(a1, a2, "same inputs -> same account");
    }

    /// @notice A createAccount carrying a genesis mandate deploys at the mandate-committed address AND binds
    ///         the mandate atomically — no separate bind tx, the mandate is enabled the instant it exists.
    function test_createAccount_bindsGenesisMandate() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();
        Mandate memory m = _mandate(makeAddr("recipient"), bytes32(uint256(0xA)));
        Mandate[] memory ms = _mandates(m);
        address predicted = factory.getAddress(SALT, vs, ds, ms);

        // Act
        address account = factory.createAccount(SALT, vs, ds, ms);

        // Assert
        assertEq(account, predicted, "deployed at the mandate-committed address");
        assertTrue(
            Daimon(payable(account)).isMandateBound(_mandateId(m)),
            "genesis mandate is bound atomically (no separate bind tx)"
        );
    }

    /// @notice A deploy carrying mandateA lands at the mandateA address; you can NOT deploy a different
    ///         mandate (mandateB) to that same address — mandateB has its own distinct address, so the
    ///         mandateA account is never hijacked by a different genesis mandate.
    function test_createAccount_cannotHijackWithDifferentMandate() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _roots();
        Mandate memory mA = _mandate(makeAddr("recipientA"), bytes32(uint256(0xA)));
        Mandate memory mB = _mandate(makeAddr("recipientB"), bytes32(uint256(0xB)));
        address addrA = factory.getAddress(SALT, vs, ds, _mandates(mA));

        // Act: deploy mandateA at its address, then deploy mandateB.
        address deployedA = factory.createAccount(SALT, vs, ds, _mandates(mA));
        address deployedB = factory.createAccount(SALT, vs, ds, _mandates(mB));

        // Assert: mandateA is at addrA with mandateA bound; mandateB landed elsewhere with mandateB bound,
        // and crucially mandateB is NOT bound at addrA — the address commitment prevents the swap.
        assertEq(deployedA, addrA, "mandateA deploys at its committed address");
        assertTrue(deployedB != addrA, "a different mandate cannot land at the mandateA address");
        assertTrue(Daimon(payable(addrA)).isMandateBound(_mandateId(mA)), "addrA binds mandateA");
        assertFalse(
            Daimon(payable(addrA)).isMandateBound(_mandateId(mB)), "addrA must NOT bind mandateB"
        );
    }
}
