// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SpendSigil_Unit_Test } from "../SpendSigil.t.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";

/// @title SpendSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Config installation: a zero budgeted token is rejected at config time, and a well-formed config
///         is persisted (token, cap, period) keyed by (id, multiplexer, account).
contract SpendSigil_initializeWithMultiplexer_Unit_Test is SpendSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A zero budgeted token is rejected at config time.
    function test_initializeWithMultiplexer_revertsWhen_zeroToken() external {
        // Arrange
        address[] memory spenders = new address[](0);
        SpendConfig memory cfg =
            SpendConfig({ token: address(0), cap: CAP, period: Period.Day, spenders: spenders });

        // Act & Assert
        vm.expectRevert(SpendSigil.InvalidToken.selector);
        spendSigil.initializeWithMultiplexer(account, CID, abi.encode(cfg));
    }

    /// @notice A valid config persists token, cap, and period.
    function test_initializeWithMultiplexer_persistsConfig() external {
        // Arrange
        _init(Period.Week);

        // Act
        (address token, uint256 cap, Period period) =
            spendSigil.configs(CID, address(this), account);

        // Assert
        assertEq(token, TOKEN, "token");
        assertEq(cap, CAP, "cap");
        assertEq(uint256(period), uint256(Period.Week), "period");
    }
}
