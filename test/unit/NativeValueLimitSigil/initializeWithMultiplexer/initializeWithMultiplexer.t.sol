// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { NativeValueLimitSigil_Unit_Test } from "../NativeValueLimitSigil.t.sol";

/// @title NativeValueLimitSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Configuring the sigil stores the native-value cap, surfaced by the `nativeValueLimits` view.
contract NativeValueLimitSigil_initializeWithMultiplexer_Unit_Test is
    NativeValueLimitSigil_Unit_Test
{
    function test_storesAndExposesTheConfiguredLimit() external {
        _init(42 ether);
        assertEq(
            sigil.nativeValueLimits(ID, address(this), ACCOUNT),
            42 ether,
            "view returns the stored cap"
        );
    }
}
