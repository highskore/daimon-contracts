// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { NativeValueLimitSigil_Unit_Test } from "../NativeValueLimitSigil.t.sol";

// Types
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title NativeValueLimitSigil.checkAction Unit Tests
/// @author highskore.eth
/// @notice value below / at / above the limit, the `limit == 0` no-ETH case (used by
///         `[SudoSigil + NativeValueLimitSigil(0)]`), and the fail-closed uninitialized default.
contract NativeValueLimitSigil_checkAction_Unit_Test is NativeValueLimitSigil_Unit_Test {
    function test_permits_valueBelowLimit() external {
        _init(1 ether);
        assertEq(_check(0.5 ether), VALIDATION_SUCCESS, "below the limit must pass");
    }

    function test_permits_valueEqualToLimit() external {
        _init(1 ether);
        assertEq(_check(1 ether), VALIDATION_SUCCESS, "exactly the limit must pass (inclusive)");
    }

    function test_rejects_valueAboveLimit() external {
        _init(1 ether);
        assertEq(_check(1 ether + 1), VALIDATION_FAILED, "one wei over the limit must fail");
    }

    /// @notice The `[SudoSigil + NativeValueLimitSigil(0)]` composition: any args, but NO ETH.
    function test_zeroLimit_permitsOnlyZeroValue() external {
        _init(0);
        assertEq(_check(0), VALIDATION_SUCCESS, "zero value under a zero cap must pass");
        assertEq(_check(1), VALIDATION_FAILED, "any value under a zero cap must fail");
    }

    /// @notice Fail-closed: an unconfigured entry is `limit == 0`, so only `value == 0` passes.
    function test_uninitialized_isFailClosed() external view {
        assertEq(_check(0), VALIDATION_SUCCESS, "uninitialized permits zero value");
        assertEq(_check(1 wei), VALIDATION_FAILED, "uninitialized rejects any native value");
    }
}
