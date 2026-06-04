// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SudoSigil_Unit_Test } from "../SudoSigil.t.sol";

// Interfaces
import { ISigilBase } from "@interfaces/ISigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title SudoSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Configuration is a no-op: any `initData` (including empty `0x`) is accepted and announced via
///         SigilSet, but nothing is stored — a checkAction permits the action with or without a prior init.
contract SudoSigil_initializeWithMultiplexer_Unit_Test is SudoSigil_Unit_Test {
    /// @dev A 4-byte selector used to shape selector-only calldata.
    bytes4 internal constant SEL = 0x12345678;

    /// @notice Empty `initData` (the shape `buildMandateFromPolicy` emits for SudoSigil) is accepted and
    ///         announced via SigilSet keyed by (id, multiplexer, account).
    function test_initializeWithMultiplexer_emptyInitData_emitsSigilSet() external {
        vm.expectEmit(true, true, true, true, address(sudo));
        emit ISigilBase.SigilSet(ID, address(this), ACCOUNT);
        sudo.initializeWithMultiplexer(ACCOUNT, ID, "");
    }

    /// @notice Arbitrary (ignored) `initData` is accepted just the same.
    function test_initializeWithMultiplexer_arbitraryInitData_emitsSigilSet() external {
        vm.expectEmit(true, true, true, true, address(sudo));
        emit ISigilBase.SigilSet(ID, address(this), ACCOUNT);
        sudo.initializeWithMultiplexer(ACCOUNT, ID, hex"deadbeef");
    }

    /// @notice Init stores nothing: a checkAction permits the action whether or not init ran first.
    function test_initializeWithMultiplexer_storesNothing() external {
        sudo.initializeWithMultiplexer(ACCOUNT, ID, "");
        assertEq(
            sudo.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "post-init checkAction still allows"
        );
    }
}
