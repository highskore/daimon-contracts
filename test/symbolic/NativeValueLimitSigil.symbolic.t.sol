// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { NativeValueLimitSigil } from "@sigils/NativeValueLimitSigil/NativeValueLimitSigil.sol";

// Libraries
import {
    NativeValueLimitConfig
} from "@sigils/NativeValueLimitSigil/lib/NativeValueLimitConfigLib.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title NativeValueLimitSigil_Symbolic_Test — machine-proven ∀-input value-cap correctness
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) that {NativeValueLimitSigil.checkAction} permits an action
///         *iff* `value <= limit`, over SYMBOLIC `value` and a SYMBOLIC configured `limit`. The
///         headline safety property is SUCCESS ⟹ `value <= limit` (no over-cap action ever passes);
///         the equivalence below proves that AND its converse in one shot.
/// @dev Two proofs:
///        1. {check_checkAction_success_implies_underCap}: ∀ (limit, value) over a configured cap,
///           SUCCESS ⇔ `value <= limit`.
///        2. {check_checkAction_default_denies_nonzeroValue}: the fail-closed default — a
///           NEVER-configured entry has `limit == 0`, so it permits ONLY `value == 0`. Proven over
///           symbolic `value` with no `initializeWithMultiplexer` call.
///
///      No loops/arrays/calldata are exercised (the sigil reads none), so the symbolic surface is
///      just two `uint256`s; the global `--loop` bound does not bite this proof.
contract NativeValueLimitSigil_Symbolic_Test is Test {
    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0xBEEF);

    NativeValueLimitSigil internal sigil;

    function setUp() public {
        sigil = new NativeValueLimitSigil();
    }

    /// @notice ∀ (limit, value): a CONFIGURED cap permits the action iff `value <= limit`.
    function check_checkAction_success_implies_underCap(uint256 limit, uint256 value) public {
        sigil.initializeWithMultiplexer(
            ACCOUNT, ID, abi.encode(NativeValueLimitConfig({ limit: limit }))
        );

        uint256 code = sigil.checkAction(ID, ACCOUNT, TARGET, value, hex"");

        // Headline + converse: SUCCESS ⇔ under the cap.
        assert((code == VALIDATION_SUCCESS) == (value <= limit));
        // Strict two-valued return.
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }

    /// @notice ∀ value: the fail-closed DEFAULT (never configured ⇒ limit 0) permits only `value == 0`.
    function check_checkAction_default_denies_nonzeroValue(uint256 value) public {
        // No initializeWithMultiplexer — the (ID, this, ACCOUNT) entry is the zero default.
        uint256 code = sigil.checkAction(ID, ACCOUNT, TARGET, value, hex"");

        assert((code == VALIDATION_SUCCESS) == (value == 0));
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }
}
