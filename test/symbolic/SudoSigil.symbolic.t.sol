// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title SudoSigil_Symbolic_Test — machine-proven ∀-input unconditional allow
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) that {SudoSigil} is the genuine allow-all policy: it
///         NEVER denies, over fully symbolic inputs. The SudoSigil reads no calldata, holds no state,
///         and is configured by a pure no-op {initializeWithMultiplexer}; its only contract is
///         "always {VALIDATION_SUCCESS}". These proofs pin exactly that — for the `checkAction` path,
///         configured or never-configured. (SudoSigil is a pure action sigil: it has no ERC-1271 tier.)
/// @dev Proven properties (∀ symbolic inputs):
///        1. {check_checkAction_always_succeeds}: ∀ (id, account, target, value, data) the action
///           path returns SUCCESS — no value, no calldata content, no config can make it deny.
///        2. {check_uninitialized_succeeds}: with NO `initializeWithMultiplexer` call, the action
///           path STILL succeeds — uninitialized and initialized behave identically (no
///           `PolicyNotInitialized` guard).
///
///      Symbolic bound: the `data`/`content` `bytes` are bounded by Halmos's global
///      `--default-bytes-lengths` (default {0, 32, 1024}). Since the sigil reads NONE of the calldata
///      (the params are unnamed and the body is `return VALIDATION_SUCCESS`), the byte-length bound is
///      irrelevant to the property — it holds for any length. No loops/arrays are exercised.
contract SudoSigil_Symbolic_Test is Test {
    SudoSigil internal sigil;

    function setUp() public {
        sigil = new SudoSigil();
    }

    /// @notice ∀ (id, account, target, value, data): the action path NEVER denies.
    /// @dev All five params are symbolic. We configure (a no-op) then assert SUCCESS unconditionally.
    function check_checkAction_always_succeeds(
        bytes32 id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        public
    {
        ConfigId cid = ConfigId.wrap(id);
        sigil.initializeWithMultiplexer(account, cid, hex"");

        uint256 code = sigil.checkAction(cid, account, target, value, data);

        // The entire contract: unconditional allow.
        assert(code == VALIDATION_SUCCESS);
    }

    /// @notice ∀ (id, account, target, value, data): a NEVER-configured SudoSigil still succeeds.
    /// @dev No `initializeWithMultiplexer` — the SudoSigil has no `PolicyNotInitialized` guard, so an
    ///      uninitialized instance behaves identically to a configured one (always allow).
    function check_uninitialized_succeeds(
        bytes32 id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        public
    {
        uint256 code = sigil.checkAction(ConfigId.wrap(id), account, target, value, data);

        assert(code == VALIDATION_SUCCESS);
    }
}
