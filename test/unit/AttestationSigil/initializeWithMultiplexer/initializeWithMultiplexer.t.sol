// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { AttestationSigil_Unit_Test } from "../AttestationSigil.t.sol";

// Types
import { ISigilBase } from "@interfaces/ISigil.sol";

/// @title AttestationSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Configuring the attestation gate: stores the sender + hash allowlists keyed by
///         (configId, msg.sender, account), marks the instance initialized, and emits {SigilSet}. A re-init
///         fully REPLACES the prior config (no stale entries).
contract AttestationSigil_initializeWithMultiplexer_Unit_Test is AttestationSigil_Unit_Test {
    bytes32 internal constant HASH = keccak256("digest");

    /// @notice Initialization records the sender allowlist, the hash-allowlist flag, and the marker.
    function test_init_storesConfig() external {
        _initSenderHash(DAPP, HASH);

        assertTrue(policy.initialized(ID, address(this), ACCOUNT), "initialized marker set");
        assertTrue(policy.allowedSender(ID, address(this), ACCOUNT, DAPP), "sender stored");
        assertTrue(policy.hasHashAllowlist(ID, address(this), ACCOUNT), "hash-allowlist flag");
        assertTrue(policy.allowedHash(ID, address(this), ACCOUNT, HASH), "hash stored");
    }

    /// @notice An empty hash allowlist leaves the flag false (any hash allowed) but still marks init.
    function test_init_emptyHashAllowlist_flagFalse() external {
        _initSender(DAPP);
        assertTrue(policy.initialized(ID, address(this), ACCOUNT), "initialized marker set");
        assertFalse(
            policy.hasHashAllowlist(ID, address(this), ACCOUNT), "no hash allowlist => flag false"
        );
    }

    /// @notice Initialization emits {SigilSet} with (id, multiplexer, account).
    function test_init_emitsSigilSet() external {
        vm.expectEmit(true, true, true, true);
        emit ISigilBase.SigilSet(ID, address(this), ACCOUNT);
        _initSender(DAPP);
    }

    /// @notice Config is keyed by multiplexer: a different multiplexer's config is independent.
    function test_init_keyedByMultiplexer() external {
        _initSender(DAPP);
        // From this test contract (the multiplexer), DAPP is allowed; from another it is not.
        assertTrue(policy.allowedSender(ID, address(this), ACCOUNT, DAPP), "this mxer allows");
        assertFalse(policy.allowedSender(ID, ATTACKER, ACCOUNT, DAPP), "other mxer does not");
    }

    /// @notice A re-init REPLACES the prior config: stale senders AND stale hashes are cleared, not merged.
    ///         (The clear-on-rebind fix — a re-bound mandateId must not retain a dropped dApp or digest.)
    function test_init_reinit_clearsStaleEntries() external {
        // First config: DAPP + HASH.
        _initSenderHash(DAPP, HASH);
        assertTrue(policy.allowedSender(ID, address(this), ACCOUNT, DAPP), "DAPP set initially");
        assertTrue(policy.allowedHash(ID, address(this), ACCOUNT, HASH), "HASH set initially");

        // Re-init with a DIFFERENT sender + hash.
        bytes32 newHash = keccak256("new-digest");
        _initSenderHash(ATTACKER, newHash);

        // The old entries are gone; only the new ones remain.
        assertFalse(policy.allowedSender(ID, address(this), ACCOUNT, DAPP), "stale DAPP cleared");
        assertFalse(policy.allowedHash(ID, address(this), ACCOUNT, HASH), "stale HASH cleared");
        assertTrue(policy.allowedSender(ID, address(this), ACCOUNT, ATTACKER), "new sender set");
        assertTrue(policy.allowedHash(ID, address(this), ACCOUNT, newHash), "new hash set");
    }

    /// @notice Re-init with an EMPTY hash allowlist clears a previously-pinned hash and flips the flag false
    ///         (so the mandate now allows ANY hash) — proving the marker tracks the live config, not history.
    function test_init_reinit_toEmptyHashAllowlist_clearsAndFlipsFlag() external {
        _initSenderHash(DAPP, HASH);
        assertTrue(policy.hasHashAllowlist(ID, address(this), ACCOUNT), "flag true after pinning");

        _initSender(DAPP); // re-init: same sender, empty hash allowlist
        assertFalse(
            policy.allowedHash(ID, address(this), ACCOUNT, HASH), "stale pinned hash cleared"
        );
        assertFalse(
            policy.hasHashAllowlist(ID, address(this), ACCOUNT), "flag flips to false (any hash)"
        );
    }
}
