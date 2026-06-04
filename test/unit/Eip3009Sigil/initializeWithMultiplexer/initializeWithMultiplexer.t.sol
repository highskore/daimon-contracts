// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Eip3009Sigil_Unit_Test } from "../Eip3009Sigil.t.sol";

// Interfaces
import { ISigilBase } from "@interfaces/ISigil.sol";

/// @title Eip3009Sigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Configuring the x402 voucher gate: stores the token + domain separator + cap + payee allowlist keyed
///         by (configId, msg.sender, account), marks the instance initialized, and emits {SigilSet}. Also
///         exercises the public view getters ({config}, {initialized}, {payeeAllowed}). A re-init fully REPLACES
///         the prior config (no stale payees).
contract Eip3009Sigil_initializeWithMultiplexer_Unit_Test is Eip3009Sigil_Unit_Test {
    /// @notice Initialization records the config and exposes it via the view getters.
    function test_init_storesConfig() external {
        _init();

        assertTrue(sigil.initialized(ID, address(this), account), "initialized marker set");

        (address t, bytes32 ds, uint256 c) = sigil.config(ID, address(this), account);
        assertEq(t, TOKEN, "token stored");
        assertEq(ds, DOMAIN, "domain separator stored");
        assertEq(c, CAP, "cap stored");

        assertTrue(sigil.payeeAllowed(ID, address(this), account, PAYEE), "payee stored");
        assertFalse(
            sigil.payeeAllowed(ID, address(this), account, EVIL_PAYEE), "off-list payee absent"
        );
    }

    /// @notice An unconfigured instance reads back not-initialized.
    function test_init_unconfigured_readsBackUninitialized() external view {
        assertFalse(sigil.initialized(ID, address(this), account), "uninitialized marker false");
    }

    /// @notice Initialization emits {SigilSet} with (id, multiplexer, account).
    function test_init_emitsSigilSet() external {
        vm.expectEmit(true, true, true, true);
        emit ISigilBase.SigilSet(ID, address(this), account);
        _init();
    }

    /// @notice Config is keyed by multiplexer: a different multiplexer's view is independent (unconfigured).
    function test_init_keyedByMultiplexer() external {
        _init();
        assertTrue(sigil.initialized(ID, address(this), account), "this mxer configured");
        assertFalse(sigil.initialized(ID, address(0xBEEF), account), "other mxer unconfigured");
        assertFalse(
            sigil.payeeAllowed(ID, address(0xBEEF), account, PAYEE), "other mxer has no payee"
        );
    }

    /// @notice A re-init REPLACES the prior config: a stale payee is cleared, a new one set, and the scalars
    ///         overwritten — the clear-on-rebind guarantee (a re-bound mandateId must not retain a dropped payee).
    function test_init_reinit_clearsStalePayee() external {
        _init(); // [PAYEE]
        assertTrue(sigil.payeeAllowed(ID, address(this), account, PAYEE), "PAYEE set initially");

        address[] memory next = new address[](1);
        next[0] = EVIL_PAYEE;
        _init(next); // re-init with a DIFFERENT payee

        assertFalse(sigil.payeeAllowed(ID, address(this), account, PAYEE), "stale PAYEE cleared");
        assertTrue(sigil.payeeAllowed(ID, address(this), account, EVIL_PAYEE), "new payee set");
    }
}
