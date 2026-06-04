// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Eip3009Sigil_Unit_Test } from "../Eip3009Sigil.t.sol";

// Interfaces
import { ISigilBase, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title Eip3009Sigil.check1271 Unit Tests
/// @author highskore.eth
/// @notice The content-aware x402 voucher gate, exercised branch-by-branch by calling {check1271} DIRECTLY with
///         the engine-packed `abi.encode(sender, hash, appDomainSeparator, contentsHash, inner)` blob. Each test
///         pins ONE failing field (sender / domain / inner length / soundness anchor / payer / time bound /
///         payee / cap) while the rest are well-formed, so the verdict isolates that branch. Default-deny when
///         unconfigured; fail-closed (clean {VALIDATION_FAILED}, never a bubbled revert) on attacker input.
contract Eip3009Sigil_check1271_Unit_Test is Eip3009Sigil_Unit_Test {
    bytes32 internal constant NONCE = keccak256("nonce-1");

    /*//////////////////////////////////////////////////////////////
                            NOT INITIALIZED
    //////////////////////////////////////////////////////////////*/

    /// @notice Querying an unconfigured (id, account) reverts PolicyNotInitialized (default-deny, one-shot).
    function test_check1271_revertsWhen_uninitialized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                ISigilBase.PolicyNotInitialized.selector, ID, address(this), account
            )
        );
        sigil.check1271(ID, account, _packedVoucher(PAYEE, CAP, NONCE));
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    /// @notice A fully well-formed voucher to an allowlisted payee within the cap and the open window passes.
    function test_check1271_wellFormedVoucher_passes() external {
        _init();
        assertEq(
            _check1271(_packedVoucher(PAYEE, CAP, NONCE)),
            VALIDATION_SUCCESS,
            "well-formed voucher to allowlisted payee at the cap passes"
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ANTI-PHISHING: SENDER / DOMAIN
    //////////////////////////////////////////////////////////////*/

    /// @notice A request whose `sender` is NOT the configured token is denied (anti-phishing).
    function test_check1271_wrongSender_fails() external {
        _init();
        bytes memory inner = _inner(account, PAYEE, CAP, 0, type(uint256).max, NONCE);
        bytes32 contents = _contents(account, PAYEE, CAP, 0, type(uint256).max, NONCE);
        // sender = a different token, everything else well-formed.
        bytes memory blob = _packed(address(0xF00D), DOMAIN, contents, inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "non-token sender denied");
    }

    /// @notice A signature over a DIFFERENT token domain (appDomainSeparator mismatch) is denied.
    function test_check1271_wrongDomain_fails() external {
        _init();
        bytes memory inner = _inner(account, PAYEE, CAP, 0, type(uint256).max, NONCE);
        bytes32 contents = _contents(account, PAYEE, CAP, 0, type(uint256).max, NONCE);
        // appDomainSeparator = a different domain, everything else well-formed.
        bytes memory blob = _packed(TOKEN, keccak256("other-domain"), contents, inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "wrong app domain denied");
    }

    /*//////////////////////////////////////////////////////////////
                         MALFORMED / SOUNDNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice An inner blob whose length is not exactly the six-word EIP-3009 content length is denied (a
    ///         malformed/short authorization the decode would otherwise read past).
    function test_check1271_malformedInnerLength_fails() external {
        _init();
        // A five-word inner (missing the nonce) — length != _CONTENT_LEN (0xc0). The contentsHash is irrelevant
        // because the length gate fails first.
        bytes memory inner = abi.encode(account, PAYEE, CAP, uint256(0), type(uint256).max);
        bytes memory blob = _packed(TOKEN, DOMAIN, keccak256("anything"), inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "malformed inner length denied");
    }

    /// @notice Fields that do NOT hash to the signed `contentsHash` are denied (the soundness anchor): a relayer
    ///         that swaps any field in the inner blob after signing fails `keccak(fields) == contentsHash`.
    function test_check1271_tamperedFields_fails() external {
        _init();
        // Signed contents pin PAYEE; the submitted inner blob claims EVIL_PAYEE -> keccak(fields) != contents.
        bytes32 contents = _contents(account, PAYEE, CAP, 0, type(uint256).max, NONCE);
        bytes memory inner = _inner(account, EVIL_PAYEE, CAP, 0, type(uint256).max, NONCE);
        bytes memory blob = _packed(TOKEN, DOMAIN, contents, inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "tampered fields denied (soundness anchor)");
    }

    /// @notice An authorization whose payer (`from`) is not the signing account is denied — the voucher must
    ///         pull from THIS account, never a third party.
    function test_check1271_wrongPayer_fails() external {
        _init();
        address otherFrom = address(0xC0FFEE);
        // Well-formed soundness anchor over the (other-from) fields, so only the `from != account` gate trips.
        bytes memory inner = _inner(otherFrom, PAYEE, CAP, 0, type(uint256).max, NONCE);
        bytes32 contents = _contents(otherFrom, PAYEE, CAP, 0, type(uint256).max, NONCE);
        bytes memory blob = _packed(TOKEN, DOMAIN, contents, inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "wrong payer denied");
    }

    /*//////////////////////////////////////////////////////////////
                              TIME BOUNDS
    //////////////////////////////////////////////////////////////*/

    /// @notice An EXPIRED voucher (`block.timestamp >= validBefore`) is denied — mirrors the token's own check.
    function test_check1271_expired_fails() external {
        _init();
        // validBefore == now: strict `block.timestamp >= vb` rejects it.
        assertEq(
            _check1271(_packedVoucherTimed(PAYEE, CAP, 0, block.timestamp, NONCE)),
            VALIDATION_FAILED,
            "expired voucher (vb == now) denied"
        );
    }

    /// @notice A NOT-YET-VALID voucher (`block.timestamp <= validAfter`) is denied.
    function test_check1271_notYetValid_fails() external {
        _init();
        // validAfter == now: strict `block.timestamp <= va` rejects it.
        assertEq(
            _check1271(_packedVoucherTimed(PAYEE, CAP, block.timestamp, type(uint256).max, NONCE)),
            VALIDATION_FAILED,
            "not-yet-valid voucher (va == now) denied"
        );
    }

    /// @notice A voucher strictly INSIDE the window (`validAfter < now < validBefore`) still passes.
    function test_check1271_withinWindow_passes() external {
        _init();
        assertEq(
            _check1271(
                _packedVoucherTimed(PAYEE, CAP, block.timestamp - 1, block.timestamp + 1, NONCE)
            ),
            VALIDATION_SUCCESS,
            "voucher strictly within (va, vb) passes"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            PAYEE / CAP
    //////////////////////////////////////////////////////////////*/

    /// @notice A `to` equal to solady's reserved set sentinel returns a CLEAN VALIDATION_FAILED — the membership
    ///         read would REVERT on the sentinel, but the explicit guard fails closed instead of bubbling.
    function test_check1271_sentinelPayee_cleanDeny() external {
        _init();
        // Well-formed soundness anchor over the sentinel payee, so only the sentinel guard short-circuits.
        bytes memory inner = _inner(account, SENTINEL_PAYEE, 1, 0, type(uint256).max, NONCE);
        bytes32 contents = _contents(account, SENTINEL_PAYEE, 1, 0, type(uint256).max, NONCE);
        bytes memory blob = _packed(TOKEN, DOMAIN, contents, inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "sentinel payee clean-denied (no revert)");
    }

    /// @notice A voucher to a payee NOT on the allowlist is denied (even within the cap and window).
    function test_check1271_nonAllowlistedPayee_fails() external {
        _init();
        bytes memory inner = _inner(account, EVIL_PAYEE, 1, 0, type(uint256).max, NONCE);
        bytes32 contents = _contents(account, EVIL_PAYEE, 1, 0, type(uint256).max, NONCE);
        bytes memory blob = _packed(TOKEN, DOMAIN, contents, inner);
        assertEq(_check1271(blob), VALIDATION_FAILED, "off-allowlist payee denied");
    }

    /// @notice An EMPTY payee allowlist denies every payee (default-deny, not allow-all).
    function test_check1271_emptyPayeeAllowlist_deniesAll() external {
        _init(new address[](0));
        assertEq(
            _check1271(_packedVoucher(PAYEE, CAP, NONCE)),
            VALIDATION_FAILED,
            "empty payee allowlist denies all"
        );
    }

    /// @notice A voucher exactly AT the cap passes; one above the cap is denied.
    function test_check1271_capBoundary() external {
        _init();
        assertEq(
            _check1271(_packedVoucher(PAYEE, CAP, keccak256("at-cap"))),
            VALIDATION_SUCCESS,
            "value at the cap passes"
        );
        assertEq(
            _check1271(_packedVoucher(PAYEE, CAP + 1, keccak256("over-cap"))),
            VALIDATION_FAILED,
            "value over the cap denied"
        );
    }
}
