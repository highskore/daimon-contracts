// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { AttestationSigil_Unit_Test } from "../AttestationSigil.t.sol";

// Contracts
import { AttestationSigil } from "@sigils/AttestationSigil/AttestationSigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title AttestationSigil.check1271 Unit Tests
/// @author highskore.eth
/// @notice The attestation gate: the requesting dApp must be allowlisted (anti-phishing) AND the REAL `hash`
///         must be allowlisted (or no hash allowlist configured). View-only; default-deny when
///         unconfigured. Drives the engine-packed `abi.encode(sender, hash, content)` argument and proves
///         the gate binds to `hash`, not the caller-supplied content blob.
contract AttestationSigil_check1271_Unit_Test is AttestationSigil_Unit_Test {
    bytes32 internal constant HASH = keccak256("digest");

    /*//////////////////////////////////////////////////////////////
                            NOT INITIALIZED
    //////////////////////////////////////////////////////////////*/

    /// @notice An unconfigured config id reverts (not silently allowed).
    function test_check1271_revertsWhen_uninitialized() external {
        vm.expectRevert();
        policy.check1271(
            ConfigId.wrap(bytes32(uint256(99))), ACCOUNT, _packed(DAPP, HASH, bytes("order"))
        );
    }

    /*//////////////////////////////////////////////////////////////
                            SENDER ALLOWLIST
    //////////////////////////////////////////////////////////////*/

    /// @notice An allowlisted dApp (any content allowed) passes.
    function test_check1271_allowedSender_anyContent_passes() external {
        _initSender(DAPP);
        assertEq(_check1271(DAPP, HASH, bytes("order")), VALIDATION_SUCCESS, "allowlisted dApp");
    }

    /// @notice A non-allowlisted dApp is rejected (anti-phishing).
    function test_check1271_nonAllowedSender_fails() external {
        _initSender(DAPP);
        assertEq(
            _check1271(ATTACKER, HASH, bytes("order")), VALIDATION_FAILED, "off-allowlist dApp"
        );
    }

    /// @notice The ANY_SENDER (address(0)) wildcard permits any requesting dApp.
    function test_check1271_anySenderWildcard_passes() external {
        _initSender(policy.ANY_SENDER());
        assertEq(_check1271(ATTACKER, HASH, bytes("order")), VALIDATION_SUCCESS, "wildcard sender");
    }

    /// @notice An empty sender allowlist denies everything (default-deny, not allow-all).
    function test_check1271_emptySenderAllowlist_deniesAll() external {
        _init(new address[](0), new bytes32[](0));
        assertEq(
            _check1271(DAPP, HASH, bytes("order")), VALIDATION_FAILED, "empty allowlist denies"
        );
    }

    /// @notice Several allowlisted dApps are all accepted; an off-list one is still rejected.
    function test_check1271_multipleSenders() external {
        address[] memory senders = new address[](2);
        senders[0] = DAPP;
        senders[1] = address(0xCAFE);
        _init(senders, new bytes32[](0));

        assertEq(_check1271(DAPP, HASH, bytes("a")), VALIDATION_SUCCESS, "first dApp");
        assertEq(_check1271(address(0xCAFE), HASH, bytes("a")), VALIDATION_SUCCESS, "second dApp");
        assertEq(_check1271(ATTACKER, HASH, bytes("a")), VALIDATION_FAILED, "off-list dApp");
    }

    /*//////////////////////////////////////////////////////////////
                              HASH ALLOWLIST
    //////////////////////////////////////////////////////////////*/

    /// @notice An allowlisted dApp signing an allowlisted digest (`hash`) passes.
    function test_check1271_allowedHash_passes() external {
        _initSenderHash(DAPP, HASH);
        assertEq(_check1271(DAPP, HASH, bytes("order")), VALIDATION_SUCCESS, "pinned hash");
    }

    /// @notice An allowlisted dApp signing a NON-allowlisted digest is rejected (hash-pinned mandate).
    function test_check1271_nonAllowedHash_fails() external {
        _initSenderHash(DAPP, HASH);
        assertEq(
            _check1271(DAPP, keccak256("other-digest"), bytes("order")),
            VALIDATION_FAILED,
            "off-allowlist hash"
        );
    }

    /// @notice With no hash allowlist, the allowlisted dApp may sign ANY digest.
    function test_check1271_noHashAllowlist_anyHashPasses() external {
        _initSender(DAPP);
        assertEq(_check1271(DAPP, keccak256("h1"), bytes("x")), VALIDATION_SUCCESS, "hash 1");
        assertEq(_check1271(DAPP, keccak256("h2"), bytes("x")), VALIDATION_SUCCESS, "hash 2");
    }

    /// @notice Sender AND hash both gate: a bad hash fails even from an allowlisted dApp, and a good hash
    ///         fails from a non-allowlisted dApp.
    function test_check1271_senderAndHash_bothGate() external {
        _initSenderHash(DAPP, HASH);
        // good hash, bad dApp -> fail
        assertEq(_check1271(ATTACKER, HASH, bytes("x")), VALIDATION_FAILED, "bad dApp");
        // bad hash, good dApp -> fail
        assertEq(_check1271(DAPP, keccak256("nope"), bytes("x")), VALIDATION_FAILED, "bad hash");
        // good hash, good dApp -> pass
        assertEq(_check1271(DAPP, HASH, bytes("x")), VALIDATION_SUCCESS, "both good");
    }

    /// @notice Several allowlisted digests are all accepted; an off-list one is still rejected.
    function test_check1271_multipleHashes() external {
        bytes32 h2 = keccak256("second");
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = HASH;
        hashes[1] = h2;
        address[] memory senders = new address[](1);
        senders[0] = DAPP;
        _init(senders, hashes);

        assertEq(_check1271(DAPP, HASH, bytes("x")), VALIDATION_SUCCESS, "first hash");
        assertEq(_check1271(DAPP, h2, bytes("x")), VALIDATION_SUCCESS, "second hash");
        assertEq(
            _check1271(DAPP, keccak256("third"), bytes("x")), VALIDATION_FAILED, "off-list hash"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    SECURITY: GATE BINDS TO THE REAL HASH
    //////////////////////////////////////////////////////////////*/

    /// @notice THE FIX. The gate must bind to the REAL `hash` (the value passed to `isValidSignature`), NOT
    ///         to the caller-supplied `content` blob. Previously the allowlist matched `keccak256(content)`,
    ///         so an attacker could carry an allowlisted content blob while the real signed `hash` was an
    ///         arbitrary order — bypassing the content gate. Here the mandate is pinned to `HASH`; presenting
    ///         a content blob whose `keccak256` equals an allowlisted value MUST NOT rescue a mismatched
    ///         real `hash`. The check fails because the real `hash` is off-allowlist, regardless of content.
    function test_check1271_mismatchedContentVsRealHash_rejected() external {
        // Pin the mandate to exactly one allowed digest.
        _initSenderHash(DAPP, HASH);

        // The attacker presents a content blob that, under the OLD design, was the allowlisted value
        // (`keccak256("buy 1 ETH @ 3000")` would have been an allowed content hash). The REAL signed hash is
        // an arbitrary, off-allowlist digest. The gate binds to the real hash -> REJECTED.
        bytes memory allowlistedLookingContent = bytes("buy 1 ETH @ 3000");
        bytes32 attackerRealHash = keccak256("drain the whole wallet");
        assertTrue(
            attackerRealHash != HASH, "test setup: attacker hash must differ from the pinned hash"
        );

        assertEq(
            _check1271(DAPP, attackerRealHash, allowlistedLookingContent),
            VALIDATION_FAILED,
            "an allowlisted-looking content blob must NOT rescue a mismatched real hash"
        );

        // And the converse: the SAME content blob with the REAL allowlisted hash passes — proving it is the
        // hash, not the content, that gates.
        assertEq(
            _check1271(DAPP, HASH, allowlistedLookingContent),
            VALIDATION_SUCCESS,
            "the pinned hash passes regardless of the content blob"
        );

        // The content blob is irrelevant when the hash matches: an empty/garbage content still passes.
        assertEq(
            _check1271(DAPP, HASH, bytes("")),
            VALIDATION_SUCCESS,
            "content blob is not gated; the matching hash is what counts"
        );
    }

    /// @notice A `hash` equal to solady's reserved zero-sentinel must DENY (not revert) when a hash allowlist
    ///         is configured — the sentinel can never be a legitimate member, so it fails closed cleanly.
    function test_check1271_zeroSentinelHash_deniesNotReverts() external {
        _initSenderHash(DAPP, HASH);
        bytes32 sentinel = bytes32(uint256(0xfbb67fda52d4bfb8bf));
        assertEq(
            _check1271(DAPP, sentinel, bytes("x")),
            VALIDATION_FAILED,
            "sentinel hash must deny cleanly, never revert"
        );
    }

    /// @notice A `sender` equal to solady's reserved zero-sentinel (it fits in 20 bytes) must DENY (not
    ///         revert) on a non-wildcard config — the sentinel can never be an allowlisted member.
    function test_check1271_zeroSentinelSender_deniesNotReverts() external {
        _initSender(DAPP);
        address sentinelSender = address(uint160(0xfbb67fda52d4bfb8bf));
        assertEq(
            _check1271(sentinelSender, HASH, bytes("x")),
            VALIDATION_FAILED,
            "sentinel sender must deny cleanly, never revert"
        );
    }

    /// @notice The ANY_SENDER wildcard still admits a sentinel-valued `sender` (the wildcard is checked first,
    ///         so the sentinel short-circuit never denies a deliberate allow-any config).
    function test_check1271_anySenderWildcard_admitsSentinelSender() external {
        _initSender(policy.ANY_SENDER());
        address sentinelSender = address(uint160(0xfbb67fda52d4bfb8bf));
        assertEq(
            _check1271(sentinelSender, HASH, bytes("x")),
            VALIDATION_SUCCESS,
            "wildcard admits any sender, including the sentinel value"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: only the exact allowlisted dApp passes when one sender is configured.
    function testFuzz_check1271_onlyAllowlistedSenderPasses(address sender) external {
        _initSender(DAPP);
        uint256 res = _check1271(sender, HASH, bytes("x"));
        if (sender == DAPP) {
            assertEq(res, VALIDATION_SUCCESS, "the allowlisted dApp passes");
        } else {
            assertEq(res, VALIDATION_FAILED, "every other dApp fails");
        }
    }

    /// @notice Fuzz the binding: with one pinned hash, ONLY that exact `hash` passes — no `content` value can
    ///         change the verdict (the gate ignores content entirely).
    function testFuzz_check1271_onlyAllowlistedHashPasses(
        bytes32 realHash,
        bytes calldata content
    )
        external
    {
        _initSenderHash(DAPP, HASH);
        uint256 res = _check1271(DAPP, realHash, content);
        if (realHash == HASH) {
            assertEq(res, VALIDATION_SUCCESS, "the pinned hash passes for any content");
        } else {
            assertEq(res, VALIDATION_FAILED, "every other hash fails regardless of content");
        }
    }
}
