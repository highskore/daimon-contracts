// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { LibHarness } from "@test/mock/LibHarness.sol";

// Types
import { ChainBind } from "@types/MandateTypes.sol";

/// @title HashLib Unit Tests
/// @author highskore.eth
/// @notice Pins HashLib's EIP-712 surface to fixed literals — the mandate-bind / exec / multichain-bind
///         typehashes, the multichain domain separator, and a known array digest.
/// @dev The multichain literals are the SAME ones the SDK suite (`packages/sdk/test/multichainBind.test.ts`)
///      asserts against, so TS↔Solidity parity is checked on BOTH sides: a typehash/domain/encoding drift on
///      either side trips a test here or there rather than silently producing a digest that no chain re-derives.
///      The example digest vector matches the SDK's `[{8453, 0x1111}, {10, 0x2222}]` case exactly. The
///      mandate-bind + exec typehash pins are drift canaries: editing either typehash string (which would
///      silently change every bind/exec signature digest) trips an assertion here.
contract HashLib_Unit_Test is Test {
    LibHarness internal h;

    function setUp() public {
        h = new LibHarness();
    }

    function test_mandateBindTypehash_matchesLiteral() public view {
        assertEq(
            h.mandateBindTypehash(),
            0x1f54046edf709f7249952c99d1f69900c3bf4b2f44be29042fea999cc82a0527,
            "MANDATE_BIND_TYPEHASH drift"
        );
    }

    function test_execTypehash_matchesLiteral() public view {
        assertEq(
            h.execTypehash(),
            0x7d4a7d07a4d289db93081cfc3e9c61b06eeb7c12818008c63d36a4c0891832db,
            "EXEC_TYPEHASH drift"
        );
    }

    function test_chainBindTypehash_matchesLiteral() public view {
        assertEq(
            h.chainBindTypehash(),
            0xf499839de43ce1f232db060babb349ac4c77ca0cd195a9ceda5d42bdffdd8fd5,
            "CHAIN_BIND_TYPEHASH drift"
        );
    }

    function test_multichainBindTypehash_matchesLiteral() public view {
        assertEq(
            h.multichainBindTypehash(),
            0x4b79667bec54060e44c3484d2bc377eb771ecaab86e4e0a4d7b0d10080553b27,
            "MULTICHAIN_BIND_TYPEHASH drift"
        );
    }

    function test_multichainDomainSeparator_matchesLiteral() public view {
        // Chain-independent (name + version only) — the same on every chain by construction.
        assertEq(
            h.multichainDomainSeparator(),
            0xa903d29724f4337d1f80b9fe6390cbd24e63514ec0b2484528c22727737e7acf,
            "MULTICHAIN_DOMAIN_SEPARATOR drift"
        );
    }

    function test_multichainBindDigest_matchesSdkVector() public view {
        ChainBind[] memory arr = new ChainBind[](2);
        arr[0] = ChainBind({ chainId: 8453, bindDigest: bytes32(uint256(0x1111)) });
        arr[1] = ChainBind({ chainId: 10, bindDigest: bytes32(uint256(0x2222)) });
        assertEq(
            h.multichainBindDigest(arr),
            0xe73f67a32603fc4998dbc024207391f4808dc665ebebab386e18a19752e85c40,
            "multichainBindDigest drift vs SDK vector"
        );
    }

    function test_multichainBindDigest_orderSensitive() public view {
        ChainBind[] memory a = new ChainBind[](2);
        a[0] = ChainBind({ chainId: 8453, bindDigest: bytes32(uint256(0x1111)) });
        a[1] = ChainBind({ chainId: 10, bindDigest: bytes32(uint256(0x2222)) });

        ChainBind[] memory b = new ChainBind[](2);
        b[0] = a[1];
        b[1] = a[0];

        assertTrue(
            h.multichainBindDigest(a) != h.multichainBindDigest(b),
            "reordering must change the digest"
        );
    }
}
