// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Libraries
import { ContentSigLib } from "@lib/ContentSigLib.sol";

/// @dev Calldata-entry harness: {ContentSigLib.tryDecodeContentSig} takes a `bytes calldata`, so the test
///      routes the tail through an external function to give it a real calldata region.
contract ContentSigHarness {
    function decode(bytes calldata tail)
        external
        pure
        returns (bool ok, bytes memory content, bytes memory keySig)
    {
        bytes calldata c;
        bytes calldata k;
        (ok, c, k) = ContentSigLib.tryDecodeContentSig(tail);
        content = c;
        keySig = k;
    }
}

/// @title ContentSigLib Unit Tests
/// @author highskore.eth
/// @notice The fail-closed, bounds-checked decoder for the ERC-1271 MANDATE payload tail
///         `abi.encode(bytes content, bytes keySig)`. A well-formed tail round-trips; every malformed,
///         truncated, or out-of-bounds tail returns `ok == false` with empty slices and NEVER reverts.
contract ContentSigLib_Unit_Test is Base_Test {
    ContentSigHarness internal harness;

    function setUp() public {
        harness = new ContentSigHarness();
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    /// @notice A canonical `abi.encode(bytes, bytes)` decodes back to the exact two byte strings.
    function test_tryDecode_wellFormed_roundTrips() external view {
        bytes memory content = bytes("buy 1 ETH @ 3000 USDC");
        bytes memory keySig = bytes(hex"deadbeefcafe");
        bytes memory tail = abi.encode(content, keySig);

        (bool ok, bytes memory gotC, bytes memory gotK) = harness.decode(tail);

        assertTrue(ok, "well-formed tail must decode");
        assertEq(gotC, content, "content round-trips");
        assertEq(gotK, keySig, "keySig round-trips");
    }

    /// @notice Empty content and empty keySig are valid (zero-length payloads).
    function test_tryDecode_emptyFields_ok() external view {
        bytes memory tail = abi.encode(bytes(""), bytes(""));

        (bool ok, bytes memory gotC, bytes memory gotK) = harness.decode(tail);

        assertTrue(ok, "two empty bytes is a valid encoding");
        assertEq(gotC.length, 0, "content empty");
        assertEq(gotK.length, 0, "keySig empty");
    }

    /*//////////////////////////////////////////////////////////////
                              FAIL-CLOSED
    //////////////////////////////////////////////////////////////*/

    /// @notice An empty tail (no head) fails closed.
    function test_tryDecode_empty_failsClosed() external view {
        (bool ok, bytes memory gotC, bytes memory gotK) = harness.decode(bytes(""));
        assertFalse(ok, "empty tail must fail closed");
        assertEq(gotC.length, 0, "empty content on failure");
        assertEq(gotK.length, 0, "empty keySig on failure");
    }

    /// @notice A tail shorter than the two-word head (0x40) fails closed.
    function test_tryDecode_shortHead_failsClosed() external view {
        // Only one offset word present (0x20 bytes), not the required 0x40.
        bytes memory tail = abi.encodePacked(uint256(0x40));
        (bool ok,,) = harness.decode(tail);
        assertFalse(ok, "tail shorter than the two-offset head must fail closed");
    }

    /// @notice An offset that points past the tail fails closed (no revert).
    function test_tryDecode_offsetOutOfBounds_failsClosed() external view {
        // Head: content offset 0x40 (valid start), keySig offset 0xFFFF (way past the tail).
        bytes memory tail = abi.encodePacked(
            uint256(0x40), // content offset
            uint256(0xFFFF), // keySig offset — out of bounds
            uint256(0), // content length 0
            uint256(0) // (filler so content's length word is in-bounds)
        );
        (bool ok,,) = harness.decode(tail);
        assertFalse(ok, "out-of-bounds offset must fail closed, not revert");
    }

    /// @notice A declared length that runs past the tail end fails closed.
    function test_tryDecode_lengthOverrunsTail_failsClosed() external view {
        // content offset 0x40, length 0x100 (overruns), but the tail has no such payload room.
        bytes memory tail = abi.encodePacked(
            uint256(0x40), // content offset
            uint256(0x80), // keySig offset
            uint256(0x100), // content length — overruns the tail
            uint256(0) // keySig length
        );
        (bool ok,,) = harness.decode(tail);
        assertFalse(ok, "length overrunning the tail must fail closed");
    }

    /// @notice A huge offset near 2^256 cannot overflow the bounds math into acceptance.
    function test_tryDecode_offsetOverflow_failsClosed() external view {
        bytes memory tail = abi.encodePacked(
            type(uint256).max, // content offset — max, so off + 0x20 would wrap if unchecked
            uint256(0x40),
            uint256(0),
            uint256(0)
        );
        (bool ok,,) = harness.decode(tail);
        assertFalse(ok, "overflow-prone offset must fail closed");
    }
}
