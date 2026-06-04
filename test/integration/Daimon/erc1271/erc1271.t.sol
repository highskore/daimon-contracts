// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

/// @title Daimon.isValidSignature (ERC-1271 / ERC-7739) Integration Tests
/// @author highskore.eth
/// @notice Drives the ERC-1271 entry through solady's nested EIP-712 (ERC-7739) PersonalSign path: a
///         ROOT signer yields the magic value; a non-owner and a MANDATE-mode sig are rejected. Note: on
///         a rejected signature solady may revert (ERC-7739 probing) rather than return 0xffffffff — both
///         count as "not accepted", so the failure tests use a try/catch helper.
contract Daimon_erc1271_Integration_Test is Daimon_Integration_Test {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    /// @dev keccak256("PersonalSign(bytes prefixed)").
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A ROOT-signed message (over the nested PersonalSign digest) returns the magic value.
    function test_erc1271_rootSigner_returnsMagic() external view {
        // Arrange
        bytes32 hash = keccak256("approve-this");
        bytes memory sig = _rootSig(address(root1), rootPk, _personalSignDigest(hash));

        // Act & Assert
        assertEq(daimon.isValidSignature(hash, sig), MAGIC_VALUE, "ROOT owner sig must be valid");
    }

    /// @notice A signature from a non-owner key is not accepted.
    function test_erc1271_wrongSigner_notAccepted() external view {
        // Arrange: sign with the agent key, which is not an installed ROOT signer.
        bytes32 hash = keccak256("approve-this");
        bytes memory sig = _rootSig(address(root1), agentPk, _personalSignDigest(hash));

        // Act & Assert
        assertFalse(_accepts(hash, sig), "non-owner sig must not be accepted");
    }

    /// @notice A MANDATE-mode (0x01) signature is not accepted — MANDATE 1271 lands with the capability
    ///         work.
    function test_erc1271_mandateMode_notAccepted() external view {
        // Arrange: a MANDATE-mode payload over the nested digest.
        bytes32 hash = keccak256("intent");
        bytes memory sig = abi.encodePacked(bytes1(0x01), _sign(agentPk, _personalSignDigest(hash)));

        // Act & Assert
        assertFalse(_accepts(hash, sig), "MANDATE-mode 1271 must not be accepted today");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev True iff the account accepts `sig` (returns the ERC-1271 magic value). A revert — solady's
    ///      ERC-7739 may probe a rejected sig — counts as not-accepted.
    function _accepts(bytes32 hash, bytes memory sig) internal view returns (bool) {
        try daimon.isValidSignature(hash, sig) returns (bytes4 mv) {
            return mv == MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev The ERC-7739 PersonalSign digest solady reconstructs when no TypedDataSign data is
    ///      appended: `_hashTypedData(keccak256(PERSONAL_SIGN_TYPEHASH, hash))` over the account domain.
    function _personalSignDigest(bytes32 hash) internal view returns (bytes32) {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = daimon.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        bytes32 structHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, hash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
