// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

// Interfaces
import { IDaimonValidator } from "@interfaces/IDaimonValidator.sol";

/// @title ECDSAValidator
/// @author highskore.eth
/// @notice secp256k1 ROOT auth scheme for Daimon (EOA / hardware-wallet owner). A singleton; each
///         account installs its own signer. Verification accepts a plain ECDSA signature, and also an
///         ERC-1271 signature if the configured signer is itself a contract (via SignatureCheckerLib).
contract ECDSAValidator is IDaimonValidator {
    /// @notice account => authorized signer address.
    mapping(address account => address signer) public signerOf;

    /// @notice Thrown when installing the zero address as the signer.
    error InvalidSigner();

    /// @inheritdoc IDaimonValidator
    function onInstall(bytes calldata data) external {
        address signer = abi.decode(data, (address));
        if (signer == address(0)) revert InvalidSigner();
        signerOf[msg.sender] = signer;
    }

    /// @inheritdoc IDaimonValidator
    function onUninstall(bytes calldata) external {
        delete signerOf[msg.sender];
    }

    /// @inheritdoc IDaimonValidator
    function isValidSignature(
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool)
    {
        address signer = signerOf[account];
        if (signer == address(0)) return false;
        return SignatureCheckerLib.isValidSignatureNowCalldata(signer, hash, signature);
    }
}
