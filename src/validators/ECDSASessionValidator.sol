// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

/// @title ECDSASessionValidator
/// @author highskore.eth
/// @notice Stateless secp256k1 session-key verifier. The agent's hot key is encoded in `data` as
///         `abi.encode(address signer)`; also accepts an ERC-1271 contract signer via SignatureCheckerLib.
contract ECDSASessionValidator is ISessionValidator {
    /// @inheritdoc ISessionValidator
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        returns (bool)
    {
        address signer = abi.decode(data, (address));
        if (signer == address(0)) return false;
        return SignatureCheckerLib.isValidSignatureNowCalldata(signer, hash, signature);
    }
}
