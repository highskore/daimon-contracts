// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ISessionValidator
/// @author highskore.eth
/// @notice Stateless verifier for a session key's signature. The session's `sessionValidatorInitData` (e.g.
///         an encoded signer address or P256 pubkey) is supplied as `data` on every call, so the validator
///         holds no per-session storage. Mirrors the smart-sessions ISessionValidator pattern.
/// @dev Distinct from {IDaimonValidator} (the ROOT layer): ROOT validators store a per-account credential and
///      authorize the *owner*; session validators are stateless and authorize a *scoped session key*.
interface ISessionValidator {
    /// @notice Verify `signature` over `hash` against the credential encoded in `data`.
    /// @param hash The digest that was signed (the EIP-712 execution digest).
    /// @param signature The session key's signature.
    /// @param data The session's `sessionValidatorInitData` (scheme-specific credential).
    /// @return True iff the signature is valid for the supplied credential.
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        returns (bool);
}
