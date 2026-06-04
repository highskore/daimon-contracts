// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IDaimonValidator
/// @author highskore.eth
/// @notice A pluggable ROOT auth scheme (e.g. secp256k1, P256/WebAuthn). Installed per-account into the
///         account's ROOT OR-set. The account calls these with `msg.sender == account`, so a validator keys
///         its per-account credential by `msg.sender`.
interface IDaimonValidator {
    /// @notice Store the account's credential. Called by the account (msg.sender == account).
    /// @param data ABI-encoded credential (scheme-specific, e.g. an address or a P256 pubkey).
    function onInstall(bytes calldata data) external;

    /// @notice Clear the account's credential. Called by the account (msg.sender == account).
    function onUninstall(bytes calldata data) external;

    /// @notice Verify `signature` over `hash` for `account` under this scheme.
    /// @param account The account whose credential to check against.
    /// @param hash The digest that was signed.
    /// @param signature The scheme-specific signature.
    /// @return True iff the signature is valid for the account's stored credential.
    function isValidSignature(
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool);
}
