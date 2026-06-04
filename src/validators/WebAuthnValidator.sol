// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { WebAuthn } from "solady/utils/WebAuthn.sol";

// Interfaces
import { IDaimonValidator } from "@interfaces/IDaimonValidator.sol";

/// @title WebAuthnValidator
/// @author highskore.eth
/// @notice P256/WebAuthn (passkey) ROOT auth scheme for Daimon. A singleton; each account installs its own
///         public key (x, y). The `hash` is used as the WebAuthn challenge; the signature ABI-encodes a
///         {WebAuthn.WebAuthnAuth}. User verification (UV) is REQUIRED. Cheap where RIP-7212 is available
///         (Base), pure-EVM fallback otherwise.
contract WebAuthnValidator is IDaimonValidator {
    /// @notice A P256 public key (the passkey credential's curve point).
    /// @param x The x coordinate.
    /// @param y The y coordinate.
    struct PubKey {
        bytes32 x;
        bytes32 y;
    }

    /// @notice account => P256 public key.
    mapping(address account => PubKey) public pubKeyOf;

    /// @notice Thrown when installing an all-zero public key (the uninstalled sentinel).
    error InvalidPubKey();

    /// @inheritdoc IDaimonValidator
    function onInstall(bytes calldata data) external {
        (bytes32 x, bytes32 y) = abi.decode(data, (bytes32, bytes32));
        if (x == bytes32(0) || y == bytes32(0)) revert InvalidPubKey();
        pubKeyOf[msg.sender] = PubKey(x, y);
    }

    /// @inheritdoc IDaimonValidator
    function onUninstall(bytes calldata) external {
        delete pubKeyOf[msg.sender];
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
        PubKey memory pk = pubKeyOf[account];
        // Reject a missing OR half-zero (degenerate, off-curve) credential, matching {onInstall}'s `||` guard
        // (a P256 point with either coordinate zero is not on the curve). `||` keeps install and verify
        // symmetric; the prior `&&` only caught the all-zero (uninstalled) case.
        if (pk.x == bytes32(0) || pk.y == bytes32(0)) return false;
        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));
        // requireUserVerification = true: a ROOT passkey must assert user verification (the UV bit in
        // authenticatorData), so a present-but-unverified credential cannot authorize. The challenge is the
        // signed digest.
        return WebAuthn.verify(abi.encode(hash), true, auth, pk.x, pk.y);
    }
}
