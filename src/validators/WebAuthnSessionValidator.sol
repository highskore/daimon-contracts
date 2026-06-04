// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { WebAuthn } from "solady/utils/WebAuthn.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

/// @title WebAuthnSessionValidator
/// @author highskore.eth
/// @notice Stateless P256/WebAuthn (passkey) session-key verifier — the scheme-pluggable sibling of
///         {ECDSASessionValidator}, so a mandate can bind a HARDWARE-BACKED agent credential (a passkey in a
///         secure enclave / device) instead of a hot ECDSA key. The agent's session credential travels in
///         `data` on every call (stateless; no per-session storage, mirroring {ECDSASessionValidator}); the
///         `hash` is the WebAuthn challenge and `signature` is an ABI-encoded {WebAuthn.WebAuthnAuth}. Cheap
///         where RIP-7212 is available (Base), pure-EVM fallback otherwise (solady {WebAuthn}).
/// @dev Credential layout (`data` = the mandate's `sessionValidatorInitData`):
///      `abi.encode(bytes32 x, bytes32 y, bool requireUV)` — the P256 public key + whether user-verification
///      is required. Unlike the ROOT {WebAuthnValidator} (which hardcodes UV=true for a human owner), a
///      session passkey lets the BINDER choose: an interactive agent credential can require UV, an autonomous
///      one (no human present to verify) can set it false. Either way the key is still bounded by the mandate.
contract WebAuthnSessionValidator is ISessionValidator {
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
        (bytes32 x, bytes32 y, bool requireUV) = abi.decode(data, (bytes32, bytes32, bool));
        // Reject a zero/degenerate pubkey: an all-zero key is the empty/uninstalled sentinel, and a half-zero
        // key (x or y == 0) is never a valid P256 point. OR (not AND) mirrors {WebAuthnValidator.onInstall}'s
        // guard, so a degenerate credential is rejected before reaching WebAuthn.verify.
        if (x == bytes32(0) || y == bytes32(0)) return false;
        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));
        // The signed challenge is the execution digest; verification falls back to pure-EVM P256 off RIP-7212.
        return WebAuthn.verify(abi.encode(hash), requireUV, auth, x, y);
    }
}
