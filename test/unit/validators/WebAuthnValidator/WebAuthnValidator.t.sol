// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { WebAuthnValidator } from "@validators/WebAuthnValidator.sol";

// Libraries
import { WebAuthn } from "solady/utils/WebAuthn.sol";

/// @title WebAuthnValidator_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for WebAuthnValidator unit suites: deploys the singleton P256/passkey scheme
///         and seeds a sample (non-zero) public key. The test contract itself plays the *account* — it is
///         `msg.sender` on `onInstall`, so the credential is keyed by `address(this)`.
abstract contract WebAuthnValidator_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev A sample (structurally valid, non-zero) P256 public key. Not tied to any private key — we never
    ///      need to produce a *valid* signature for it (that path is a known gap, see the suites below).
    bytes32 internal constant PUBKEY_X =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 internal constant PUBKEY_Y =
        0x2222222222222222222222222222222222222222222222222222222222222222;

    /// @dev A digest reused across signature tests (used as the WebAuthn challenge).
    bytes32 internal constant DIGEST = keccak256("daimon.webauthn.digest");

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    WebAuthnValidator internal validator;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        validator = new WebAuthnValidator();
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev ABI-encode a P256 pubkey for `onInstall`.
    function _pubKey(bytes32 x, bytes32 y) internal pure returns (bytes memory) {
        return abi.encode(x, y);
    }

    /// @dev A structurally well-formed but cryptographically invalid {WebAuthn.WebAuthnAuth} blob: it
    ///      decodes cleanly (so `isValidSignature` does not revert on decode) but cannot pass verification.
    function _malformedAuth() internal pure returns (bytes memory) {
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"",
            clientDataJSON: "",
            challengeIndex: 0,
            typeIndex: 0,
            r: bytes32(0),
            s: bytes32(0)
        });
        return abi.encode(auth);
    }
}
