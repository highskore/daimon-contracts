// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { RootStorageLib } from "@lib/RootStorageLib.sol";

// Interfaces
import { IDaimonValidator } from "@interfaces/IDaimonValidator.sol";
import { IRootRegistry } from "@interfaces/IRootRegistry.sol";

/// @title RootRegistry
/// @author highskore.eth
/// @notice The ROOT auth layer: an OR-set of installed {IDaimonValidator} schemes (passkey/WebAuthn,
///         secp256k1, ...). Any one installed scheme authorizes; the signature names which. Exposes the
///         shared {_isOwner} primitive used by the account's direct-call (ERC-1608) / ERC-1271 ROOT path
///         and the MANDATE engine's mandate-bind check.
/// @dev Guard: the last installed scheme can't be removed (would brick the account). An installed
///      scheme is active immediately — membership in the set is the only notion of "active", there is no
///      activation delay. `_isOwner` returns false (never reverts) on an unknown scheme, composing
///      cleanly inside signature validation. State lives in {RootStorageLib}.
abstract contract RootRegistry is IRootRegistry {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*·:⛧:·──────── MUTATIONS ────────:⛧:·*/

    /// @dev Install a scheme. The scheme is active immediately on install.
    /// @param validator The scheme to install.
    /// @param initData The scheme's credential data.
    function _installRoot(address validator, bytes memory initData) internal {
        RootStorageLib.RootStorage storage $ = RootStorageLib.load();
        if (!$.validators.add(validator)) revert RootAlreadyInstalled(validator);
        IDaimonValidator(validator).onInstall(initData);
        emit RootValidatorInstalled(validator);
    }

    /// @dev Remove a scheme. Cannot remove the last one (would brick the account).
    /// @param validator The scheme to remove.
    /// @param deinitData Optional teardown data passed to the scheme.
    function _removeRoot(address validator, bytes memory deinitData) internal {
        RootStorageLib.RootStorage storage $ = RootStorageLib.load();
        if (!$.validators.contains(validator)) revert RootNotInstalled(validator);
        if ($.validators.length() <= 1) revert CannotRemoveLastRoot();
        $.validators.remove(validator);
        IDaimonValidator(validator).onUninstall(deinitData);
        emit RootValidatorUninstalled(validator);
    }

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @inheritdoc IRootRegistry
    function rootValidators() public view returns (address[] memory) {
        return RootStorageLib.load().validators.values();
    }

    /// @inheritdoc IRootRegistry
    function isRootInstalled(address validator) public view returns (bool) {
        return RootStorageLib.load().validators.contains(validator);
    }

    /*·:⛧:·──────── OWNER CHECK ────────:⛧:·*/

    /// @dev OR-set owner check (packed form), for the direct-call / ERC-1271 ROOT path. `sig` is
    ///      `[20-byte validator address][scheme signature]`.
    /// @param hash The digest that was signed.
    /// @param sig The packed validator + scheme signature.
    /// @return True iff an installed scheme verifies the signature.
    function _isOwner(bytes32 hash, bytes calldata sig) internal view returns (bool) {
        if (sig.length < 20) return false;
        return _verifyRoot(address(bytes20(sig[0:20])), hash, sig[20:]);
    }

    /// @dev OR-set owner check (explicit form), for callers holding the validator + signature
    /// separately in memory (e.g. the MANDATE bind path decoding a struct).
    /// @param validator The scheme to check against.
    /// @param hash The digest that was signed.
    /// @param innerSig The scheme signature.
    /// @return True iff the scheme is installed and verifies the signature.
    function _isOwner(
        address validator,
        bytes32 hash,
        bytes memory innerSig
    )
        internal
        view
        returns (bool)
    {
        return _verifyRoot(validator, hash, innerSig);
    }

    /// @dev Core check: the scheme must be installed. `innerSig` may be calldata or memory; it is
    /// ABI-encoded for the external call either way.
    /// @param validator The scheme.
    /// @param hash The digest that was signed.
    /// @param innerSig The scheme signature.
    /// @return True iff valid.
    function _verifyRoot(
        address validator,
        bytes32 hash,
        bytes memory innerSig
    )
        private
        view
        returns (bool)
    {
        if (!isRootInstalled(validator)) return false;
        return IDaimonValidator(validator).isValidSignature(address(this), hash, innerSig);
    }
}
