// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { RootRegistry } from "@core/RootRegistry.sol";

/// @title RootRegistryHarness
/// @author highskore.eth
/// @notice Concrete {RootRegistry} for unit testing: exposes the abstract layer's internal mutators and
///         owner-check primitive as external wrappers so the ROOT install/remove and OR-set
///         verification logic can be driven directly, without an enclosing account. Test-only.
/// @dev The harness *is* the account from each validator's perspective — it is the `msg.sender` on the
///      `onInstall`/`onUninstall`/`isValidSignature` calls, so a scheme keys its credential by this
///      contract's address. The public `isRootInstalled`/`rootValidators` views are inherited as-is.
contract RootRegistryHarness is RootRegistry {
    /*//////////////////////////////////////////////////////////////
                              MUTATORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Install a scheme (active immediately).
    /// @param validator The scheme to install.
    /// @param initData The scheme's credential data.
    function installRoot(address validator, bytes calldata initData) external {
        _installRoot(validator, initData);
    }

    /// @notice Remove an installed scheme.
    /// @param validator The scheme to remove.
    /// @param deinitData Optional teardown data passed to the scheme.
    function removeRoot(address validator, bytes calldata deinitData) external {
        _removeRoot(validator, deinitData);
    }

    /*//////////////////////////////////////////////////////////////
                            OWNER CHECK
    //////////////////////////////////////////////////////////////*/

    /// @notice OR-set owner check (packed form): `sig` is `[20-byte validator][scheme signature]`.
    /// @param hash The digest that was signed.
    /// @param sig The packed validator + scheme signature.
    /// @return True iff an installed scheme verifies the signature.
    function isOwnerPacked(bytes32 hash, bytes calldata sig) external view returns (bool) {
        return _isOwner(hash, sig);
    }

    /// @notice OR-set owner check (explicit form): validator + inner signature held separately.
    /// @param validator The scheme to check against.
    /// @param hash The digest that was signed.
    /// @param innerSig The scheme signature.
    /// @return True iff the scheme is installed and verifies the signature.
    function isOwnerExplicit(
        address validator,
        bytes32 hash,
        bytes calldata innerSig
    )
        external
        view
        returns (bool)
    {
        return _isOwner(validator, hash, innerSig);
    }
}
