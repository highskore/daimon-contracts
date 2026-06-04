// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IRootRegistry
/// @author highskore.eth
/// @notice Events, errors, and read accessors for the ROOT auth layer (the installable OR-set of owner
///         schemes).
interface IRootRegistry {
    /// @notice Emitted when a ROOT scheme is installed. The scheme is active immediately.
    /// @param validator The installed scheme.
    event RootValidatorInstalled(address indexed validator);

    /// @notice Emitted when a ROOT scheme is removed.
    /// @param validator The removed scheme.
    event RootValidatorUninstalled(address indexed validator);

    /// @notice Thrown when installing a scheme that is already installed.
    /// @param validator The duplicate scheme.
    error RootAlreadyInstalled(address validator);

    /// @notice Thrown when removing a scheme that is not installed.
    /// @param validator The missing scheme.
    error RootNotInstalled(address validator);

    /// @notice Thrown when a removal would leave the account with no ROOT scheme (would brick it).
    error CannotRemoveLastRoot();

    /// @notice The installed ROOT schemes (the OR-set).
    /// @return The scheme addresses.
    function rootValidators() external view returns (address[] memory);

    /// @notice Whether a scheme is installed (and thus an active ROOT owner).
    /// @param validator The scheme.
    /// @return True iff installed.
    function isRootInstalled(address validator) external view returns (bool);
}
