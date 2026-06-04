// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import {
    IActionSigil,
    ISigilBase,
    IERC165,
    ConfigId,
    VALIDATION_SUCCESS
} from "@interfaces/ISigil.sol";
// Types
import { MandateId } from "@types/MandateTypes.sol";

/// @dev The single account view this mock probes during init. {MandateEngine.isMandateBound} is a public
///      function on the abstract engine (not on {IMandateEngine}), so the mock declares the minimal surface.
interface IMandateBoundView {
    function isMandateBound(MandateId pid) external view returns (bool);
}

/// @title MockReentrantInitSigil
/// @author highskore.eth
/// @notice A test-only {IActionSigil} that, during {initializeWithMultiplexer} (the per-sigil init the engine
///         calls WHILE registering a mandate), reenters the account to read {IMandateEngine.isMandateBound} for a
///         pid carried in its `initData`, and records what it observed. This witnesses the CEI ordering of
///         {MandateEngine._registerMandate}: a sigil whose init runs mid-registration must NOT yet see the
///         mandate as enabled (the `enabled` flag is set LAST, after every sigil is wired). If it observed
///         `true`, the enable flag was flipped before the sigil loops — a reentrant MANDATE_USE would see a
///         partially-configured-but-enabled mandate.
/// @dev Advertises {IActionSigil} via ERC-165 so it passes the engine's registration-time interface gate (it is
///      wired as an action sigil in the tests).
contract MockReentrantInitSigil is IActionSigil {
    /// @notice The value {IMandateEngine.isMandateBound} returned when this sigil's init reentered the account.
    bool public observedBound;
    /// @notice Whether init ran (so a test can assert the reentrant read actually happened).
    bool public initRan;

    /// @inheritdoc ISigilBase
    /// @dev `msg.sender` is the account/engine. `initData` carries the pid to probe. Reenter and record.
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
    {
        MandateId pid = abi.decode(initData, (MandateId));
        observedBound = IMandateBoundView(msg.sender).isMandateBound(pid);
        initRan = true;
        emit ISigilBase.SigilSet(configId, msg.sender, account);
    }

    /// @inheritdoc IActionSigil
    function checkAction(
        ConfigId,
        address,
        address,
        uint256,
        bytes calldata
    )
        external
        pure
        returns (uint256)
    {
        return VALIDATION_SUCCESS;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IActionSigil).interfaceId;
    }
}
