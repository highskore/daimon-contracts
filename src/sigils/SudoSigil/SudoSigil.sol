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

// forgefmt: disable-start
///  ________ _   _______ _____   _____ _____ _____ _____ _
/// /  ___| | | |  _  \  _  | |  /  ___|_   _|  __ \_   _| |
/// \ `--.| | | | | | | | | | |  \ `--.  | | | |  \/ | | | |
///  `--. \ | | | | | | | | | |   `--. \ | | | | __  | | | |
/// /\__/ / |_| | |/ /\ \_/ / |  /\__/ /_| |_| |_\ \_| |_| |____
/// \____/ \___/|___/  \___/|_|  \____/ \___/ \____/\___/\_____/
///
///   allow-all ─ reads NO calldata, holds NO state, always succeeds
// forgefmt: disable-end
/// @title SudoSigil — the unconditional allow-all policy
/// @author highskore.eth
/// @notice The minimal {IActionSigil}: it permits the configured `(target, selector)` action with ANY arguments
///         and ANY ETH value, reading no calldata and holding no state. It is the "allow this function with
///         any args" policy — the on-chain expression of a no-constraint mandate.
/// @dev Why it exists: a no-POLICY action is denied (the engine treats an empty policy list as deny), so even
///      an unconstrained action still needs *a* policy attached. {OmniSigil} can express "any args" with an
///      always-true rule, but every OmniSigil rule reads a fixed calldata word via a REVERTING slice
///      (`data[4+offset:36+offset]`) — which reverts for a 0-argument call (4-byte calldata). The SudoSigil
///      sidesteps that entirely: it returns success without ever touching calldata, so it supports 0-argument
///      functions and any "allow with any args" policy without padding the calldata.
///
///      Lineage: ports the `SudoPolicy` pattern from erc7579/smartsessions (an always-`VALIDATION_SUCCESS`
///      policy) to the Daimon {IActionSigil} surface. A sigil is the symbol that binds a daimon to its allowed
///      behavior; the SudoSigil binds it to nothing beyond the action's `(target, selector)` scope itself —
///      default-deny still confines the call to exactly that target and selector, set by the engine.
///
///      Like every sigil it is configured per account by the MANDATE engine via {initializeWithMultiplexer};
///      here that is a pure no-op (there is nothing to store), so unlike other sigils it has no
///      `PolicyNotInitialized` guard — an uninitialized SudoSigil and an initialized one behave identically
///      (always allow). It writes no state and reverts on nothing.
contract SudoSigil is IActionSigil {
    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
    /// @dev No-op: the SudoSigil stores no configuration. Accepts (and ignores) any `initData`, including
    ///      empty `0x`. Emits {SigilSet} so the configure step is observable on-chain like any other sigil.
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata
    )
        external
    {
        emit ISigilBase.SigilSet(configId, msg.sender, account);
    }

    /*·:⛧:·──────── CHECK ────────:⛧:·*/

    /// @inheritdoc IActionSigil
    /// @dev Always permits. Reads no `data`, enforces no `value` cap — the action is allowed with any
    ///      arguments and any ETH value. The action's `(target, selector)` scope (enforced by the engine) is
    ///      the only constraint.
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

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the action tier only: {IERC165}, {ISigilBase}, {IActionSigil}.
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IActionSigil).interfaceId;
    }
}
