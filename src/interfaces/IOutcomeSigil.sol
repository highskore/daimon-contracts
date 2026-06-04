// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { ISigilBase, ConfigId } from "@interfaces/ISigil.sol";

/*·:⛧:·──────── IOUTCOMESIGIL ────────:⛧:·*/

/// @title IOutcomeSigil
/// @author highskore.eth
/// @notice An *outcome sigil* is a per-EXECUTION policy that brackets the whole call set with a
///         pre/post pair, rather than gating each call independently like {IActionSigil.checkAction}. It
///         snapshots state before the calls run (`preCheck`) and asserts an end-state invariant after
///         they finish (`postCheck`), so it can enforce *cumulative* outcomes — e.g. a rolling spend
///         cap measured by the account's net balance delta — that a per-call view cannot.
/// @dev Two-tier hook model. {IActionSigil.checkAction} is the per-CALL gate, run inside the execution loop;
///      the two methods here are the per-EXECUTION bracket, run once before and once after that loop.
///      Like every sigil, an outcome sigil keys its config by `(configId, msg.sender, account)`; the
///      engine is baked into the account, so `msg.sender == account` at runtime. The hooks run on the
///      MANDATE path only — the ROOT (owner) path is unconstrained and skips them.
///
///      ATOMICITY: `preCheck` and `postCheck` run inside the same atomic execution as the calls, so a
///      `postCheck` revert rolls the entire execution back. State written by `postCheck` (e.g. the
///      accrued spend) therefore only persists when the whole execution succeeds.
interface IOutcomeSigil is ISigilBase {
    /// @notice Snapshot the pre-execution state needed to evaluate the outcome invariant.
    /// @dev Called once, before the execution's call loop, on the MANDATE path. Implementations should
    ///      stash whatever baseline they need (typically in EIP-1153 transient storage, which clears at
    ///      the end of the transaction) keyed by `(id, msg.sender, account)`.
    /// @param id The configuration identifier.
    /// @param account The account whose execution is being bracketed.
    function preCheck(ConfigId id, address account) external;

    /// @notice Assert the end-state invariant after the execution's calls have run; revert on violation.
    /// @dev Called once, after the execution's call loop, on the MANDATE path. A revert here unwinds the
    ///      whole execution (atomicity). Implementations compare the post-execution state against the
    ///      baseline taken in {preCheck} and persist any cumulative accounting only on success.
    ///
    ///      The executed ERC-7579 call set (`mode` + `executionData`, exactly as decoded by the engine for
    ///      the loop) is forwarded so an outcome sigil can ITEMIZE per-call effects globally — it can decode
    ///      and sum every call's contribution itself, with no dependence on a per-call {IActionSigil.checkAction}
    ///      attachment. This lets a cumulative invariant (e.g. a calldata-summed spend cap) be complete
    ///      regardless of which action sigils gate the calls.
    /// @param id The configuration identifier.
    /// @param account The account whose execution is being bracketed.
    /// @param mode The ERC-7579 execution mode (first byte: 0 single, 1 batch).
    /// @param executionData The ERC-7579-encoded call(s) that just executed.
    function postCheck(
        ConfigId id,
        address account,
        bytes32 mode,
        bytes calldata executionData
    )
        external;
}
