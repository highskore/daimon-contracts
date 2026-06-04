// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";

// Libraries
import { EnforcementLib } from "@lib/EnforcementLib.sol";
import { MandateStorageLib } from "@lib/MandateStorageLib.sol";

// Types
import { MandateId } from "@types/MandateTypes.sol";

/// @title ExecLib
/// @author highskore.eth
/// @notice Direct-call execution for the Daimon account: decode the ERC-7579 single/batch (via solady's
///         {LibERC7579}), enforce the mandate's sigils per call on the MANDATE path, and run each call from
///         the account's own context. Extracted from the flagship so the account stays thin
///         and the batch path stays within stack limits without via-IR.
/// @dev Internal library: it runs in the account's context, so `address(this)` is the account. It operates on
///      the account's {MandateStorageLib.MandateStorage} pointer; authorization (ROOT / mandate bind+load) is
///      done by the account before calling in, and signalled via `root` + `pid`.
library ExecLib {
    /// @notice Enforce (when not ROOT) and execute an ERC-7579 single or batch execution. Reverts the whole
    ///         execution if any call's sigils reject it ({IDaimon.UnauthorizedExecution}), an outcome
    ///         sigil's post-condition fails, or a call reverts.
    /// @dev On the MANDATE path the call loop is bracketed by the mandate's per-execution outcome sigils:
    ///      every outcome sigil's {IOutcomeSigil.preCheck} runs before the first call (snapshotting state)
    ///      and its {IOutcomeSigil.postCheck} runs after the last (asserting the end-state invariant). A
    ///      post-check revert unwinds the whole execution (atomicity). The ROOT path is the unconstrained
    ///      owner, so it skips both the per-call sigils and the outcome hooks.
    /// @param $ The account's mandate storage.
    /// @param root True iff ROOT-authorized — the owner may execute anything, so sigils are skipped.
    /// @param pid The mandate id whose sigils gate the calls (MANDATE path; ignored when `root`).
    /// @param mode The ERC-7579 execution mode (first byte: 0 single, 1 batch).
    /// @param executionData The ERC-7579-encoded call(s).
    /// @return results Each call's return data, in order.
    function enforceAndExecute(
        MandateStorageLib.MandateStorage storage $,
        bool root,
        MandateId pid,
        bytes32 mode,
        bytes calldata executionData
    )
        internal
        returns (bytes[] memory results)
    {
        // MANDATE path only: snapshot pre-execution state for the mandate's outcome sigils. ROOT is the
        // unconstrained owner and is not bracketed.
        if (!root) EnforcementLib.runPreChecks($, pid);

        uint8 callType = uint8(LibERC7579.getCallType(mode));
        if (callType == 0) {
            (address to, uint256 value, bytes calldata data) =
                LibERC7579.decodeSingle(executionData);
            results = new bytes[](1);
            results[0] = _one($, root, pid, to, value, data);
        } else if (callType == 1) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
            if (pointers.length == 0) revert IDaimon.NotSupported();
            results = new bytes[](pointers.length);
            for (uint256 i; i < pointers.length; ++i) {
                (address to, uint256 value, bytes calldata data) =
                    LibERC7579.getExecution(pointers, i);
                results[i] = _one($, root, pid, to, value, data);
            }
        } else {
            revert IDaimon.NotSupported();
        }

        // MANDATE path only: assert the end-state invariant, forwarding the executed call set so an outcome
        // sigil can itemize per-call effects globally. A revert here unwinds the whole execution.
        if (!root) EnforcementLib.runPostChecks($, pid, mode, executionData);
    }

    /// @dev Enforce (unless ROOT) then run one call.
    function _one(
        MandateStorageLib.MandateStorage storage $,
        bool root,
        MandateId pid,
        address to,
        uint256 value,
        bytes calldata data
    )
        private
        returns (bytes memory)
    {
        if (!root && !EnforcementLib.enforceAction($, pid, to, value, data)) {
            revert IDaimon.UnauthorizedExecution();
        }
        return _run(to, value, data);
    }

    /// @dev Execute one call from the account's own context, bubbling any revert. `to == 0` => self.
    function _run(
        address to_,
        uint256 value,
        bytes calldata data
    )
        private
        returns (bytes memory ret)
    {
        address to = to_ == address(0) ? address(this) : to_;
        bool ok;
        (ok, ret) = to.call{ value: value }(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}
