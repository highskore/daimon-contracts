// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Types
import { MandateId, ActionId, Mandate } from "@types/MandateTypes.sol";

/// @title IdLib
/// @author highskore.eth
/// @notice Pure derivations for the identifiers used by the MANDATE layer: mandate ids, action ids,
///         and the per-(mandate, action) sigil config ids.
library IdLib {
    /// @notice Derive a mandate's `MandateId` from its session-key config + salt.
    /// @param s The mandate.
    /// @return keccak256(sessionValidator, sessionValidatorInitData, salt).
    function toMandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @notice Derive a scoped action's `ActionId` from a (target, selector) pair.
    /// @param target The call target.
    /// @param selector The selector invoked on `target`.
    /// @return keccak256(target, selector).
    function toActionId(address target, bytes4 selector) internal pure returns (ActionId) {
        return ActionId.wrap(keccak256(abi.encodePacked(target, selector)));
    }

    /// @notice Derive the `ConfigId` a sigil stores/reads config under, for a (mandate, action).
    /// @dev Cap and usage state is keyed per-mandate (`pid`): two mandates sharing the same session key
    ///      (same validator + initData but different `salt` → different `MandateId`) carry INDEPENDENT cap
    ///      state — their caps do NOT aggregate. A mandate builder issuing multiple mandates to one session
    ///      key must account for this: each mandate's budget is isolated, and the session key can spend up
    ///      to each mandate's cap independently.
    /// @param pid The mandate id.
    /// @param aid The action id.
    /// @return The sigil config id.
    function toConfigId(MandateId pid, ActionId aid) internal pure returns (ConfigId) {
        bytes32 id = keccak256(abi.encodePacked(MandateId.unwrap(pid), ActionId.unwrap(aid)));
        return ConfigId.wrap(id);
    }

    /// @notice Derive the `ConfigId` an outcome sigil stores/reads config under, for a mandate. Outcome
    ///         sigils are per-EXECUTION (per-mandate), not per-(target, selector), so the config id is
    ///         keyed by the mandate alone — domain-separated from {toConfigId} by a constant tag so it can
    ///         never collide with a per-action config id.
    /// @param pid The mandate id.
    /// @return The outcome-sigil config id.
    function toOutcomeConfigId(MandateId pid) internal pure returns (ConfigId) {
        bytes32 id = keccak256(abi.encodePacked("daimon.outcome", MandateId.unwrap(pid)));
        return ConfigId.wrap(id);
    }

    /// @notice Derive the `ConfigId` a per-mandate SIGNATURE (ERC-1271) sigil stores/reads config under, for a
    ///         mandate. Domain-separated from {toOutcomeConfigId} (outcome) and {toConfigId} (per-action) by a
    ///         distinct constant tag, so the signature tier can never collide with the outcome tier — even for a
    ///         single address that implements both {IOutcomeSigil} and {I1271Sigil} and is placed in both slots
    ///         of one mandate.
    /// @param pid The mandate id.
    /// @return The signature-sigil config id.
    function toSignatureConfigId(MandateId pid) internal pure returns (ConfigId) {
        bytes32 id = keccak256(abi.encodePacked("daimon.signature", MandateId.unwrap(pid)));
        return ConfigId.wrap(id);
    }
}
