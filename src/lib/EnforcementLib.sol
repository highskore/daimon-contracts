// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";
import { IOutcomeSigil } from "@interfaces/IOutcomeSigil.sol";

// Libraries
import { IdLib } from "@lib/IdLib.sol";
import { MandateStorageLib } from "@lib/MandateStorageLib.sol";
import { RootStorageLib } from "@lib/RootStorageLib.sol";

// Types
import {
    MandateId,
    ActionId,
    FALLBACK_TARGET_FLAG,
    FALLBACK_ACTIONID
} from "@types/MandateTypes.sol";

/// @title EnforcementLib
/// @author highskore.eth
/// @notice The centralized sigil-enforcement loops for the Daimon account's MANDATE layer — Daimon's
///         PolicyLib-equivalent. Holds the three places a mandate's sigils are evaluated: the per-call
///         action gate ({enforceAction}), the per-execution outcome checks ({runPreChecks}/{runPostChecks}), and the
///         per-mandate ERC-1271 signature gate ({enforce1271}). Decode + execute live in {ExecLib} and the
///         BIND/USE orchestration lives in {MandateEngine}; both call into here for the actual checks, so
///         the enforcement semantics live in one place.
/// @dev Internal library: every function runs in the account's context (it is baked into the account), so
///      `address(this)` is the account and `msg.sender` to every sigil is the account itself. Each function
///      operates on the account's {MandateStorageLib.MandateStorage} pointer; authorization (ROOT / mandate
///      bind+load) is performed by the caller before invoking these checks.
library EnforcementLib {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /// @notice Default-deny per-call sigil check — modelled on smart-sessions-v2's
    ///         `PolicyLib.checkSingle7579Exec`. `to == address(0)` resolves to the account (matching
    ///         execution) before deriving the ActionId, so a self-call cannot slip past a target-scoped
    ///         sigil. A session may never target the account itself (a nested-execution bypass guard —
    ///         smart-sessions reverts `InvalidSelfCall`; we default-deny it). Returns `false` for the deny
    ///         path so the caller can revert with its own error; reverting on a non-`VALIDATION_SUCCESS`
    ///         sigil is the caller's responsibility (see {ExecLib}).
    /// @param $ The account's mandate storage.
    /// @param pid The mandate id whose action sigils gate the call.
    /// @param to_ The call target (`address(0)` resolves to the account).
    /// @param value The ETH value being sent with the call.
    /// @param data The calldata of the action (inner call: selector ++ args).
    /// @return True iff a sigil set gates the call — the EXACT (target, selector) action, or (ONLY when that has
    ///         none) the wildcard FALLBACK action — and EVERY sigil in it returns `VALIDATION_SUCCESS`. False
    ///         otherwise: a self-call, a call to the {FALLBACK_TARGET_FLAG} sentinel, no exact AND no fallback
    ///         sigil configured, or any sigil rejection. An exact action that REJECTS does not fall back.
    function enforceAction(
        MandateStorageLib.MandateStorage storage $,
        MandateId pid,
        address to_,
        uint256 value,
        bytes calldata data
    )
        internal
        returns (bool)
    {
        address to = to_ == address(0) ? address(this) : to_;
        if (to == address(this)) return false; // no session self-calls (nested-exec bypass guard)
        if (to == FALLBACK_TARGET_FLAG) return false; // the fallback sentinel is never a real call target
        // The account's auth/policy state is SHARDED across external singletons — its ROOT validators
        // ({RootStorageLib}) and its policy sigils — each keyed by the account address and mutated on
        // `msg.sender == account`. During a MANDATE execution the account IS `msg.sender` to any non-self target,
        // so a call to one of these (e.g. `ECDSAValidator.onInstall` to overwrite the ROOT signer, or a sigil's
        // `initializeWithMultiplexer` to raise its own cap) is a self-call in disguise. Default-deny them, the
        // sharded-state analogue of the `to == address(this)` guard above (smart-sessions gets this for free — its
        // policy module is a SEPARATE address from the account, so the config key never collides; Daimon bakes the
        // engine into the account, so it must deny explicitly). Validators are a small account-wide set (full ROOT-
        // takeover coverage); sigils are checked against THIS mandate's own set (`pid` is in hand here) — closing
        // the headline self-cap-raise. See {MandateStorageLib.mandateSigils} for the cross-mandate residual.
        if (RootStorageLib.load().validators.contains(to)) return false; // an installed ROOT validator
        if ($.mandateSigils[pid].contains(to)) return false; // one of THIS mandate's own policy sigils
        ActionId aid = IdLib.toActionId(to, data.length >= 4 ? bytes4(data[0:4]) : bytes4(0));
        address[] memory sigils = $.actionSigils[aid][pid].values();
        if (sigils.length == 0) {
            // The exact (target, selector) has no sigils. Distinguish a REGISTERED-but-empty action (a
            // misconfigured exact action whose `aid` IS in the mandate's action set) from an UNREGISTERED one
            // (no entry at all). Only an UNREGISTERED action falls back to the wildcard — a registered-but-empty
            // action keeps its existing default-DENY so the fallback can never broaden an owner-signed exact
            // action beyond its explicit shape. Exact matches always take precedence (checked first); the
            // fallback only fills a genuine gap, and its sigils are checked against the REAL (`to`, `value`,
            // `data`) under the shared fallback config id (compose value/time/spend sigils to bound it).
            if ($.actionIds[pid].contains(ActionId.unwrap(aid))) return false; // registered but empty -> deny
            aid = FALLBACK_ACTIONID;
            sigils = $.actionSigils[FALLBACK_ACTIONID][pid].values();
            if (sigils.length == 0) return false; // unregistered AND no fallback -> deny
        }

        ConfigId cid = IdLib.toConfigId(pid, aid); // FALLBACK_ACTIONID when we fell back
        for (uint256 j; j < sigils.length; ++j) {
            if (
                IActionSigil(sigils[j]).checkAction(cid, address(this), to, value, data)
                    != VALIDATION_SUCCESS
            ) {
                return false;
            }
        }
        return true;
    }

    /// @notice Run every outcome sigil's pre-execution snapshot ({IOutcomeSigil.preCheck}) before the
    ///         mandate's call loop. No-op when the mandate has no outcome sigils.
    /// @param $ The account's mandate storage.
    /// @param pid The mandate whose outcome sigils to snapshot.
    function runPreChecks(MandateStorageLib.MandateStorage storage $, MandateId pid) internal {
        address[] memory sigils = $.outcomeSigils[pid].values();
        if (sigils.length == 0) return;
        ConfigId cid = IdLib.toOutcomeConfigId(pid);
        for (uint256 i; i < sigils.length; ++i) {
            IOutcomeSigil(sigils[i]).preCheck(cid, address(this));
        }
    }

    /// @notice Run every outcome sigil's post-execution assertion ({IOutcomeSigil.postCheck}) after the
    ///         mandate's call loop, forwarding the executed ERC-7579 call set so each sigil can itemize
    ///         per-call effects globally. A revert here unwinds the whole execution (atomicity). No-op when
    ///         the mandate has no outcome sigils.
    /// @param $ The account's mandate storage.
    /// @param pid The mandate whose outcome sigils to assert.
    /// @param mode The ERC-7579 execution mode (first byte: 0 single, 1 batch).
    /// @param executionData The ERC-7579-encoded call(s) that just executed.
    function runPostChecks(
        MandateStorageLib.MandateStorage storage $,
        MandateId pid,
        bytes32 mode,
        bytes calldata executionData
    )
        internal
    {
        address[] memory sigils = $.outcomeSigils[pid].values();
        if (sigils.length == 0) return;
        ConfigId cid = IdLib.toOutcomeConfigId(pid);
        for (uint256 i; i < sigils.length; ++i) {
            IOutcomeSigil(sigils[i]).postCheck(cid, address(this), mode, executionData);
        }
    }

    /// @notice The per-mandate ERC-1271 signature-sigil gate: require EVERY configured signature sigil to
    ///         approve the attested content via {I1271Sigil.check1271}. View-only (runs under solady's 1271
    ///         STATICCALL). Returns `false` on the first non-`VALIDATION_SUCCESS` sigil (default-deny) —
    ///         it never reverts, so the caller can fail the 1271 check closed.
    /// @param $ The account's mandate storage.
    /// @param pid The mandate id (the caller has already checked it is enabled with a non-empty signature
    ///        sigil set).
    /// @param gated The `abi.encode(sender, hash, appDomainSeparator, contentsHash, content)` payload each signature sigil reads to gate the
    ///        requesting sender (anti-phishing) and the real `hash`.
    /// @return True iff EVERY configured signature sigil returns `VALIDATION_SUCCESS`; false otherwise.
    function enforce1271(
        MandateStorageLib.MandateStorage storage $,
        MandateId pid,
        bytes memory gated
    )
        internal
        view
        returns (bool)
    {
        address[] memory sigils = $.signatureSigils[pid].values();
        ConfigId cid = IdLib.toSignatureConfigId(pid);
        for (uint256 i; i < sigils.length; ++i) {
            if (I1271Sigil(sigils[i]).check1271(cid, address(this), gated) != VALIDATION_SUCCESS) {
                return false;
            }
        }
        return true;
    }
}
