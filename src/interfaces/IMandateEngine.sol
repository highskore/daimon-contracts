// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { MandateId, ActionId } from "@types/MandateTypes.sol";

/// @title IMandateEngine
/// @author highskore.eth
/// @notice Events, errors, and read accessors for the baked MANDATE layer (mandate enable/use).
interface IMandateEngine {
    /// @notice Emitted when a mandate is enabled (persisted) for the account.
    /// @param mandateId The enabled mandate's id.
    event MandateBound(MandateId indexed mandateId);

    /// @notice Emitted when a mandate is revoked (killed) for the account.
    /// @param mandateId The revoked mandate's id.
    event MandateRevoked(MandateId indexed mandateId);

    /// @notice Thrown when the ROOT signature over a mandate-enable digest does not verify.
    /// @param mandateId The mandate that failed authorization.
    error UnauthorizedBind(MandateId mandateId);

    /// @notice Thrown when a mandate BIND is submitted after the signed bind-authorization deadline
    ///         (`validUntil`) has passed — enforced ONCE at bind time, not a runtime expiry. `validUntil == 0`
    ///         is the open sentinel (no deadline).
    /// @param mandateId The mandate whose bind deadline was exceeded.
    /// @param validUntil The signed bind deadline (unix seconds, inclusive) that was exceeded.
    error BindExpired(MandateId mandateId, uint48 validUntil);

    /// @notice Thrown on a MULTICHAIN bind when THIS chain's selected entry does not match the local state:
    ///         either its `chainId` is not `block.chainid`, or its `bindDigest` is not the digest this chain
    ///         recomputes for the carried mandate at the current per-mandate nonce. Deliberately a SINGLE error
    ///         covering both cases — it never leaks to a relayer WHICH check failed (wrong chain selection vs.
    ///         a forged/stale digest). Note same-chain replay also surfaces here: after a successful bind the
    ///         per-mandate nonce increments, so a re-submitted array's `bindDigest` no longer matches.
    /// @param mandateId The mandate whose multichain bind entry did not match this chain.
    error ChainBindMismatch(MandateId mandateId);

    /// @notice Thrown at bind time when a configured sigil does not advertise the ERC-165 interface its tier
    ///         requires: action sigils must support {IActionSigil}, signature sigils must support {I1271Sigil},
    ///         outcome sigils must support {IOutcomeSigil}. This subsumes the codeless-address case (an
    ///         EOA/codeless address answers no ERC-165 query) AND rejects a wrong-TIER sigil — e.g. an
    ///         action-only sigil placed in the outcome or signature tier, whose tier method's low-level call
    ///         would otherwise return `(true, "")` and silently fail OPEN. Rejecting it here makes the mandate
    ///         fail CLOSED at bind.
    /// @param sigil The address that does not support its tier's required interface.
    error UnsupportedSigil(address sigil);

    /// @notice The ActionIds enabled for a mandate — the (target, selector) action keys the mandate gates
    ///         (a fallback action is keyed under the fixed `FALLBACK_ACTIONID`). An empty array means the
    ///         mandate enables no actions (e.g. a signing-only x402 voucher mandate).
    /// @param pid The mandate id.
    /// @return The enabled ActionIds.
    function mandateActionIds(MandateId pid) external view returns (bytes32[] memory);

    /// @notice The action sigils gating a single (ActionId, MandateId) — the per-action gates a USE call must
    ///         satisfy. An empty array means the mandate enables no sigil for that action (default-deny: the
    ///         action is not permitted).
    /// @param aid The action id (`IdLib.toActionId(target, selector)`, or `FALLBACK_ACTIONID` for the
    ///        wildcard fallback action).
    /// @param pid The mandate id.
    /// @return The configured action-sigil addresses.
    function mandateActionSigils(
        ActionId aid,
        MandateId pid
    )
        external
        view
        returns (address[] memory);

    /// @notice The per-execution outcome sigils for a mandate — the {IOutcomeSigil}s bracketing the mandate's
    ///         calls with a pre/post pair (e.g. a stateful rolling spend cap). An empty array means the mandate
    ///         configures no outcome sigil.
    /// @param pid The mandate id.
    /// @return The configured outcome-sigil addresses.
    function mandateOutcomeSigils(MandateId pid) external view returns (address[] memory);
}
