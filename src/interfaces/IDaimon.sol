// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IERC1608 } from "@interfaces/IERC1608.sol";

// Types
import { Mandate, MandateId } from "@types/MandateTypes.sol";

/// @title IDaimon
/// @author highskore.eth
/// @notice External API (account management) plus errors for the Daimon account. Extends {IERC1608}
///         (ERC-1608) — the signature-authorized execution entrypoint.
interface IDaimon is IERC1608 {
    /// @notice Emitted when a direct-call execution (`executeWithSig`) succeeds — it reverts otherwise, so
    ///         the event alone marks success. The call count is derivable from the tx calldata.
    /// @param nonce The single-use execution nonce consumed (the execution's unique id).
    event Executed(uint256 indexed nonce);

    /// @notice Thrown when a signature carries an unknown mode byte.
    /// @param mode The unrecognized mode.
    error InvalidSignatureMode(uint8 mode);

    /// @notice Thrown when a direct-call execution nonce has already been used.
    /// @param nonce The replayed nonce.
    error ExecNonceUsed(uint256 nonce);

    /// @notice Thrown when a direct-call execution's ROOT/MANDATE authorization fails.
    error UnauthorizedExecution();

    /// @notice Thrown when a direct-call execution is submitted after its signed `deadline` (checked before
    ///         the nonce is burned, so an expired payload leaves its nonce reusable).
    error Expired();

    /// @notice Thrown when initializing with an empty ROOT set (>= 1 scheme is required).
    error RootSetTooSmall();

    /// @notice Thrown when the validators and initDatas arrays have different lengths.
    error LengthMismatch();

    /// @notice Thrown for disabled entry points (single-owner initializer, delegatecall).
    error NotSupported();

    /// @notice Thrown when {bindMandates} is called with an empty `mandates` array (>= 1 is required).
    error NoMandates();

    /// @notice Thrown when a self-gated privileged op (installRoot/uninstallRoot/revokeMandate/upgrade) is
    ///         called by anyone but the account itself (i.e. not a ROOT-authed `executeWithSig` self-call).
    error Unauthorized();

    /// @notice Initialize the account with its bootstrap ROOT set (>= 1 scheme) and, optionally, a set of
    ///         genesis mandates bound atomically at deploy time. The CREATE2 address commits to BOTH the
    ///         ROOT set and the genesis mandates (see {DaimonFactory}), so this once-only call can bind the
    ///         genesis mandates WITHOUT a ROOT signature — a different mandate set is a different account.
    ///         A single-validator root is allowed; >= 2 is an opt-in recovery default (an OR-set), not a hard
    ///         requirement.
    /// @param validators The ROOT auth scheme contracts to install (active immediately).
    /// @param initDatas Per-scheme credential data (e.g. abi.encode(signer) / abi.encode(x, y)).
    /// @param mandates The genesis mandates to bind at deploy time (may be empty).
    function initialize(
        address[] calldata validators,
        bytes[] calldata initDatas,
        Mandate[] calldata mandates
    )
        external
        payable;

    /// @notice Install a new ROOT auth scheme (active immediately). Owner-only (`onlyOwner`): the
    ///         account itself, reached via a ROOT-authed self-call through {executeWithSig}.
    /// @param validator The scheme to install.
    /// @param initData The scheme's credential data.
    function installRoot(address validator, bytes calldata initData) external payable;

    /// @notice Remove a ROOT auth scheme. ROOT-authed; cannot remove the last scheme.
    /// @param validator The scheme to remove.
    /// @param deinitData Optional teardown data passed to the scheme.
    function uninstallRoot(address validator, bytes calldata deinitData) external payable;

    /// @notice Revoke (kill) an enabled mandate. Owner-only (`onlyOwner`): the account itself, reached via a
    ///         ROOT-authed self-call through {executeWithSig}.
    /// @param mandateId The mandate to revoke.
    function revokeMandate(MandateId mandateId) external payable;

    /// @notice Bind (enable) one or more mandates in a single self-call — the standalone bind path. Owner-only
    ///         (`onlySelf`): the account itself, reached via a ROOT-authed self-call through {executeWithSig}.
    ///         The HUMAN authorizes this by ROOT-signing an {executeWithSig} whose single call is
    ///         `address(this).bindMandates([...])`; a relayer submits that (ROOT-signed, so gasless for the
    ///         human). The ROOT execution path skips per-call sigil enforcement, so it permits the self-call;
    ///         `onlySelf` is the gate, so NO per-mandate ROOT signature is needed (the outer ROOT auth covers
    ///         the whole bind set). This mirrors GENESIS registration (no per-mandate signature), but is
    ///         reachable post-deploy on a LIVE account — closing the gap for SIGNING-ONLY mandates (an x402
    ///         voucher with attestation sigils and NO actions), which cannot be bound via the inline
    ///         {executeWithSig} MANDATE_BIND path (that requires >= 1 bundled executable call).
    /// @dev Reverts {NoMandates} on an empty array. A re-bind of an existing MandateId is a REPLACE (it clears
    ///      any prior config first; see {MandateEngine._registerMandate}). Emits {IMandateEngine.MandateBound}
    ///      per bound mandate.
    /// @param mandates The mandates to bind (>= 1).
    /// @return pids The bound mandates' ids, in order.
    function bindMandates(Mandate[] calldata mandates)
        external
        payable
        returns (MandateId[] memory pids);

    /// @notice The next enable nonce for a mandate — the value an off-chain caller must commit into the BIND
    ///         digest for the NEXT bind of `mandateId`. Sequential per mandate and never reset by a revoke, so
    ///         the digest stays in lockstep with the contract: 0 for a never-bound mandate (the first bind), N
    ///         after N successful binds. A re-bind of the same mandate must read this (not hardcode 0) or the
    ///         ROOT signature will not verify.
    /// @param mandateId The mandate id.
    /// @return The next enable nonce to commit into the bind digest.
    function mandateEnableNonce(MandateId mandateId) external view returns (uint256);

    /// @notice Whether a direct-call execution nonce has been consumed — the single-use replay guard
    ///         {executeWithSig} checks (and burns) before authorizing an execution. False for an unused nonce,
    ///         true once an execution carrying it has succeeded. A relayer can read this to skip re-submitting
    ///         an already-landed execution.
    /// @param nonce The execution nonce to query.
    /// @return True iff the nonce has been used (burned).
    function execNonceUsed(uint256 nonce) external view returns (bool);

    // `executeWithSig` (ERC-1608) is inherited from {IERC1608}. DAIMON's modal signature `[mode][...]`
    // selects ROOT (the owner OR-set) or MANDATE (the engine + the mandate's per-call sigils, default-deny).
}
