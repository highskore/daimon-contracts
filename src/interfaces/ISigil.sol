// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/*·:⛧:·──────── TYPES / CONSTANTS ────────:⛧:·*/

/// @dev Identifier for a configured sigil instance, scoped per permission + action.
type ConfigId is bytes32;

/// @dev Returned by a sigil when the action is permitted.
uint256 constant VALIDATION_SUCCESS = 0;
/// @dev Returned by a sigil when the action is rejected.
uint256 constant VALIDATION_FAILED = 1;

/// @notice Minimal ERC-165 surface, inlined to avoid pulling forge-std into `src/`.
interface IERC165 {
    /// @notice ERC-165 interface-support query.
    /// @param interfaceID The interface identifier.
    /// @return True iff the interface is supported.
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

/*·:⛧:·──────── ISIGILBASE ────────:⛧:·*/

/// @title ISigilBase
/// @author highskore.eth
/// @notice The shared configuration surface every *sigil* exposes, regardless of which check tier it
///         serves. A sigil is a policy that binds the daimon — it constrains what a session key may do.
///         The MANDATE engine configures every sigil through this surface at bind time; the tier-specific
///         check methods live in the role interfaces that extend this one ({IActionSigil} for the per-call
///         action gate, {I1271Sigil} for the ERC-1271 signature gate, {IOutcomeSigil} for the per-execution
///         outcome bracket). A sigil implements ONLY the tier(s) it serves and advertises exactly those via
///         ERC-165, so {MandateEngine._registerMandate} rejects a wrong-tier sigil at bind ({UnsupportedSigil}).
/// @dev Configured per account by the MANDATE engine at enable time. A sigil keys config by
///      `(configId, msg.sender, account)`; since the engine is baked into the account, `msg.sender == account`
///      at runtime.
interface ISigilBase is IERC165 {
    /// @notice Emitted when a sigil instance is configured for an account via a multiplexer.
    /// @param id The configuration id.
    /// @param multiplexer The caller that configured the sigil (the account/engine).
    /// @param account The account the sigil guards.
    event SigilSet(ConfigId id, address multiplexer, address account);

    /// @notice Thrown when a sigil is invoked before being configured for (id, multiplexer,
    ///        account).
    /// @param id The configuration id.
    /// @param multiplexer The expected configuring caller.
    /// @param account The account.
    error PolicyNotInitialized(ConfigId id, address multiplexer, address account);

    /// @notice Configure this sigil for `account`, called by the multiplexer (the MANDATE engine).
    /// @param account The account the sigil will guard.
    /// @param configId The configuration identifier.
    /// @param initData ABI-encoded, sigil-specific configuration.
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external;
}

/*·:⛧:·──────── IACTIONSIGIL ────────:⛧:·*/

/// @title IActionSigil
/// @author highskore.eth
/// @notice An *action sigil* is a per-CALL policy: the engine runs {checkAction} for every executed action
///         and default-denies the call unless every action sigil gating its `(target, selector)` returns
///         {VALIDATION_SUCCESS}. Concrete action sigils: {OmniSigil} (generic calldata-arg rules),
///         {SudoSigil} (allow-all), {NativeValueLimitSigil} (native-value cap), {TimeFrameSigil} (time window).
/// @dev Extends {ISigilBase} with the per-call gate only. A sigil that also gates the ERC-1271 path
///      additionally implements {I1271Sigil} (e.g. {TimeFrameSigil}); one that only meters an execution's
///      outcome implements {IOutcomeSigil} instead.
interface IActionSigil is ISigilBase {
    /// @notice Check whether an action is permitted under the configured rules.
    /// @param id The configuration identifier.
    /// @param account The account performing the action.
    /// @param target The call target.
    /// @param value The ETH value being sent.
    /// @param data The calldata of the action (inner call: selector ++ args).
    /// @return A validation code: `VALIDATION_SUCCESS` or `VALIDATION_FAILED`.
    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256);
}

/*·:⛧:·──────── I1271SIGIL ────────:⛧:·*/

/// @title I1271Sigil
/// @author highskore.eth
/// @notice A *signature sigil* is a per-mandate policy that gates the ERC-1271 signing path: the engine runs
///         {check1271} for every signature sigil before the account returns the 1271 magic value, and
///         default-denies unless every one returns {VALIDATION_SUCCESS}. Concrete signature sigils:
///         {AttestationSigil} (requesting-dApp + hash allowlist), {Eip3009Sigil} (x402 voucher gate), and
///         {TimeFrameSigil} (which also serves the action tier — its `check1271` is a real time-gate).
/// @dev Extends {ISigilBase} with the view-only 1271 gate only. The 1271 path runs under solady's STATICCALL,
///      so {check1271} is `view` and writes no state.
interface I1271Sigil is ISigilBase {
    /// @notice View-only check for the ERC-1271 path: validate signed `content` against the configured
    ///         rules without writing state (a `view` STATICCALL cannot SSTORE). Stateless bounds
    ///         (payee allowlist, per-call max) are enforced; cumulative limits act as per-call ceilings.
    /// @param id The configuration identifier.
    /// @param account The account whose mandate is being exercised.
    /// @param content The calldata-shaped content being authorized (selector ++ args).
    /// @return A validation code: `VALIDATION_SUCCESS` or `VALIDATION_FAILED`.
    function check1271(
        ConfigId id,
        address account,
        bytes calldata content
    )
        external
        view
        returns (uint256);
}
