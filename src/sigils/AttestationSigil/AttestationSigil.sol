// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import {
    AttestationConfigLib,
    AttestationConfig
} from "@sigils/AttestationSigil/lib/AttestationConfigLib.sol";

// Interfaces
import {
    I1271Sigil,
    ISigilBase,
    IERC165,
    ConfigId,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "@interfaces/ISigil.sol";

// forgefmt: disable-start
///     _   _   _            _        _   _
///    / \ | |_| |_ ___  ___| |_ __ _| |_(_) ___  _ __
///   / _ \| __| __/ _ \/ __| __/ _` | __| |/ _ \| '_ \
///  / ___ \ |_| ||  __/\__ \ || (_| | |_| | (_) | | | |
/// /_/   \_\__|\__\___||___/\__\__,_|\__|_|\___/|_| |_|
///
///   gate a 1271 signature by  (requesting dApp ∈ allowlist)  ∧  (real hash ∈ allowlist | any)
// forgefmt: disable-end
/// @title AttestationSigil — the attestation (ERC-1271 / ERC-7739) signing sigil
/// @author highskore.eth
/// @notice The dedicated ERC-1271 SIGNING policy for a mandate: it gates WHICH dApp a mandate may produce a
///         signature for (an anti-phishing requesting-sender allowlist) and WHICH exact digest it
///         may sign (a hash allowlist over the REAL `hash` passed to `isValidSignature`). This is the
///         attestation analogue of the on-chain action
///         sigils — instead of gating an execution it gates a {Daimon}'s ERC-1271 reply, so an intent like
///         "let the agent sign EIP-712 orders for dApp X only" compiles to it. A mandate carries it in its
///         `signatureSigils` set; the engine runs every signature sigil's {check1271} before the account
///         returns the 1271 magic value, and the session key must additionally have signed the digest.
/// @dev Lineage: ports the `ERC1271Policy` pattern from erc7579/smartsessions to the Daimon {I1271Sigil} surface
///      (named {AttestationSigil} here). Two structural choices differ from the on-chain action sigils:
///
///      1. THE REQUESTING SENDER + THE REAL HASH. {I1271Sigil.check1271} carries only `(id, account, content)` —
///         not the requesting dApp, nor the digest being validated. Rather than widen that surface, the
///         {MandateEngine}'s 1271 dispatch packs the requesting sender, the REAL `hash` (the value reaching
///         the validation override, which the session key signs), and the content blob into the `content`
///         argument as `abi.encode(address sender, bytes32 hash, bytes32 appDomainSeparator, bytes32 contentsHash, bytes content)`. This sigil unpacks it and
///         gates on the sender and the `hash` — NOT the content blob, which has no cryptographic tie to the
///         value actually validated. Action sigils ({OmniSigil}, {SudoSigil}, …) implement {IActionSigil}, not
///         {I1271Sigil}, so they can never be wired as signature sigils (the engine's per-tier bind guard
///         rejects them) and the two roles stay cleanly separated. The method shape is `check1271` returning a
///         {VALIDATION_SUCCESS}/{VALIDATION_FAILED} code, view-only, default-deny when uninitialized.
///
///      2. STATELESS + VIEW. The 1271 path runs under solady's STATICCALL, so {check1271} is `view` and
///         writes no state — the gate is purely an allowlist membership test (no usage accrual; the digest
///         + session-key binding live in the engine).
///
///      Configured per account by the {MandateEngine} at bind time via {initializeWithMultiplexer}; keyed by
///      `(configId, msg.sender, account)`. The engine is baked into the account, so `msg.sender == account`
///      at runtime, and a 1271 attestation can never be configured without a ROOT-signed bind (the bind
///      digest commits to the mandate's signature sigils — see {HashLib.MANDATE_BIND_TYPEHASH}).
contract AttestationSigil is I1271Sigil {
    using AttestationConfigLib for ConfigId;

    /*·:⛧:·──────── CONSTANTS ────────:⛧:·*/

    /// @notice The sentinel that, when present in `allowedSenders`, permits a request from ANY dApp. Use it
    ///         to opt OUT of the anti-phishing allowlist explicitly (rather than leaving it empty, which
    ///         denies everything). `address(0)` is never a real EVM caller, so it is a safe wildcard.
    address public constant ANY_SENDER = address(0);

    /// @dev solady {EnumerableSetLib}'s reserved zero-sentinel (`uint72(bytes9(keccak256("_ZERO_SENTINEL")))`).
    ///      `add`/`contains` REVERT on this exact value for BOTH set kinds, so neither a `hash` nor a `sender`
    ///      equal to it can ever be a legitimately-added allowlist member. {check1271} short-circuits it to a
    ///      clean deny (never reverts on attacker-chosen input). The 9-byte value fits in a 20-byte address,
    ///      so the {_SENTINEL_SENDER} form is reachable as a `sender` and must be guarded too. A real ERC-7739
    ///      digest / EVM caller colliding with it is cryptographically negligible — this is a safety guard.
    bytes32 private constant _ZERO_SENTINEL = bytes32(uint256(0xfbb67fda52d4bfb8bf));

    /// @dev The same sentinel narrowed to an address — the value a `sender` would take to trigger solady's
    ///      `AddressSet` zero-sentinel revert.
    address private constant _SENTINEL_SENDER = address(uint160(0xfbb67fda52d4bfb8bf));

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice Whether `(id, multiplexer, account)` was configured. Mirrors the prior public `initialized`
    ///         mapping getter; distinguishes a deliberate "any hash" config from a never-initialized one.
    /// @param id The configuration identifier.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate is attesting.
    /// @return True iff the instance was configured.
    function initialized(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (bool)
    {
        return id.isInitialized(multiplexer, account);
    }

    /// @notice Whether a requesting dApp is on the anti-phishing allowlist for `(id, msg.sender, account)`.
    /// @param id The configuration identifier.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate is attesting.
    /// @param sender The requesting dApp to query.
    /// @return True iff `sender` is allowlisted.
    function allowedSender(
        ConfigId id,
        address multiplexer,
        address account,
        address sender
    )
        external
        view
        returns (bool)
    {
        return id.senderAllowed(multiplexer, account, sender);
    }

    /// @notice Whether an exact ERC-1271 digest is on the hash allowlist for `(id, msg.sender, account)`.
    /// @param id The configuration identifier.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate is attesting.
    /// @param hash The ERC-1271 digest to query.
    /// @return True iff `hash` is allowlisted.
    function allowedHash(
        ConfigId id,
        address multiplexer,
        address account,
        bytes32 hash
    )
        external
        view
        returns (bool)
    {
        return id.hashAllowed(multiplexer, account, hash);
    }

    /// @notice Whether a hash allowlist was supplied for `(id, msg.sender, account)`. When false, ANY hash is
    ///         permitted (sender-gated only); when true, the real `hash` must be in the allowlist.
    /// @param id The configuration identifier.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate is attesting.
    /// @return True iff a non-empty hash allowlist is configured.
    function hasHashAllowlist(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (bool)
    {
        return id.hasHashAllowlist(multiplexer, account);
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
    /// @dev Decode {AttestationConfig} from `initData` and REPLACE the requesting-sender + hash allowlists
    ///      for `(configId, msg.sender, account)` via {AttestationConfigLib}. Any prior entries are CLEARED
    ///      first, so a re-bind of the same mandateId never leaves a stale dApp or stale allowed-hash behind
    ///      (the new config is the whole config). An empty `allowedSenders` is permitted but means the
    ///      instance denies every 1271 request (default-deny) until reconfigured; an empty `allowedHashes`
    ///      means any hash is allowed (sender-gated only). Emits {SigilSet}.
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
    {
        configId.initialize(msg.sender, account, initData);
        emit ISigilBase.SigilSet(configId, msg.sender, account);
    }

    /*·:⛧:·──────── CHECK (1271) ────────:⛧:·*/

    /// @inheritdoc I1271Sigil
    /// @dev The attestation gate. `content` here is the engine-packed
    ///      `abi.encode(sender, hash, appDomainSeparator, contentsHash, innerContent)` (see {MandateEngine}'s 1271
    ///      dispatch), NOT a raw calldata slice. Returns {VALIDATION_SUCCESS} iff the requesting `sender` is
    ///      allowlisted (or {ANY_SENDER} is set) AND the REAL `hash` is allowlisted (or no hash allowlist
    ///      was configured). Reverts (not silently allows) if the instance was never configured.
    ///
    ///      SECURITY: the gate binds to `hash` — the REAL digest being validated (the ERC-7739-nested value
    ///      that reaches the account's validation path and that the mandate's session key signs over; see
    ///      {MandateEngine._authMandate1271}) — NOT to `innerContent`. It is a deterministic 1:1 function of
    ///      the raw application hash the dApp passed to `isValidSignature` (nested over the account domain),
    ///      so pinning it is cryptographically equivalent to pinning that raw hash. `innerContent` is a
    ///      caller-supplied blob with NO cryptographic tie to `hash`, so gating on `keccak256(innerContent)`
    ///      was bypassable: a hijacked agent could carry an allowlisted blob while the real signed digest was
    ///      an arbitrary order. Pinning `hash` closes that — the allowlisted value and the signed value are
    ///      one and the same. `innerContent` is intentionally ignored here (kept in the packed shape only for
    ///      legibility / future content sigils that themselves bind it to `hash`).
    /// @param id The configuration identifier.
    /// @param account The account whose mandate is attesting.
    /// @param content The engine-packed `abi.encode(sender, hash, appDomainSeparator, contentsHash, innerContent)`.
    /// @return A validation code: {VALIDATION_SUCCESS} or {VALIDATION_FAILED}.
    function check1271(
        ConfigId id,
        address account,
        bytes calldata content
    )
        external
        view
        returns (uint256)
    {
        if (!id.isInitialized(msg.sender, account)) {
            revert PolicyNotInitialized(id, msg.sender, account);
        }

        // The engine packs `(sender, hash, appDomainSeparator, contentsHash, innerContent)`. This sigil gates
        // the requesting sender + the REAL `hash`; the ERC-7739 `appDomainSeparator` + `contentsHash` are
        // carried for content-aware sigils (unused here).
        (address sender, bytes32 hash,,,) =
            abi.decode(content, (address, bytes32, bytes32, bytes32, bytes));

        // Anti-phishing: the requesting dApp must be allowlisted (or ANY_SENDER explicitly opted in). The
        // ANY_SENDER wildcard is checked FIRST so the sentinel short-circuit below cannot deny a wildcard
        // config. `ANY_SENDER` (address(0)) is never the sentinel, so this `contains` is always safe.
        if (!id.senderAllowed(msg.sender, account, ANY_SENDER)) {
            // The set's reserved zero-sentinel can never be a real member ({add}/{contains} revert on it), so a
            // `sender` equal to it (it fits in 20 bytes) is a clean deny — short-circuit to avoid the revert.
            if (sender == _SENTINEL_SENDER) return VALIDATION_FAILED;
            if (!id.senderAllowed(msg.sender, account, sender)) {
                return VALIDATION_FAILED;
            }
        }

        // Hash gate: if a hash allowlist was configured, the REAL `hash` must be in it; otherwise any hash is
        // allowed (sender-gated only). A non-empty set is the "has allowlist" marker.
        if (id.hasHashAllowlist(msg.sender, account)) {
            // The set's reserved zero-sentinel can never be a real member ({add}/{contains} revert on it), so
            // a `hash` equal to it is a clean deny — short-circuit to avoid the revert and fail closed.
            if (hash == _ZERO_SENTINEL) return VALIDATION_FAILED;
            if (!id.hashAllowed(msg.sender, account, hash)) {
                return VALIDATION_FAILED;
            }
        }

        return VALIDATION_SUCCESS;
    }

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the signature tier only: {IERC165}, {ISigilBase}, {I1271Sigil}. {AttestationSigil} gates
    ///      the ERC-1271 SIGNING path only; it is NOT an action policy, so the engine's per-tier bind guard
    ///      reverts {UnsupportedSigil} if it is placed in an action slot.
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(I1271Sigil).interfaceId;
    }
}
