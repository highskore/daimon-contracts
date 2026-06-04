// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

/// @dev Identifies a session (mandate): keccak256(sessionValidator, sessionValidatorInitData, salt).
type MandateId is bytes32;

/// @dev Identifies a scoped action: keccak256(target, selector).
type ActionId is bytes32;

/// @dev Sentinel `target` marking a FALLBACK (wildcard) action in a {Mandate}'s `actions` list. Its sigils gate
///      ANY `(target, selector)` call that has NO exact-match action — a catch-all policy for broad-but-bounded
///      agents (compose it with value/time/spend sigils). Registered under {FALLBACK_ACTIONID}; it is never a
///      real call target (a real call whose `to` equals this flag is denied). A fallback action's `selector`
///      does NOT affect routing — it matches every selector, and the ActionId is the fixed {FALLBACK_ACTIONID}
///      regardless — though the literal `selector` bytes remain part of the ROOT-signed mandate content (the
///      bind digest's actions hash).
///
///      DIVERGENCE from smart-sessions (which uses `address(1)`): Daimon supports arbitrary call targets,
///      including the EVM PRECOMPILES at `address(1)`..`address(0x0a)` (e.g. ecrecover at `address(1)`). Using a
///      precompile as the flag would (a) silently turn an exact precompile-scoped action into a wildcard and (b)
///      make mandate calls to that precompile impossible. So the flag is instead a keccak-derived address —
///      `address(uint160(uint256(keccak256("daimon.fallback.target"))))` — that no real target would occupy,
///      leaving every precompile callable as a normal exact action.
address constant FALLBACK_TARGET_FLAG = 0xe72A12755A2BF230F3a8FfCe51E309Bc073134B6;

/// @dev Fixed {ActionId} the fallback action's sigils are stored + checked under —
///      `keccak256("daimon.action.fallback")`. Domain-separated from any real `IdLib.toActionId(target,
///      selector)` (a keccak of 24 packed bytes) so the wildcard policy can never collide with a scoped action.
ActionId constant FALLBACK_ACTIONID =
    ActionId.wrap(0xa3dc9ac6e47e3c6c77a04d4b378c14b917c5e9081335e39ccb091688794a21a5);

/// @notice A per-ACTION sigil contract + its per-action configuration (e.g. an OmniSigil rule tree).
/// @param sigil The {IActionSigil} contract gating the action.
/// @param initData ABI-encoded, sigil-specific configuration (decoded in `initializeWithMultiplexer`).
struct ActionSigilData {
    address sigil;
    bytes initData;
}

/// @notice One scoped action in a mandate: a (target, selector) gated by a set of sigils (all must pass).
/// @param target The call target the action is scoped to.
/// @param selector The 4-byte function selector the action is scoped to.
/// @param sigils The sigils gating this action; ALL must return success for the call to be permitted.
struct ActionData {
    address target;
    bytes4 selector;
    ActionSigilData[] sigils;
}

/// @notice A per-EXECUTION outcome sigil + its config. Unlike {ActionData} (a per-call gate scoped to a
///         (target, selector)), an outcome sigil brackets the *whole* execution with a pre/post pair —
///         e.g. a stateful rolling spend cap measured by the account's net balance delta.
/// @param sigil The {IOutcomeSigil} contract.
/// @param initData ABI-encoded, sigil-specific configuration (decoded in `initializeWithMultiplexer`).
struct OutcomeSigilData {
    address sigil;
    bytes initData;
}

/// @notice A per-MANDATE signature (ERC-1271 / attestation) sigil + its config. Gates the mandate's 1271
///         signing path — what typed data / content the agent may sign, and for which requesting dApp —
///         rather than an on-chain execution. An empty `signatureSigils` set means the mandate cannot
///         1271-sign at all (default-deny). The canonical implementation is {AttestationSigil}.
/// @param sigil The {I1271Sigil} contract whose {I1271Sigil.check1271} gates the signed content.
/// @param initData ABI-encoded, sigil-specific configuration (decoded in `initializeWithMultiplexer`).
struct SignatureSigilData {
    address sigil;
    bytes initData;
}

/// @notice A mandate: a session key (validator + credential), the BIND-authorization deadline, the scoped
///         per-call actions, the per-execution outcome sigils, and the per-mandate signature (ERC-1271) sigils.
/// @dev `validUntil` is the BIND-AUTHORIZATION DEADLINE — the deadline on the ROOT bind signature, NOT a
///      runtime mandate expiry. It is committed to the MANDATE_BIND digest (so the ROOT signer authenticates
///      it) and enforced ONCE, at bind time: a relayer that submits an otherwise-valid bind after this deadline
///      is rejected. `validUntil == 0` is the open sentinel (no bind deadline; the bind authorization never
///      expires). RUNTIME time bounds are a SEPARATE concern — attach a {TimeFrameSigil} sigil to the
///      action(s) to enforce a `[validAfter, validUntil]` window per action at execution time. Do not conflate
///      the two: `validUntil` here bounds WHEN the bind may be submitted; a TimeFrameSigil bounds WHEN the
///      bound mandate may be used.
/// @param sessionValidator The {ISessionValidator} that verifies the session key's signatures.
/// @param sessionValidatorInitData The session key's stateless credential (e.g. abi.encode(signer)).
/// @param salt Disambiguates mandates that otherwise share a validator + credential (part of the MandateId).
/// @param validUntil The BIND-authorization deadline (0 = no deadline); enforced once at bind, not at runtime.
/// @param actions The scoped per-call actions; each is gated by its per-action sigils.
/// @param outcomeSigils The per-execution outcome sigils bracketing the mandate's calls with a pre/post pair.
/// @param signatureSigils The per-mandate ERC-1271 (attestation) sigils gating the 1271 signing path.
struct Mandate {
    ISessionValidator sessionValidator;
    bytes sessionValidatorInitData;
    bytes32 salt;
    uint48 validUntil; // 0 = no bind deadline (the ROOT bind authorization never expires)
    ActionData[] actions;
    OutcomeSigilData[] outcomeSigils;
    SignatureSigilData[] signatureSigils;
}

/// @notice Carried in a MANDATE-mode execution signature to enable a mandate inline (BIND flow).
/// @param session The mandate being authorized.
/// @param rootValidator Which installed ROOT scheme authorizes the enable.
/// @param rootSignature The ROOT signature over the EIP-712 enable digest.
struct MandateBinding {
    Mandate session;
    address rootValidator;
    bytes rootSignature;
}

/// @notice One chain's bind digest in a multichain bind array.
/// @dev `bindDigest` is the SAME account-domain digest the single-chain BIND path computes on that chain
///      (`_hashTypedDataSession(HashLib.bindStructHash(...))` — it commits to that chain's chainId + account via the
///      account EIP-712 domain), so an entry is bound to exactly one (mandate, chain, account, nonce). The
///      multichain flow signs an ARRAY of these once under a chain-independent domain (see {HashLib}).
/// @param chainId The chain this entry authorizes the bind on.
/// @param bindDigest The account-domain bind digest for this chain (the SAME value the single-chain path
///        computes via `_hashTypedDataSession` on that chain).
struct ChainBind {
    uint64 chainId;
    bytes32 bindDigest;
}

/// @notice Carried in a MANDATE-mode execution signature to enable a mandate inline across N chains with ONE
///         ROOT signature (multichain BIND flow).
/// @dev The ROOT signs the multichain ARRAY digest (`HashLib.multichainBindDigest(perChain)`) ONCE;
///      every target chain re-derives the SAME array digest from `perChain` and checks the single ROOT signature
///      over it, after asserting THIS chain's entry equals the digest it computes locally. The array is
///      integrity-protected by the ROOT signature: a relayer that drops, reorders, or edits any entry changes
///      the array digest and breaks the signature. Replay is still impossible — see {HashLib} and
///      {MandateEngine._bindMandateMultichain} for the per-chain nonce + account-domain invariants.
/// @param session The mandate being authorized (identical on every chain).
/// @param rootValidator Which installed ROOT scheme authorizes the enable.
/// @param rootSignature The ROOT signature over the multichain ARRAY digest (NOT a single chain's digest).
/// @param perChain The full signed (chainId, bindDigest) array — integrity-protected by `rootSignature`.
/// @param chainIndex Index into `perChain` of THIS chain's entry.
struct MultichainMandateBinding {
    Mandate session;
    address rootValidator;
    bytes rootSignature;
    ChainBind[] perChain;
    uint256 chainIndex;
}
