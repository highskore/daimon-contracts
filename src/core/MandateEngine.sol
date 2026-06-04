// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { IdLib } from "@lib/IdLib.sol";
import { ModeLib } from "@lib/ModeLib.sol";
import { MandateStorageLib } from "@lib/MandateStorageLib.sol";
import { ContentSigLib } from "@lib/ContentSigLib.sol";
import { EnforcementLib } from "@lib/EnforcementLib.sol";
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { IActionSigil, I1271Sigil, ConfigId } from "@interfaces/ISigil.sol";
import { IOutcomeSigil } from "@interfaces/IOutcomeSigil.sol";
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";
import { IMandateEngine } from "@interfaces/IMandateEngine.sol";

// Types
import {
    MandateId,
    ActionId,
    Mandate,
    ActionData,
    OutcomeSigilData,
    SignatureSigilData,
    MandateBinding,
    MultichainMandateBinding,
    ChainBind,
    FALLBACK_TARGET_FLAG,
    FALLBACK_ACTIONID
} from "@types/MandateTypes.sol";

/// @title MandateEngine
/// @author highskore.eth
/// @notice The baked MANDATE layer of the Daimon account. A mandate (a {Mandate}) is authorized once
///         by a ROOT signature (BIND), persisted, then used by a scoped session key (USE). On each
///         action the engine parses the execution, runs the mandate's sigils, and verifies the key.
/// @dev Security model:
///      - Default-deny: an action with no matching sigil for its (target, selector) is rejected, so a
///        mandate only permits what it enumerates.
///      - ROOT gates enabling: a mandate is persisted only via a ROOT signature over the EIP-712 enable
///        digest, so a session key can never widen its own scope.
///      - Replay: the enable digest binds a per-mandate nonce and the account's EIP-712 domain (chainId
///        + account), so an enable signature is single-use and cannot cross permission/chain/account.
///      - Trust boundary: the engine is baked into the account, so `msg.sender` to every sigil/validator
///        is the account itself.
///      The account supplies {_authorizeEnable} (ROOT check) and {_hashTypedDataSession} (EIP-712 domain)
///      as hooks; sigil enforcement over the decoded ERC-7579 calls happens in the account's {ExecLib}.
// forgefmt: disable-start
///   BIND   [Mandate + ROOT sig] ─▶ verify ROOT over EIP-712 digest ─▶ persist mandate ┐
///   USE    [MandateId]       ─▶ load enabled mandate ──────────────────────────────┤
///                                                                                      ▼
///                     enforce sigils over execute(…) ─▶ verify session key ─▶ 0 | 1
// forgefmt: disable-end
abstract contract MandateEngine is IMandateEngine {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*·:⛧:·──────── ACCOUNT-PROVIDED HOOKS ────────:⛧:·*/

    /// @dev Verify a ROOT signature over the enable digest; the account routes this to its OR-set
    /// so a mandate is only enabled with owner authorization.
    /// @param rootValidator The installed ROOT scheme that signed.
    /// @param digest The EIP-712 enable digest.
    /// @param sig The ROOT signature.
    /// @return True iff the signature is a valid owner authorization.
    function _authorizeEnable(
        address rootValidator,
        bytes32 digest,
        bytes memory sig
    )
        internal
        view
        virtual
        returns (bool);

    /// @dev Wrap a struct hash in the account's EIP-712 domain (binds chainId + account).
    /// @param structHash The hashed {HashLib.MANDATE_BIND_TYPEHASH} struct.
    /// @return The domain-separated digest to be signed by ROOT.
    function _hashTypedDataSession(bytes32 structHash) internal view virtual returns (bytes32);

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice Whether a mandate is currently enabled for the account.
    /// @param pid The mandate id.
    /// @return True iff enabled.
    function isMandateBound(MandateId pid) public view returns (bool) {
        return MandateStorageLib.load().enabled[pid];
    }

    /// @notice The per-mandate signature (ERC-1271) sigils — the attestation gates on the mandate's 1271
    ///         signing path. An empty set means the mandate cannot 1271-sign at all (default-deny).
    /// @param pid The mandate id.
    /// @return The configured signature-sigil addresses.
    function mandateSignatureSigils(MandateId pid) public view returns (address[] memory) {
        return MandateStorageLib.load().signatureSigils[pid].values();
    }

    /// @inheritdoc IMandateEngine
    function mandateActionIds(MandateId pid) public view returns (bytes32[] memory) {
        return MandateStorageLib.load().actionIds[pid].values();
    }

    /// @inheritdoc IMandateEngine
    function mandateActionSigils(
        ActionId aid,
        MandateId pid
    )
        public
        view
        returns (address[] memory)
    {
        return MandateStorageLib.load().actionSigils[aid][pid].values();
    }

    /// @inheritdoc IMandateEngine
    function mandateOutcomeSigils(MandateId pid) public view returns (address[] memory) {
        return MandateStorageLib.load().outcomeSigils[pid].values();
    }

    /*·:⛧:·──────── VALIDATION ────────:⛧:·*/

    /// @dev Persist a mandate after verifying ROOT authorization over its EIP-712 enable digest,
    /// then store the session-key config and initialize each action's sigils. Reverts if ROOT does
    /// not authorize.
    /// @param en The carried mandate + ROOT validator + ROOT signature.
    /// @return pid The enabled mandate's id.
    function _bindMandate(MandateBinding memory en) private returns (MandateId pid) {
        Mandate memory s = en.session;
        pid = IdLib.toMandateId(s);
        MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();

        // Bind a per-mandate nonce + the account domain so the enable signature is single-use and
        // scoped. The digest commits to the BIND-authorization deadline (`validUntil`), the per-call actions,
        // the per-execution outcome sigils, AND the per-mandate signature (ERC-1271) sigils, so a session key
        // can neither widen its action scope, strip the spend cap the owner signed, extend the bind deadline,
        // nor grant itself a 1271 signing capability the owner did not authorize.
        uint256 nonce = $.enableNonce[pid]++;
        bytes32 digest = _hashTypedDataSession(HashLib.bindStructHash(pid, s, nonce));
        if (!_authorizeEnable(en.rootValidator, digest, en.rootSignature)) {
            revert UnauthorizedBind(pid);
        }

        // Bind-time deadline: `validUntil` is the deadline on the ROOT bind authorization, NOT a runtime expiry.
        // It is now part of the (just-verified) signed digest, so this submitted value is authenticated — a
        // relayer cannot forge or extend it. Enforce it ONCE here: a bind submitted after the deadline is
        // rejected. `0` is the open sentinel (no deadline; the bind authorization never expires).
        if (s.validUntil != 0 && block.timestamp > s.validUntil) {
            revert BindExpired(pid, s.validUntil);
        }

        _registerMandate($, pid, s);
    }

    /// @dev Persist a mandate from a MULTICHAIN bind: the ROOT signs ONE array of per-chain bind digests
    ///      (`perChain`) under a fixed, chain-independent domain ({HashLib}); every target chain
    ///      verifies its own entry against the digest it recomputes locally, then re-derives the SAME array
    ///      digest and checks the single ROOT signature over it. Reverts if THIS chain's entry does not match
    ///      ({ChainBindMismatch}) or if the array's ROOT signature does not verify ({UnauthorizedBind}); the
    ///      bind-time deadline is enforced exactly as in {_bindMandate}.
    ///
    ///      KEY INVARIANTS (mirroring the single-chain path):
    ///        - PER-CHAIN NONCE: `$.enableNonce[pid]++` increments before signature verification, so a same-chain
    ///          replay of the SAME signed array reverts — the locally-recomputed `thisChainDigest` no longer
    ///          equals the array entry (which was built at the previous nonce), surfacing as {ChainBindMismatch}.
    ///        - ACCOUNT DOMAIN PER LEAF: each `bindDigest` is wrapped in the account EIP-712 domain (chainId +
    ///          account) via {_hashTypedDataSession}, so cross-chain / cross-account replay is impossible even
    ///          though the OUTER array digest is chain-independent.
    ///        - ARRAY INTEGRITY: `perChain` is bound by the ROOT signature over {HashLib.multichainBindDigest}
    ///          — a relayer that drops, reorders, or edits any entry changes the array digest and breaks the sig.
    ///        - LOCAL-TO-SIGNED TIE: `entry.bindDigest == thisChainDigest` ties THIS chain's locally-recomputed
    ///          digest to the signed array entry, so the relayer cannot point this chain at a forged digest.
    /// @param en The carried mandate + ROOT validator + ROOT signature over the array + the array + this chain's
    ///        index.
    /// @return pid The enabled mandate's id.
    function _bindMandateMultichain(MultichainMandateBinding memory en)
        private
        returns (MandateId pid)
    {
        Mandate memory s = en.session;
        pid = IdLib.toMandateId(s);
        MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();

        // Per-mandate nonce: incremented BEFORE verification so a same-chain replay of the same signed array
        // recomputes a different `thisChainDigest` and fails the entry match below (single-use, like _bindMandate).
        uint256 nonce = $.enableNonce[pid]++;
        bytes32 thisChainDigest = _hashTypedDataSession(HashLib.bindStructHash(pid, s, nonce));

        // Select THIS chain's entry from the signed array and tie it to local state. A single ChainBindMismatch
        // covers an out-of-range index, a wrong-chain selection, AND a forged/stale digest — it never leaks to a
        // relayer WHICH check failed.
        if (en.chainIndex >= en.perChain.length) revert ChainBindMismatch(pid);
        ChainBind memory entry = en.perChain[en.chainIndex];
        if (entry.chainId != block.chainid) revert ChainBindMismatch(pid);
        if (entry.bindDigest != thisChainDigest) revert ChainBindMismatch(pid);

        // Re-derive the SAME chain-independent array digest the ROOT signed once, and verify the single ROOT
        // signature over it. The array is integrity-protected: any tampered entry changes this digest.
        bytes32 mcDigest = HashLib.multichainBindDigest(en.perChain);
        if (!_authorizeEnable(en.rootValidator, mcDigest, en.rootSignature)) {
            revert UnauthorizedBind(pid);
        }

        // Bind-time deadline, identical to {_bindMandate}: `validUntil` is committed to each chain's bindDigest
        // (and thus to the just-verified array), so the submitted value is authenticated. `0` = open sentinel.
        if (s.validUntil != 0 && block.timestamp > s.validUntil) {
            revert BindExpired(pid, s.validUntil);
        }

        _registerMandate($, pid, s);
    }

    /// @dev GENESIS no-signature bind: register a mandate WITHOUT a ROOT signature and WITHOUT advancing the
    ///      enable nonce. Reachable only from {Daimon.initialize} at deploy time — the CREATE2 address commits
    ///      to the exact genesis mandate set (see {DaimonFactory}), so a different set yields a different
    ///      account, not a hijack; and as the INITIAL bind there is no prior {_bindMandate} signature to
    ///      invalidate, so the nonce correctly starts at 0. Performs the identical persistence as
    ///      {_bindMandate} via the shared {_registerMandate}. (The post-deploy standalone path is
    ///      {_bindStandalone}, which DOES advance the nonce.)
    /// @param s The genesis mandate to register.
    /// @return pid The registered mandate's id.
    function _bootstrapMandate(Mandate calldata s) internal returns (MandateId pid) {
        pid = IdLib.toMandateId(s);
        _registerMandate(MandateStorageLib.load(), pid, s);
    }

    /// @dev STANDALONE no-per-mandate-signature bind for the `onlySelf` {Daimon.bindMandates} path. Like
    ///      {_bootstrapMandate} it registers without a per-mandate ROOT signature (authorized by `onlySelf` —
    ///      the outer ROOT {executeWithSig} self-call), but unlike genesis it ALSO advances the per-mandate
    ///      enable nonce. This keeps the `mandateEnableNonce` invariant — a successful post-genesis bind
    ///      advances the nonce — and, critically, INVALIDATES any stale inline {_bindMandate} signature
    ///      committed to the OLD nonce, so such a signature can never be replayed to re-bind/override this
    ///      mandate after a standalone bind. Persists via the shared {_registerMandate}.
    /// @param s The mandate to register (standalone bind).
    /// @return pid The registered mandate's id.
    function _bindStandalone(Mandate calldata s) internal returns (MandateId pid) {
        pid = IdLib.toMandateId(s);
        MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();
        ++$.enableNonce[pid];
        // Bind-time deadline, identical to {_bindMandate}: `validUntil` is the deadline by which the bind may be
        // submitted (NOT a runtime expiry). A standalone bind is carried in a ROOT-signed {executeWithSig} a
        // relayer may hold, so enforce it here too — a relayer cannot submit an expired bind. `0` = open
        // sentinel (no deadline). (Genesis {_bootstrapMandate} skips this: the bind IS the deploy, so there is
        // no relayer-hold window to bound.)
        if (s.validUntil != 0 && block.timestamp > s.validUntil) {
            revert BindExpired(pid, s.validUntil);
        }
        _registerMandate($, pid, s);
    }

    /// @dev The shared mandate-registration core, used by BOTH the ROOT-authorized {_bindMandate} and the
    ///      no-signature genesis {_bootstrapMandate}. Persists the enabled flag, session-key config, per-action
    ///      sigils (`initializeWithMultiplexer` per sigil), per-execution outcome sigils, and per-mandate
    ///      signature (ERC-1271) sigils. Does NOT perform authorization — each caller gates it (ROOT sig vs. the
    ///      address commitment). It also does NOT persist the mandate's `validUntil`: no runtime time check
    ///      here — `validUntil` is the bind-time deadline (enforced at bind).
    /// @param $ The mandate storage pointer.
    /// @param pid The mandate id (`IdLib.toMandateId(s)`).
    /// @param s The mandate to register.
    function _registerMandate(
        MandateStorageLib.MandateStorage storage $,
        MandateId pid,
        Mandate memory s
    )
        private
    {
        // Clear any prior config for this id FIRST so a re-bind is a true REPLACE, never a merge: the
        // mandateId is content-derived but a ROOT-authorized re-bind of the same id with a different sigil
        // set must not leave stale action / outcome / signature (ERC-1271) sigils behind (a stale signature
        // sigil would keep a signing capability the new config dropped). Mirrors {_revokeMandate}'s clearing.
        _clearMandateSets($, pid);

        // CEI: disable FIRST (with the matching enable LAST, below). _clearMandateSets does not touch
        // `enabled`, so on a RE-BIND of an already-enabled mandate it would otherwise stay enabled across
        // the sigil-init external calls — reopening the very reentrancy window the enable-last guard closes
        // for a first bind. Disabling here makes "enabled is false throughout registration" hold on EVERY
        // bind path (genesis / inline / standalone / multichain / re-bind).
        $.enabled[pid] = false;

        $.signerConf[pid] =
            MandateStorageLib.SignerConf(address(s.sessionValidator), s.sessionValidatorInitData);

        for (uint256 i; i < s.actions.length; ++i) {
            ActionData memory a = s.actions[i];
            // A fallback action (target == FALLBACK_TARGET_FLAG) registers its sigils under the fixed
            // FALLBACK_ACTIONID — the wildcard catch-all enforceAction falls back to when no exact (target,
            // selector) action matches. Its `selector` is ignored. Every other action keys on (target, selector).
            ActionId aid = a.target == FALLBACK_TARGET_FLAG
                ? FALLBACK_ACTIONID
                : IdLib.toActionId(a.target, a.selector);
            ConfigId cid = IdLib.toConfigId(pid, aid);
            $.actionIds[pid].add(ActionId.unwrap(aid));
            for (uint256 j; j < a.sigils.length; ++j) {
                address sigil = a.sigils[j].sigil;
                // Fail-closed at bind: the address must advertise {IActionSigil} via ERC-165, which rejects an
                // EOA/codeless address (whose later low-level call would no-op to `(true, "")` and skip
                // enforcement) AND a wrong-TIER sigil that serves only the 1271 / outcome role.
                if (!_supportsSigilInterface(sigil, type(IActionSigil).interfaceId)) {
                    revert UnsupportedSigil(sigil);
                }
                $.actionSigils[aid][pid].add(sigil);
                IActionSigil(sigil)
                    .initializeWithMultiplexer(address(this), cid, a.sigils[j].initData);
            }
        }

        // Register + initialize the per-execution outcome sigils and the per-mandate signature (ERC-1271)
        // sigils, mirroring action-sigil wiring. Both share the per-mandate ConfigId (keyed by the mandate
        // alone, not per-(target, selector)) — {IdLib.toMandateConfigId} is domain-separated from the
        // per-action id, so the two categories never collide even when one address serves both roles.
        ConfigId mcid = IdLib.toMandateConfigId(pid);
        for (uint256 i; i < s.outcomeSigils.length; ++i) {
            OutcomeSigilData memory o = s.outcomeSigils[i];
            // Fail-closed at bind: an outcome sigil must advertise {IOutcomeSigil} via ERC-165. This rejects
            // both an EOA/codeless address and a wrong-TIER (action-only {IActionSigil} / signature-only
            // {I1271Sigil}) sigil — whose pre/postCheck
            // low-level call would no-op to `(true, "")` and silently skip the spend cap.
            if (!_supportsSigilInterface(o.sigil, type(IOutcomeSigil).interfaceId)) {
                revert UnsupportedSigil(o.sigil);
            }
            $.outcomeSigils[pid].add(o.sigil);
            IOutcomeSigil(o.sigil).initializeWithMultiplexer(address(this), mcid, o.initData);
        }
        for (uint256 i; i < s.signatureSigils.length; ++i) {
            SignatureSigilData memory sg = s.signatureSigils[i];
            // Fail-closed at bind: a signature sigil must advertise {I1271Sigil} via ERC-165. This rejects both
            // an EOA/codeless address (whose check1271 low-level call would no-op to `(true, "")` and skip the
            // attestation gate) AND a wrong-TIER, action-only sigil ({OmniSigil}/{SudoSigil}/{NativeValueLimitSigil})
            // or outcome-only {SpendSigil} placed in the signature slot — none implement {I1271Sigil}, so they
            // revert {UnsupportedSigil} here rather than reaching a broken/fail-open check1271 at runtime.
            if (!_supportsSigilInterface(sg.sigil, type(I1271Sigil).interfaceId)) {
                revert UnsupportedSigil(sg.sigil);
            }
            $.signatureSigils[pid].add(sg.sigil);
            I1271Sigil(sg.sigil).initializeWithMultiplexer(address(this), mcid, sg.initData);
        }

        // CEI: enable LAST, after every sigil is registered + initialized. A sigil whose
        // `initializeWithMultiplexer` reenters `executeWithSig` (MANDATE_USE of this same pid) would
        // otherwise observe an enabled mandate with a partial sigil set. Enabling here closes that window.
        $.enabled[pid] = true;
        emit MandateBound(pid);
    }

    /// @dev Clear EVERY per-mandate enumerable set for `pid`: each action id and its sigil set, the outcome
    ///      sigils, and the signature (ERC-1271) sigils. Shared by {_revokeMandate} (kill) and
    ///      {_registerMandate} (re-bind replace), so neither can leave a stale sigil — in particular a stale
    ///      signature sigil that would keep a 1271 signing capability the new/empty config dropped. Does NOT
    ///      touch `enabled`, `signerConf`, or `enableNonce`; the callers manage those.
    /// @param $ The mandate storage pointer.
    /// @param pid The mandate whose sets to clear.
    function _clearMandateSets(MandateStorageLib.MandateStorage storage $, MandateId pid) private {
        bytes32[] memory aids = $.actionIds[pid].values();
        for (uint256 i; i < aids.length; ++i) {
            ActionId aid = ActionId.wrap(aids[i]);
            EnumerableSetLib.AddressSet storage ss = $.actionSigils[aid][pid];
            address[] memory sigils = ss.values();
            for (uint256 j; j < sigils.length; ++j) {
                ss.remove(sigils[j]);
            }
            $.actionIds[pid].remove(aids[i]);
        }
        EnumerableSetLib.AddressSet storage os = $.outcomeSigils[pid];
        address[] memory ocs = os.values();
        for (uint256 i; i < ocs.length; ++i) {
            os.remove(ocs[i]);
        }
        EnumerableSetLib.AddressSet storage ss = $.signatureSigils[pid];
        address[] memory sgs = ss.values();
        for (uint256 i; i < sgs.length; ++i) {
            ss.remove(sgs[i]);
        }
    }

    /// @dev SAFE ERC-165 interface probe used to gate sigil registration per tier. Returns false (never
    ///      reverts) for a codeless/EOA address, a non-165 contract, a reverting `supportsInterface`, or one
    ///      that returns a short/false answer — so a wrong-tier or codeless sigil is rejected at bind
    ///      ({UnsupportedSigil}) rather than failing OPEN at runtime (a low-level call to a codeless address
    ///      returns `(true, "")`). `0x01ffc9a7` is `IERC165.supportsInterface(bytes4)`'s selector.
    /// @param sigil The candidate sigil address.
    /// @param interfaceId The interface the tier requires ({IActionSigil} for action, {I1271Sigil} for
    ///        signature, {IOutcomeSigil} for outcome).
    /// @return True iff `sigil` is a contract that affirmatively advertises `interfaceId` via ERC-165.
    function _supportsSigilInterface(address sigil, bytes4 interfaceId)
        private
        view
        returns (bool)
    {
        if (sigil.code.length == 0) return false;
        // Cap the probe gas: a malicious sigil's `supportsInterface` could otherwise burn all forwarded gas
        // (the bind reverts and its single-use exec nonce is already spent — a griefing vector). 30k is ample
        // for any real ERC-165 answer. Bounding the gas also bounds the returndata it can produce.
        (bool ok, bytes memory ret) =
            sigil.staticcall{ gas: 30_000 }(abi.encodeWithSelector(0x01ffc9a7, interfaceId));
        return ok && ret.length >= 32 && abi.decode(ret, (bool));
    }

    /// @dev Revoke (kill) a mandate: clear its enabled flag, session-key config, and every action / outcome /
    ///      signature sigil it configured. The per-mandate `enableNonce` is intentionally NOT reset, so an old
    ///      enable signature cannot be replayed after a revoke + re-enable. There is no `validUntil` slot to
    ///      clear — `validUntil` is the SIGNED bind-time deadline (enforced once in {_bindMandate}), never
    ///      persisted; clearing `enabled` already denies every use of the mandate.
    /// @param pid The mandate to revoke.
    function _revokeMandate(MandateId pid) internal {
        MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();
        _clearMandateSets($, pid);
        $.enabled[pid] = false;
        delete $.signerConf[pid];
        emit MandateRevoked(pid);
    }

    /// @dev Authorize a MANDATE-mode direct-call: dispatch the sub-mode, bind (or load) the mandate, and
    ///      verify the session key over `digest`. Does NOT enforce sigils — the account does that per call
    ///      via {ExecLib.enforceAndExecute} (it holds the decoded calls). The BIND sub-path may revert via
    ///      {_bindMandate} on bad ROOT auth or a missed bind deadline ({BindExpired}); the USE sub-path returns
    ///      `ok = false` rather than reverting.
    /// @param digest The execution digest the session key signs over.
    /// @param data The signature after the account's mode byte: `[sub-mode][payload]`.
    /// @return pid The bound/loaded mandate id (zero when `ok` is false).
    /// @return ok True iff the mandate is bound/enabled and the session-key signature is valid.
    function _authMandate(
        bytes32 digest,
        bytes calldata data
    )
        internal
        returns (MandateId pid, bool ok)
    {
        if (data.length == 0) return (MandateId.wrap(bytes32(0)), false);
        uint8 sm = uint8(data[0]);

        if (sm == ModeLib.MANDATE_BIND) {
            (MandateBinding memory en, bytes memory keySig) =
                abi.decode(data[1:], (MandateBinding, bytes));
            pid = _bindMandate(en);
            ok = _checkSessionKey(pid, digest, keySig);
        } else if (sm == ModeLib.MANDATE_BIND_MULTICHAIN) {
            (MultichainMandateBinding memory en, bytes memory keySig) =
                abi.decode(data[1:], (MultichainMandateBinding, bytes));
            pid = _bindMandateMultichain(en);
            ok = _checkSessionKey(pid, digest, keySig);
        } else if (sm == ModeLib.MANDATE_USE) {
            if (data.length < 33) return (MandateId.wrap(bytes32(0)), false);
            pid = MandateId.wrap(bytes32(data[1:33]));
            MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();
            if (!$.enabled[pid]) return (pid, false);
            // No runtime time check here — `validUntil` is the bind-time deadline (enforced at bind).
            ok = _checkSessionKey(pid, digest, data[33:]);
        }
    }

    /// @dev Verify the session key's signature via its configured stateless validator.
    /// @param pid The mandate id.
    /// @param hash The digest the session key signed (the EIP-712 execution digest).
    /// @param keySig The session key's signature.
    /// @return True iff the signature is valid for the mandate's session-key credential.
    function _checkSessionKey(
        MandateId pid,
        bytes32 hash,
        bytes memory keySig
    )
        private
        view
        returns (bool)
    {
        MandateStorageLib.SignerConf storage sc = MandateStorageLib.load().signerConf[pid];
        return ISessionValidator(sc.validator).validateSignatureWithData(hash, keySig, sc.initData);
    }

    /*·:⛧:·──────── ERC-1271 (ATTESTATION) ────────:⛧:·*/

    /// @dev Authorize a MANDATE-mode ERC-1271 signature: a bound mandate's session key attesting to
    ///      `content` (an x402 quote, an intent, an EIP-712 order …) for a requesting dApp. View-only —
    ///      this runs under solady's 1271 STATICCALL, so it can read state but never writes. Default-deny at
    ///      every step:
    ///        1. the payload must carry a 32-byte mandate id;
    ///        2. the mandate must be enabled (`validUntil` is the SIGNED bind-time deadline, enforced once at
    ///           bind in {_bindMandate}, NOT a runtime expiry — so the 1271 path makes no time check);
    ///        3. the mandate must configure AT LEAST ONE signature (attestation) sigil — an empty set means
    ///           the mandate cannot 1271-sign at all (so a swap/spend mandate never silently gains a signing
    ///           capability);
    ///        4. EVERY signature sigil's {I1271Sigil.check1271} must return success over the attested content,
    ///           the requesting `sender`, and the `hash` (the sigil gates which dApp + which content);
    ///        5. the session key must have signed `hash`.
    ///      The sigil receives `abi.encode(sender, hash, appDomainSeparator, contentsHash, content)` as its `content` argument: the
    ///      requesting-sender allowlist (anti-phishing) is the {AttestationSigil}'s job, so the dispatch threads
    ///      the caller through rather than changing the {I1271Sigil} surface. ROOT 1271 is handled by the account
    ///      directly and never reaches here.
    /// @param hash The (ERC-7739-nested) digest the dApp asked the account to validate.
    /// @param sender The requesting dApp — the `msg.sender` of the account's `isValidSignature` call.
    /// @param data The 1271 signature after the account's mode byte:
    ///        `[32-byte mandateId][abi.encode(bytes content, bytes sessionKeySig)]`.
    /// @return ok True iff the mandate may attest to this `(sender, hash, appDomainSeparator, contentsHash, content)`.
    function _authMandate1271(
        bytes32 hash,
        address sender,
        bytes calldata data,
        bytes32 appDomainSeparator,
        bytes32 contentsHash
    )
        internal
        view
        returns (bool ok)
    {
        if (data.length < 32) return false;
        MandateId pid = MandateId.wrap(bytes32(data[0:32]));

        MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();
        if (!$.enabled[pid]) return false;
        // No runtime time check here — `validUntil` is the bind-time deadline (enforced at bind).

        // Default-deny: a mandate with NO signature sigil cannot 1271-sign. This keeps the signing
        // capability strictly opt-in — an action/spend mandate never gains it implicitly.
        if ($.signatureSigils[pid].length() == 0) return false;

        // Decode + gate + session-key-check the payload tail in a helper to keep this frame within stack
        // limits without via-IR. The decode is fail-closed (see {_gateAndVerify}).
        return _gateAndVerify(pid, sender, hash, data[32:], appDomainSeparator, contentsHash);
    }

    /// @dev The fail-closed decode + sigil gate + session-key bind for a MANDATE 1271 attestation. Decodes the
    ///      payload tail `abi.encode(bytes content, bytes keySig)` via {ContentSigLib} (a malformed/short tail
    ///      yields `ok == false`, never a panic-revert), then requires EVERY signature sigil to approve the
    ///      attested `(sender, hash, appDomainSeparator, contentsHash, content)` and finally that the session
    ///      key signed `hash`. Each sigil reads `abi.encode(sender, hash, appDomainSeparator, contentsHash,
    ///      content)` — the {AttestationSigil} unpacks it to gate the requesting sender (anti-phishing) and the
    ///      REAL `hash` (the same value the session key signs, so the gate cannot be fed a value different from
    ///      the one actually validated). `appDomainSeparator` + `contentsHash` are the solady-VERIFIED ERC-7739
    ///      TypedDataSign content (zero on the PersonalSign / opaque-hash path), so a content-aware sigil may
    ///      gate the signed typed-data's domain + struct, not just the opaque `hash`. View-only.
    /// @param pid The mandate id (already checked enabled, with a non-empty signature-sigil set).
    /// @param sender The requesting dApp.
    /// @param hash The (ERC-7739-nested) digest the dApp asked the account to validate.
    /// @param tail The 1271 payload after the 32-byte mandate id: `abi.encode(bytes content, bytes keySig)`.
    /// @param appDomainSeparator The signed content's EIP-712 domain separator (zero on the PersonalSign path).
    /// @param contentsHash The signed content's bytes32 struct hash (zero on the PersonalSign path).
    /// @return True iff the tail decodes, every sigil approves, and the session key signed `hash`.
    function _gateAndVerify(
        MandateId pid,
        address sender,
        bytes32 hash,
        bytes calldata tail,
        bytes32 appDomainSeparator,
        bytes32 contentsHash
    )
        private
        view
        returns (bool)
    {
        (bool good, bytes calldata content, bytes calldata keySig) =
            ContentSigLib.tryDecodeContentSig(tail);
        if (!good) return false;

        bytes memory gated = abi.encode(sender, hash, appDomainSeparator, contentsHash, content);
        if (!EnforcementLib.enforce1271(MandateStorageLib.load(), pid, gated)) return false;
        return _checkSessionKey(pid, hash, keySig);
    }
}
