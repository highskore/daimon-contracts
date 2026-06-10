// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { Initializable } from "solady/utils/Initializable.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardTransient } from "solady/utils/ReentrancyGuardTransient.sol";
import { Receiver } from "solady/accounts/Receiver.sol";
import { ERC1271 } from "solady/accounts/ERC1271.sol";
import { DaimonERC7739 } from "@core/DaimonERC7739.sol";
import { RootRegistry } from "@core/RootRegistry.sol";
import { MandateEngine } from "@core/MandateEngine.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
import { IERC1608 } from "@interfaces/IERC1608.sol";

// Libraries
import { ExecLib } from "@lib/ExecLib.sol";
import { MandateStorageLib } from "@lib/MandateStorageLib.sol";
import { HashLib } from "@lib/HashLib.sol";
import { ModeLib } from "@lib/ModeLib.sol";

// Types
import { Mandate, MandateId } from "@types/MandateTypes.sol";

// forgefmt: disable-start
/// ______  ___  ________  ________ _   _
/// |  _  \/ _ \|_   _|  \/  |  _  | \ | |
/// | | | / /_\ \ | | | .  . | | | |  \| |
/// | | | |  _  | | | | |\/| | | | | . ` |
/// | |/ /| | | |_| |_| |  | \ \_/ / |\  |
/// |___/ \_| |_/\___/\_|  |_/\___/\_| \_/
///
///   sig[0] ┬─ 0x00 ROOT ─────▶ RootRegistry._isOwner   (OR-set: passkey · ecdsa · …)
///          └─ 0x01 MANDATE ─▶ MandateEngine ─▶ sigils ─▶ session key
// forgefmt: disable-end
/// @title Daimon
/// @author highskore.eth
/// @notice A non-custodial smart account for autonomous agents. The human owns it via an installable OR-set
///         of ROOT auth schemes (passkey/WebAuthn, secp256k1); the agent operates within bounded mandates
///         enforced by the MANDATE engine. Validation is modal on the first signature byte.
/// @dev Direct-call (ERC-1608) only: a low-trust relayer submits a ROOT- or session-key-signed execution and
///      pays the gas. Built on
///      solady's standalone mixins — {UUPSUpgradeable}, {Receiver}, and {ERC1271}
///      (EIP-712 + ERC-1271 + ERC-7739). ROOT and MANDATE paths are live for BOTH direct-call execution
///      (single `execute`/batch) and ERC-1271 signing (ROOT: owner; MANDATE: attestation-sigil-gated).
///      Deployment is factory-driven: {DaimonFactory} deploys an ERC-1967 proxy (LibClone) per account and
///      initializes it atomically via delegatecall. The implementation's initializers are disabled in the
///      constructor, so the deployed logic contract can never itself be initialized or hijacked.
contract Daimon is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardTransient,
    Receiver,
    DaimonERC7739,
    RootRegistry,
    MandateEngine,
    IDaimon
{
    /*·:⛧:·──────── CONSTRUCTOR ────────:⛧:·*/

    /// @dev Locks the implementation: accounts run as ERC-1967 proxies (deployed + initialized atomically by
    ///      {DaimonFactory}), so the logic contract itself must never be initialized. Disabling initializers
    ///      here closes the uninitialized-implementation hijack while leaving proxy initialization (via
    ///      delegatecall) unaffected.
    constructor() {
        _disableInitializers();
    }

    /*·:⛧:·──────── INITIALIZE ────────:⛧:·*/

    /// @inheritdoc IDaimon
    function initialize(
        address[] calldata validators,
        bytes[] calldata initDatas,
        Mandate[] calldata mandates
    )
        external
        payable
        virtual
        initializer
    {
        if (validators.length < 1) revert RootSetTooSmall();
        if (validators.length != initDatas.length) revert LengthMismatch();
        // Self-gated: privileged ops (installRoot, upgrade) run only as `onlySelf`, i.e. a ROOT-authed
        // self-call (`executeWithSig`), never a single EOA. The `initializer` modifier makes this once-only
        // (reverts on a second call), so the genesis binding below is reachable ONLY here, at deploy time —
        // there is no post-deploy path to inject a mandate without a ROOT sig.
        for (uint256 i; i < validators.length; ++i) {
            _installRoot(validators[i], initDatas[i]);
        }
        // Genesis mandates: bind each via the NO-SIGNATURE path. Safe precisely because the CREATE2 address
        // commits to `mandates` (see {DaimonFactory._salt}) — a different set is a different account, so this
        // permissionless deploy cannot be front-run to bind an attacker's mandate at this address.
        for (uint256 i; i < mandates.length; ++i) {
            _bootstrapMandate(mandates[i]);
        }
    }

    /// @dev Block the single-arg initializer; Daimon uses the ROOT-set initializer above (auth is the
    ///      RootRegistry OR-set, not a single owner). A single-validator root is allowed (>= 1); >= 2 is an
    ///      opt-in default for recovery (an OR-set so losing one scheme doesn't brick the account), not a hard
    ///      requirement.
    function initialize(address) public payable virtual {
        revert NotSupported();
    }

    /// @dev Privileged ops (installRoot/uninstallRoot/revokeMandate/upgrade) run only as a self-call — a
    ///      ROOT-authed `executeWithSig` that targets the account (`msg.sender == address(this)`).
    modifier onlySelf() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }

    /*·:⛧:·──────── MODAL VALIDATION ────────:⛧:·*/

    /// @dev Modal ERC-1271 validation, sharing the same dispatch (solady handles ERC-7739 nesting above).
    ///      ROOT (0x00): the OR-set owner check over the whole `hash` — the unconstrained human signer.
    ///      MANDATE (0x01): a bound mandate's session key attesting to `content` for a requesting dApp,
    ///      gated by the mandate's signature (attestation) sigils — the x402 / intent signing path. The
    ///      requesting sender is `msg.sender` (the dApp that called `isValidSignature`); solady preserves it
    ///      down this internal view chain, so the {AttestationSigil} can enforce a per-dApp allowlist.
    /// @dev PersonalSign / opaque-hash 1271: no signed content, so dispatch with a zero domain + content hash.
    function _erc1271IsValidSignatureNowCalldata(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        virtual
        override
        returns (bool)
    {
        return _dispatch1271(hash, signature, bytes32(0), bytes32(0));
    }

    /// @dev TypedDataSign 1271 ({DaimonERC7739}): solady has VERIFIED `appDomainSeparator` + `contentsHash`
    ///      against `hash`, so a MANDATE signature sigil may trust them as the signed typed-data's domain +
    ///      struct hash. ROOT signs the whole `hash` regardless, so content gating is a MANDATE-only concern.
    function _erc1271IsValidSignatureNowCalldataWithContents(
        bytes32 hash,
        bytes calldata signature,
        bytes32 appDomainSeparator,
        bytes32 contentsHash
    )
        internal
        view
        virtual
        override
        returns (bool)
    {
        return _dispatch1271(hash, signature, appDomainSeparator, contentsHash);
    }

    /// @dev Modal 1271 dispatch shared by the PersonalSign + TypedDataSign hooks. `appDomainSeparator` +
    ///      `contentsHash` are zero for PersonalSign (no signed content) and the solady-verified values for
    ///      TypedDataSign; they reach the MANDATE signature sigils, never ROOT.
    function _dispatch1271(
        bytes32 hash,
        bytes calldata signature,
        bytes32 appDomainSeparator,
        bytes32 contentsHash
    )
        private
        view
        returns (bool)
    {
        if (signature.length == 0) return false;
        uint8 mode = uint8(signature[0]);
        if (mode == ModeLib.MODE_ROOT) return _isOwner(hash, signature[1:]);
        if (mode == ModeLib.MODE_MANDATE) {
            return
                _authMandate1271(hash, msg.sender, signature[1:], appDomainSeparator, contentsHash);
        }
        return false;
    }

    /*·:⛧:·──────── DIRECT EXECUTION ────────:⛧:·*/

    /// @inheritdoc IERC1608
    /// @dev The direct-call path: a low-trust relayer submits a ROOT- or session-key-signed execution and
    ///      pays the gas. `mode` +
    ///      `executionData` are the ERC-7579 single/batch encoding (decoded via {LibERC7579}); the MANDATE
    ///      path enforces the mandate's sigils over *every* call. The signed digest commits to
    ///      `(mode, executionData, nonce, deadline)`. Reverts on failure; the single-use nonce is burned first
    ///      (CEI), but only AFTER the `deadline` check, so an expired payload cannot burn its nonce.
    ///      `nonReentrant` (solady transient guard): a nested `executeWithSig` would clobber an outer execution's
    ///      SpendSigil pre-execution balance snapshot — kept in transient storage keyed by `(account, token)`, not
    ///      per-execution — and zero out its balance-delta backstop, so nested entry is forbidden. The ROOT
    ///      self-call to `bindMandates`/`installRoot`/`upgrade` is a DIFFERENT function (not a nested
    ///      `executeWithSig`), so it is not blocked.
    function executeWithSig(
        bytes32 mode,
        bytes calldata executionData,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    )
        external
        payable
        virtual
        nonReentrant
        returns (bytes[] memory results)
    {
        if (sig.length == 0) revert InvalidSignatureMode(0);

        // Reject an expired payload BEFORE burning the nonce, so it stays reusable until a fresh signature.
        if (block.timestamp > deadline) revert Expired();

        // Burn the single-use nonce first (checks-effects-interactions); caller-chosen + order-independent.
        MandateStorageLib.MandateStorage storage $ = MandateStorageLib.load();
        if ($.execNonceUsed[nonce]) revert ExecNonceUsed(nonce);
        $.execNonceUsed[nonce] = true;

        // Authorize over the EIP-712 execution digest (the domain binds chainId + this account, anti-replay):
        // ROOT (owner over the whole execution) or MANDATE (per-call sigils, enforced below). Resolved in a
        // helper so this entrypoint's stack stays within limits (no via-IR), see ExecLib note below.
        (bool root, MandateId pid) = _authorizeExecution(mode, executionData, nonce, deadline, sig);

        // Decode the ERC-7579 single/batch, enforce the mandate's sigils per call (MANDATE), and execute —
        // all in ExecLib, so the flagship stays thin and the batch path stays within stack limits (no via-IR).
        results = ExecLib.enforceAndExecute($, root, pid, mode, executionData);
        emit Executed(nonce);
    }

    /// @dev Resolve and verify the modal signature over the EIP-712 execution digest committing to
    ///      `(mode, executionData, nonce, deadline)`. Split out of {executeWithSig} so the digest + auth
    ///      locals do not pile onto that entrypoint's frame (the batch path is already tight; no via-IR).
    /// @return root True iff the signature is a ROOT authorization (bypasses per-call sigils).
    /// @return pid The authorized mandate id for the MANDATE path (zero for ROOT).
    function _authorizeExecution(
        bytes32 mode,
        bytes calldata executionData,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    )
        private
        returns (bool root, MandateId pid)
    {
        bytes32 digest =
            _hashTypedData(HashLib.execStructHash(mode, executionData, nonce, deadline));
        uint8 sm = uint8(sig[0]);
        if (sm == ModeLib.MODE_ROOT) {
            root = true;
            if (!_isOwner(digest, sig[1:])) revert UnauthorizedExecution();
        } else if (sm == ModeLib.MODE_MANDATE) {
            bool ok;
            (pid, ok) = _authMandate(digest, sig[1:]);
            if (!ok) revert UnauthorizedExecution();
        } else {
            revert InvalidSignatureMode(sm);
        }
    }

    /*·:⛧:·──────── ERC-165 ────────:⛧:·*/

    /// @notice ERC-165 — advertises ERC-1608 ({IERC1608}) and ERC-1271 support.
    /// @param interfaceId The interface id to query.
    /// @return True for ERC-165 itself, ERC-1271 (`isValidSignature`), and ERC-1608 (`executeWithSig`).
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == 0x01ffc9a7 // ERC-165
            || interfaceId == 0x1626ba7e // ERC-1271 (isValidSignature) — the account is a 1271 signer
            || interfaceId == type(IERC1608).interfaceId; // ERC-1608
    }

    /*·:⛧:·──────── ROOT MANAGEMENT ────────:⛧:·*/

    /// @inheritdoc IDaimon
    function installRoot(
        address validator,
        bytes calldata initData
    )
        external
        payable
        virtual
        onlySelf
    {
        _installRoot(validator, initData);
    }

    /// @inheritdoc IDaimon
    function uninstallRoot(
        address validator,
        bytes calldata deinitData
    )
        external
        payable
        virtual
        onlySelf
    {
        _removeRoot(validator, deinitData);
    }

    /// @inheritdoc IDaimon
    function revokeMandate(MandateId mandateId) external payable virtual onlySelf {
        _revokeMandate(mandateId);
    }

    /// @inheritdoc IDaimon
    /// @dev Standalone bind: register each mandate via {_bindStandalone} → {_registerMandate} (the same
    ///      no-signature persistence as genesis, but it ADVANCES the per-mandate enable nonce — see below).
    ///      Authorization is purely `onlySelf` — the account
    ///      reaches this ONLY via its own ROOT-authed {executeWithSig} self-call (the ROOT path skips
    ///      {ExecLib} sigil enforcement, so a `to == address(this)` call is permitted), so the outer ROOT
    ///      signature is what authorizes the whole bind set. The AGENT (MANDATE) path can NOT reach here:
    ///      {EnforcementLib.enforceAction} default-denies any `to == address(this)` self-call BEFORE evaluating
    ///      sigils, so no mandate — however broad (even a SudoSigil/fallback) — can target the account itself.
    ///      No per-mandate ROOT signature and no execution
    ///      here — the outer ROOT executeWithSig is the authorization. Each bind ADVANCES that mandate's
    ///      `mandateEnableNonce` (via {_bindStandalone}), so the nonce invariant holds AND a stale inline
    ///      {executeWithSig} MANDATE_BIND signature committed to the old nonce cannot be replayed to override
    ///      this bind. This is what lets a SIGNING-ONLY mandate (an x402 voucher: attestation sigils, NO
    ///      actions) be bound to a LIVE account, which the inline MANDATE_BIND path cannot do (it needs >= 1
    ///      bundled call).
    function bindMandates(Mandate[] calldata mandates)
        external
        payable
        virtual
        onlySelf
        returns (MandateId[] memory pids)
    {
        uint256 length = mandates.length;
        if (length == 0) revert NoMandates();
        pids = new MandateId[](length);
        for (uint256 i; i < length; ++i) {
            pids[i] = _bindStandalone(mandates[i]);
        }
    }

    /*·:⛧:·──────── MANDATE VIEWS ────────:⛧:·*/

    /// @inheritdoc IDaimon
    function mandateEnableNonce(MandateId mandateId) external view virtual returns (uint256) {
        return MandateStorageLib.load().enableNonce[mandateId];
    }

    /// @inheritdoc IDaimon
    function execNonceUsed(uint256 nonce) external view virtual returns (bool) {
        return MandateStorageLib.load().execNonceUsed[nonce];
    }

    /*·:⛧:·──────── OVERRIDES ────────:⛧:·*/

    /// @dev Restrict UUPS upgrades to a self-call (`address(this)`) — a ROOT-authed {executeWithSig} that
    ///      targets the account. There is no `execute`/`delegateExecute` surface, so no delegatecall from the
    ///      account (the execution surface stays minimal).
    function _authorizeUpgrade(address) internal virtual override(UUPSUpgradeable) onlySelf { }

    /// @dev ERC-1271 signer hook required by {ERC1271}. Daimon overrides
    ///      {_erc1271IsValidSignatureNowCalldata} to route ROOT/MANDATE modally, so this hook is off the main
    ///      path; it returns `address(this)` so 1271 still resolves to the account if the modal route were
    ///      ever bypassed.
    function _erc1271Signer() internal view virtual override(ERC1271) returns (address) {
        return address(this);
    }

    /// @dev EIP-712 domain for the ERC-1271 / ERC-7739 workflow.
    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "Daimon";
        version = "1";
    }

    /// @dev MANDATE enable authorization: route to the ROOT OR-set.
    function _authorizeEnable(
        address rootValidator,
        bytes32 digest,
        bytes memory sig
    )
        internal
        view
        override
        returns (bool)
    {
        return _isOwner(rootValidator, digest, sig);
    }

    /// @dev Wrap the MANDATE enable struct hash in this account's EIP-712 domain.
    function _hashTypedDataSession(bytes32 structHash) internal view override returns (bytes32) {
        return _hashTypedData(structHash);
    }
}
