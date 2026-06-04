// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { Eip3009ConfigLib, Eip3009Config } from "@sigils/Eip3009Sigil/lib/Eip3009ConfigLib.sol";

// Interfaces
import {
    I1271Sigil,
    ISigilBase,
    IERC165,
    ConfigId,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "@interfaces/ISigil.sol";

/// @title Eip3009Sigil — content-aware x402 (EIP-3009) voucher signing sigil
/// @author highskore.eth
/// @notice An ERC-1271 SIGNING policy that authorizes a mandate's session key to 1271-sign EIP-3009
///         `transferWithAuthorization`s for ONE token — but only to allowlisted payees and only up to a
///         per-authorization cap, INSTEAD of pinning one exact digest (as {AttestationSigil} does). This turns an
///         x402 voucher from "one pre-pinned payment" into "any payment to an allowlisted payee under a cap":
///         the recurring-allowance shape gasless agent payments actually need.
///
///         BOUNDS (read this): there is intentionally NO cumulative cap — a 1271 gate is a view STATICCALL and
///         cannot accrue state. Each authorization is independently bounded (allowlisted payee, `value <= cap`),
///         and total outflow is bounded by (a) the payee allowlist — funds can only reach payees the human
///         approved, never an attacker — and (b) the ACCOUNT BALANCE (EIP-3009 pulls from the account, and each
///         authorization needs a fresh single-use nonce). So a compromised session key can accelerate spending to
///         an APPROVED payee up to the funded balance, but cannot redirect funds. To bound the cumulative total,
///         fund the account with only the intended budget.
/// @dev It gates the SIGNED typed-data, not the opaque hash. {DaimonERC7739} threads the solady-VERIFIED
///      ERC-7739 TypedDataSign `appDomainSeparator` + `contentsHash` to {check1271} (packed by the engine as
///      `abi.encode(sender, hash, appDomainSeparator, contentsHash, content)`). The session key signs the final
///      `hash`; solady has proven `hash == keccak(0x1901 ‖ appDomainSeparator ‖ contentsHash)`. So this sigil
///      recomputes the EIP-3009 struct hash from the caller-supplied fields and requires it == `contentsHash` —
///      a single keccak that BINDS the decoded fields to the value actually signed (the soundness anchor) — then
///      applies the payee + cap rules. Signature-only ({I1271Sigil}): it implements no action gate and
///      advertises only the 1271 tier, so the engine's per-tier bind guard reverts {UnsupportedSigil} if it is
///      placed in an action slot. Configured per account by
///      the {MandateEngine} at bind time; keyed by `(configId, msg.sender, account)`.
contract Eip3009Sigil is I1271Sigil {
    using Eip3009ConfigLib for ConfigId;

    /*·:⛧:·──────── CONSTANTS ────────:⛧:·*/

    /// @notice The EIP-3009 `TransferWithAuthorization` struct typehash (the value the token's domain digest
    ///         commits to). `keccak("TransferWithAuthorization(address from,address to,uint256 value,uint256
    ///         validAfter,uint256 validBefore,bytes32 nonce)")` = `0x7c7c…2267`.
    bytes32 internal constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /// @dev The EIP-3009 content blob is six static words: `abi.encode(from,to,value,validAfter,validBefore,nonce)`.
    uint256 private constant _CONTENT_LEN = 0xc0;

    /// @dev solady {EnumerableSetLib}'s reserved zero-sentinel narrowed to an address: `AddressSet.contains`
    ///      REVERTS on it, so a relayer-supplied `to` equal to it must be denied BEFORE the membership read to
    ///      stay fail-closed (return {VALIDATION_FAILED}, never bubble a 1271 revert). Mirrors {AttestationSigil}.
    ///      A real payee colliding with this 9-byte value is cryptographically negligible.
    address private constant _SENTINEL_PAYEE = address(uint160(0xfbb67fda52d4bfb8bf));

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice Whether `(id, multiplexer, account)` was configured.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate signs.
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

    /// @notice The configured token, domain separator, and cap for `(id, msg.sender, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate signs.
    /// @return token The EIP-3009 token.
    /// @return tokenDomainSeparator The token's EIP-712 domain separator the signed authorization must use.
    /// @return cap The per-authorization value cap.
    function config(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (address token, bytes32 tokenDomainSeparator, uint256 cap)
    {
        return (
            id.token(multiplexer, account),
            id.domain(multiplexer, account),
            id.cap(multiplexer, account)
        );
    }

    /// @notice Whether `payee` is on the payee allowlist for `(id, msg.sender, account)`.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account whose mandate signs.
    /// @param payee The payee to query.
    /// @return True iff `payee` is allowlisted.
    function payeeAllowed(
        ConfigId id,
        address multiplexer,
        address account,
        address payee
    )
        external
        view
        returns (bool)
    {
        return id.payeeAllowed(multiplexer, account, payee);
    }

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        configId.initialize(msg.sender, account, initData);
        emit SigilSet(configId, msg.sender, account);
    }

    /*·:⛧:·──────── ENFORCE ────────:⛧:·*/

    /// @inheritdoc I1271Sigil
    /// @dev `content` is the engine-packed `abi.encode(sender, hash, appDomainSeparator, contentsHash,
    ///      innerContent)` where `innerContent = abi.encode(from,to,value,validAfter,validBefore,nonce)` (the
    ///      EIP-3009 authorization fields the relayer supplies). Fail-closed: a short blob or any failed check
    ///      returns {VALIDATION_FAILED}, never reverts on attacker-chosen input.
    function check1271(
        ConfigId id,
        address account,
        bytes calldata content
    )
        external
        view
        override
        returns (uint256)
    {
        if (!id.isInitialized(msg.sender, account)) {
            revert PolicyNotInitialized(id, msg.sender, account);
        }

        (address sender,, bytes32 appDomainSeparator, bytes32 contentsHash, bytes memory inner) =
            abi.decode(content, (address, bytes32, bytes32, bytes32, bytes));

        // Anti-phishing: only the configured token may request this voucher's signing, and the signed
        // authorization must be over THAT token's EIP-712 domain (the ERC-7739-verified appDomainSeparator).
        if (sender != id.token(msg.sender, account)) return VALIDATION_FAILED;
        if (appDomainSeparator != id.domain(msg.sender, account)) return VALIDATION_FAILED;

        // The EIP-3009 field gate is split into its own frame to stay within stack limits without via-IR.
        return _checkVoucher(id, account, contentsHash, inner);
    }

    /// @dev Decode the relayer-supplied EIP-3009 authorization fields, BIND them to the signed content
    ///      (`keccak(TYPEHASH, fields) == contentsHash` — the soundness anchor; `contentsHash` is solady-
    ///      verified against the signed `hash`), then apply the payer / payee / cap rules. Fail-closed: a
    ///      malformed/short blob or any failed check returns {VALIDATION_FAILED}.
    /// @param id The configuration id.
    /// @param account The signing account (the EIP-3009 `from`).
    /// @param contentsHash The solady-verified bytes32 struct hash of the signed authorization.
    /// @param inner `abi.encode(from, to, value, validAfter, validBefore, nonce)`.
    /// @return A validation code: {VALIDATION_SUCCESS} or {VALIDATION_FAILED}.
    function _checkVoucher(
        ConfigId id,
        address account,
        bytes32 contentsHash,
        bytes memory inner
    )
        private
        view
        returns (uint256)
    {
        if (inner.length != _CONTENT_LEN) return VALIDATION_FAILED;
        (address from, address to, uint256 value, uint256 va, uint256 vb, bytes32 nonce) =
            abi.decode(inner, (address, address, uint256, uint256, uint256, bytes32));

        // SOUNDNESS ANCHOR: recompute the EIP-3009 struct hash from the supplied fields and require it equals
        // the solady-VERIFIED `contentsHash`. solady already proved `hash == keccak(0x1901 ‖ appDomainSeparator
        // ‖ contentsHash)` and that the session key signed `hash`, so this single keccak binds the decoded
        // fields to the exact authorization being signed — the fields cannot be spoofed.
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, va, vb, nonce)
        );
        if (structHash != contentsHash) return VALIDATION_FAILED;

        // The payer must be this account (the EIP-3009 token only calls THIS account's isValidSignature for an
        // authorization whose `from` is this account, but bind it here too).
        if (from != account) return VALIDATION_FAILED;

        // EIP-3009 time bounds, mirroring the token's own `transferWithAuthorization` check
        // (`block.timestamp <= validAfter` revert, `block.timestamp >= validBefore` revert — strict
        // inequalities): an authorization is valid only when `validAfter < block.timestamp < validBefore`.
        // Reject signing a not-yet-valid or expired voucher rather than producing a signature the token will
        // reject on submission.
        if (block.timestamp <= va || block.timestamp >= vb) return VALIDATION_FAILED;

        // The field policy: allowlisted payee, within the per-authorization cap. Guard the solady set's reserved
        // sentinel first — `contains` reverts on it, so a relayer-supplied `to` equal to it is a clean deny.
        if (to == _SENTINEL_PAYEE) return VALIDATION_FAILED;
        if (!id.payeeAllowed(msg.sender, account, to)) return VALIDATION_FAILED;
        if (value > id.cap(msg.sender, account)) return VALIDATION_FAILED;

        return VALIDATION_SUCCESS;
    }

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the signature tier only: {IERC165}, {ISigilBase}, {I1271Sigil}.
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(I1271Sigil).interfaceId;
    }
}
