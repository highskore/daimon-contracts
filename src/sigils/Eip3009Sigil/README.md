# Eip3009Sigil

The content-aware **gasless x402 voucher** signing sigil. An ERC-1271 / ERC-7739 signing policy that
lets a mandate's session key 1271-authorize EIP-3009 `transferWithAuthorization`s for one token to an
allowlisted set of payees, each under a per-authorization cap — a *recurring* payment allowance, not a
single pinned payment.

## What it gates

A `Daimon`'s ERC-1271 reply to a 1271-capable EIP-3009 token. It is the field-aware sibling of
`AttestationSigil`: instead of pinning one exact digest, it inspects the *fields* of the signed EIP-3009
authorization (relying on the ERC-7739 TypedDataSign machinery, which threads the solady-verified
`appDomainSeparator` + `contentsHash` to the sigil) and gates the payment by token, domain, payee, and
amount. This turns an x402 voucher from "one pre-pinned payment" into "any payment to an approved payee
under a cap."

The soundness anchor: the relayer supplies the raw EIP-3009 fields as `innerContent`, and the sigil
recomputes `keccak256(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore,
nonce)` and requires it to equal the solady-verified `contentsHash`. That binds the supplied fields to
what the session key actually signed — so the field checks below are trustworthy.

Gated dimensions:

- The requesting sender must be the configured `token` (the token is `msg.sender` of the account's
  `isValidSignature`).
- The signed app domain (`appDomainSeparator`) must equal the token's EIP-712 domain separator.
- The EIP-3009 `from` must be the account (you can only authorize spending your own balance).
- The `to` (payee) must be in the allowlist (the reserved solady set-sentinel is guarded to a clean deny).
- The `value` must be `<= cap` (per authorization).
- The authorization must be within its time window: `validAfter < block.timestamp < validBefore` (strict
  inequalities, mirroring the EIP-3009 token's own `transferWithAuthorization` check). A not-yet-valid or
  expired voucher is denied at signing, so the sigil never produces a signature the token would reject.

## No cumulative cap (by design)

A `view` ERC-1271 check cannot accrue state, so there is **no cumulative cap** here — only a per-payment
cap + a payee allowlist. Total spend is bounded by the allowlist + the account balance. An off-chain
cumulative cap (the SDK `CappedSigner`) is the managed-signer backstop; on-chain, keep the payee
allowlist tight and the per-payment cap conservative.

## Config shape

`Eip3009Config` (abi-decoded from `initData`):

- `token` — the 1271-capable EIP-3009 token the voucher signs for (also the required requesting sender).
- `tokenDomainSeparator` — the token's EIP-712 domain separator the signed `appDomainSeparator` must match.
- `allowedPayees` — the payees the agent may pay (the EIP-3009 `to` set). An empty list denies every payee.
- `cap` — the per-authorization value cap (token base units).

Stored per `(configId, multiplexer, account)`.

## Check semantics

- `check1271(id, account, content)` — `view`. `content` is the engine-packed
  `abi.encode(sender, hash, appDomainSeparator, contentsHash, innerContent)`. Returns
  `VALIDATION_SUCCESS` iff: `sender == token`, `appDomainSeparator == tokenDomainSeparator`, the
  soundness anchor holds, `from == account`, `to` is an allowlisted payee (sentinel-guarded),
  `value <= cap`, and `validAfter < block.timestamp < validBefore`. Fail-closed on a malformed
  `innerContent` length or any failed gate.
- `initializeWithMultiplexer(account, configId, initData)` — decodes `Eip3009Config`, writes it for
  `(configId, msg.sender, account)`, emits `SigilSet`.

## Conformance

Implements `I1271Sigil` (`check1271` + the shared `ISigilBase` config surface). `supportsInterface`
returns true for `IERC165`, `ISigilBase`, and `I1271Sigil` only — a pure signature sigil with no action
(`IActionSigil`) or outcome (`IOutcomeSigil`) tier, so placing it on an action reverts `UnsupportedSigil`
at bind. The 1271 path is stateless and view-only.

## Layout

- `Eip3009Sigil.sol` — the sigil contract (the soundness anchor + payee/cap/token/domain gates; split
  into `_checkVoucher` / `_typedDataFinalHash` frames to stay within stack limits).
- `lib/Eip3009ConfigLib.sol` — owns the per-`(configId, multiplexer, account)` `Eip3009Config` storage
  plus the decode/write + read paths; declares `Eip3009Config`.
