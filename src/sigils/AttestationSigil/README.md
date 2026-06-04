# AttestationSigil

The attestation (ERC-1271 / ERC-7739) signing sigil. The dedicated ERC-1271 signing policy for a
mandate: it gates which dApp a mandate may produce a signature for and which exact digest it may
sign.

## What it gates

A `Daimon`'s ERC-1271 reply. It is the attestation analogue of the on-chain action sigils — instead
of gating an execution it gates a signature. An intent like "let the agent sign EIP-712 orders for
dApp X only" compiles to it. A mandate carries it in its signature-sigil set; the engine runs every
signature sigil's `check1271` before the account returns the 1271 magic value, and the session key
must additionally have signed the digest.

Two dimensions are gated:

- The requesting sender — an anti-phishing allowlist of dApps. The requesting sender is the
  `msg.sender` of the account's `isValidSignature` call.
- The real hash — the exact ERC-1271 digest (the ERC-7739-nested value reaching the account's
  validation path, which the session key signs over). This is the value actually validated, not a
  caller-supplied content blob.

## Config shape

`AttestationConfig` (abi-decoded from `initData`):

- `allowedSenders` — the requesting dApps the mandate may sign for. An empty list denies every
  request (default-deny). To sign for any dApp, include the `ANY_SENDER` sentinel (`address(0)`) — an
  explicit opt-out.
- `allowedHashes` — the exact ERC-1271 digests this mandate may attest to. An empty list means any
  hash is allowed (sender-gated only); a non-empty list pins the mandate to exactly those digests.

Storage uses solady enumerable sets per `(configId, msg.sender, account)` (so a re-init clears prior
entries), plus an `initialized` bool that is the configured marker — distinguishing a deliberate "any
hash" config (empty `allowedHashes`) from a never-configured instance.

## Check semantics

- `check1271(id, account, content)` — `view`. The attestation gate. `content` is the engine-packed
  `abi.encode(sender, hash, appDomainSeparator, contentsHash, innerContent)`. Reverts `PolicyNotInitialized` if
  the instance was never configured. Returns `VALIDATION_SUCCESS` iff the requesting `sender` is
  allowlisted (or `ANY_SENDER` is set) and the real `hash` is allowlisted (or no hash allowlist was
  configured). It binds to `hash`, not `innerContent` (which has no cryptographic tie to the signed
  value). solady's reserved zero-sentinel is short-circuited to a clean deny for both the sender and
  hash sets, so attacker-chosen input never reverts.
- `initializeWithMultiplexer(account, configId, initData)` — decodes `AttestationConfig`, clears any
  prior sender/hash entries, writes the new ones, sets `initialized`, emits `SigilSet`.

View helpers: `allowedSender`, `allowedHash`, `hasHashAllowlist`.

## Conformance

Implements `I1271Sigil` (`check1271` + the shared `ISigilBase` config surface). `supportsInterface`
returns true for `IERC165`, `ISigilBase`, and `I1271Sigil` only — a pure signature sigil with no action
(`IActionSigil`) or outcome (`IOutcomeSigil`) tier, so placing it on an action reverts `UnsupportedSigil`
at bind. The 1271 path is stateless and view-only.

## Layout

- `AttestationSigil.sol` — the sigil contract (the sentinel short-circuits and gate semantics live here).
- `lib/AttestationConfigLib.sol` — owns the per-`(configId, multiplexer, account)` sender allowlist,
  hash allowlist, and `initialized` marker storage plus the decode/clear/write (`initialize`) and
  membership read (`isInitialized`, `senderAllowed`, `hashAllowed`, `hasHashAllowlist`) paths the sigil
  calls; also declares `AttestationConfig`.
