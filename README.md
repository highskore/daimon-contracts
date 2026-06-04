```
______  ___  ________  ________ _   _
|  _  \/ _ \|_   _|  \/  |  _  | \ | |
| | | / /_\ \ | | | .  . | | | |  \| |
| | | |  _  | | | | |\/| | | | | . ` |
| |/ /| | | |_| |_| |  | \ \_/ / |\  |
|___/ \_| |_/\___/\_|  |_/\___/\_| \_/
        ·:⛧:· C O N T R A C T S ·:⛧:·
   non-custodial · direct-call · modal · sigil-bound
```

> A non-custodial smart account where **you** hold root (a passkey) and an agent operates only inside
> **mandates** it is structurally incapable of exceeding. Prompt-inject it, leak its key, let it go rogue —
> the worst it can do is exactly what you already allowed.

*daimon* — Greek **δαίμων**, the guiding spirit; Japanese **大門**, the great gate; and **d·AI·mon**. You
summon one, bind it with sigils, and put it to work behind a gate it cannot cross.

This repository is the **on-chain core** — the smart-account contracts and the reference implementation of
[ERC-1608](./ERC-1608.md) (signed execution + stateful payments). The SDK, agent tooling, and demo live
outside this repo.

## Why

Agent wallets today are custodial: a server holds the key and flips a central privilege. One injection or
one breach and the funds are gone. DAIMON inverts it — **scope the mandate, not the action:**

- **Root is yours, non-custodial.** An OR-set of auth schemes you control (passkey / WebAuthn, ECDSA). No
  server, and no key anyone else holds, can move your funds.
- **The agent gets a mandate** — a bounded grant enforced *on-chain*: recipient locked, amount capped,
  selector allow-listed, time-boxed. It acts freely *inside* the box; it cannot enlarge the box.
- **Containment, not prevention.** Assume the agent *will* be compromised; the win is that a compromised
  agent stays contained by structure, not by a policy server or a privileged toggle.

## The on-chain core

It is a non-custodial smart account (ERC-1608) whose execution path is **direct-call only**
— the signer commits to an `executeWithSig` and a low-trust relayer submits it and pays gas — whose
validation is **modal**, and whose agent sessions are bounded by **sigils** (on-chain policies) the
session key cannot widen. It is built on solady's standalone mixins (`UUPSUpgradeable` +
`Receiver` + `ERC1271`); the relayer pays gas, so gas can't be drained against the policy.

## Modal validation

The first signature byte selects the path; nothing else can cross between them.

```
                          ┌─ 0x00 ROOT ────▶ RootRegistry._isOwner ──▶ OR-set: passkey · ecdsa · …
      signature[0] ───────┤                                            (the human — privileged ops)
                          └─ 0x01 MANDATE ─▶ MandateEngine ─▶ sigils ─▶ session key
                                             │                          (the agent — bounded ops)
                                             ├─ 0x00 USE  : run an already-bound mandate
                                             └─ 0x01 BIND : persist a ROOT-signed mandate, then use it
```

- **ROOT** is the human. An installable OR-set of `IDaimonValidator` schemes (ECDSA, WebAuthn/P256),
  each active immediately on install, can't-remove-last. ROOT authorizes privileged ops and
  binds mandates.
- **MANDATE** is the agent. Every action is checked against its sigils (**default-deny**: an action with
  no matching sigil is rejected) and then the session key's signature is verified.

A mandate is **bound** four ways, all ROOT-authorized: **genesis** (committed into the CREATE2 address, bound
no-sig at deploy), **inline** (`[0x01][0x01]` carried with the first execution), **standalone**
(`bindMandates([...])` via a ROOT `executeWithSig` self-call — the only post-deploy binder for an action-less
mandate like an x402 voucher), and **multichain** (`[0x01][0x02]`, one ROOT signature over a per-chain bind
array). Every path advances the per-mandate enable nonce and enforces the `validUntil` bind deadline.

## Layout

```
src/
  Daimon.sol             # the account: UUPS+Receiver+ERC1271 + RootRegistry + MandateEngine, modal dispatch
  DaimonFactory.sol      # CREATE2 / ERC-1967 factory — counterfactual address commits to the root set
  core/
    RootRegistry.sol     # ROOT OR-set: install / uninstall (can't-remove-last), owner checks
    MandateEngine.sol    # mandate bind (genesis · inline · standalone bindMandates · multichain) / use / revoke, EIP-712 bind digest, sigil enforcement
  interfaces/            # external API + events + errors (IDaimon, IRootRegistry, IMandateEngine, ISigilBase + IActionSigil/I1271Sigil, IOutcomeSigil, …)
  lib/                   # pure logic + namespaced storage:
                         #   ModeLib (mode bytes) · IdLib (id derivation) · ExecLib (ERC-7579 decode + enforce + execute)
                         #   HashLib (EIP-712 typehashes + struct hashes + multichain bind digest) · RootStorageLib · MandateStorageLib (ERC-7201, with ASCII slot diagrams)
  sigils/               # action (IActionSigil): OmniSigil (AND/OR/NOT arg policy) + tree lib · SudoSigil (allow-all) · NativeValueLimitSigil (per-call native cap) · RateLimitSigil (per-call action-frequency cap) · TimeFrameSigil ([validAfter,validUntil], ALSO I1271Sigil)
                         # outcome (IOutcomeSigil): SpendSigil (rolling spend cap, global guard)
                         # signature (I1271Sigil): AttestationSigil (gates 1271 signing by requester + exact hash) · Eip3009Sigil (x402 voucher gate) · TimeFrameSigil (time-gates signing too)
  types/                # MandateTypes (MandateId/ActionId UDVTs, Mandate/MandateBinding/… structs)
  validators/           # ECDSA / WebAuthn (ROOT) and ECDSASession / WebAuthnSession (MANDATE) verifiers
```

The mode bytes (`MODE_ROOT`/`MODE_MANDATE`, `MANDATE_USE`/`MANDATE_BIND`) live in `lib/ModeLib.sol` —
one source of truth shared by the account and the engine (and mirrored in the SDK). Storage lives in
ERC-7201 libraries, never inline on the contracts.

## Sigils

A **sigil** is an on-chain policy a mandate binds to — the rules the agent's session key is allowed to act
within. Enforcement is **default-deny**: an action with no matching sigil is rejected *before* the session
signature is even checked. Sigils come in two shapes that compose — one gates what goes **in**, the other
bounds what comes **out**.

### Action sigils — gate the inputs · `IActionSigil`

Evaluated *before* the call, per execution. `checkAction(...)` validates the calldata against the policy.
Action sigils gate on-chain calls only; gating an ERC-1271 signature is a *separate* tier (`I1271Sigil` —
see below), so an action sigil never doubles as a signature gate (the one exception is `TimeFrameSigil`,
which serves both tiers because a time window is meaningful for a signature too). **`OmniSigil`** is the
generic one: an **AND / OR / NOT tree** over calldata-argument rules
(`EQUAL` / `GT` / `LT` / value caps), evaluated by `OmniSigilTreeLib`. **`SudoSigil`** is the minimal one:
an **allow-all** policy that reads no calldata and always succeeds — the on-chain form of a no-constraint
mandate (default-deny still confines the call to its `(target, selector)`). It is what a "allow this function
with any args" policy compiles to, including 0-argument functions, which OmniSigil's fixed-offset calldata
read cannot serve.

The MVP defense is the **recipient lock** — pin the swap recipient to the account so a hijacked agent can
route value nowhere but home:

```
   swap(amountIn, amountOutMin, path, to, deadline)
                                      └──┬──┘
                                         ▼
                              OmniSigil: to == account ?
                                  ┌──────┴──────┐
                              yes ▼             ▼ no
                            EXECUTE          REVERT (contained)
```

> Caveat (proven in tests): a static-offset lock only holds for top-level statically-typed
> args (v2-style router `to` at a fixed offset). A recipient buried in dynamic ABI data (Uniswap
> UniversalRouter) shifts offset across encodings — those routers need ABI-aware locking, deferred.

### Outcome sigils — bound the results · `IOutcomeSigil`

A pre/post **hook pair** (the ERC-7579 hook shape): `preCheck` snapshots state before the call,
`postCheck(id, account, mode, executionData)` asserts the end-state after — and crucially it receives the
WHOLE executed payload, so it is a **global guard** over every call in the batch, not a per-call check. Where
an action sigil reasons about *intent* (calldata), an outcome sigil reasons about *effect* (state delta).
**`SpendSigil`** is the first — a **stateful, rolling-window spend cap** on a single ERC-20:

```
   pre   ─ snapshot balanceBefore                                  (transient storage)
   call  ─ … the agent's execution (one or many calls) …
   post  ─ itemize EVERY executed call:
           outflow = max( Σ transfer/transferFrom/approve calldata , balanceBefore − balanceAfter )
           spent += outflow   ·   require spent ≤ cap (else SpendCapExceeded)
           revert a blanket grant (BlanketGrantBlocked) · revert Permit2 (Permit2GrantBlocked)
```

The `max(...)` is the point: charging the **real balance delta** as a backstop to the calldata sum means an
outflow the parser *undercounts* — an unparsed target, an indirect transfer — is still metered. On top of
that the global guard **refuses unbounded grants outright**: a blanket `approve(max)` / `setApprovalForAll` /
`authorizeOperator` on the budgeted token reverts (`BlanketGrantBlocked`), as does any `Permit2`
approval (`Permit2GrantBlocked`) — an allowance is a *future* outflow the cap couldn't meter, so it is denied
rather than counted. So the cap is a budget the agent **structurally cannot exceed**, not a calldata heuristic
that can be routed around. Spend resets on a configurable `Period` (`Minute` … `Year`, or `Forever` for a
lifetime cap). SpendSigil is **outcome-only** — it advertises only `IOutcomeSigil` via ERC-165, so placing it
in the action or signature tier of a mandate reverts `UnsupportedSigil` at bind.

### Signature sigils — gate the 1271 signing · `I1271Sigil` (`check1271`)

**`AttestationSigil`** gates what a bound mandate may ERC-1271 **sign** (not call): an allowlist of requesting
dApps (`allowedSenders`) and, optionally, an allowlist of the exact `hash` digests permitted (`allowedHashes`,
the ERC-7739-nested value actually validated). It is the gate behind gasless x402 — a voucher pins
`allowedSenders=[token]` + `allowedHashes=[the nested EIP-3009 digest]`, so the session key may 1271-approve
exactly one payment and nothing else.

Action sigils gate inputs; outcome sigils bound results; signature sigils gate gasless signing — and a single
mandate can carry any combination.

## Commands

```bash
forge build            # compile (via_ir off for fast iteration)
forge test             # 375 tests
forge fmt --check      # style gate (line 100, double quotes, wrap_comments off)
```
