// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import {
    SpendSigilConfigLib,
    SpendConfig,
    SpendState,
    Period
} from "@sigils/SpendSigil/lib/SpendSigilConfigLib.sol";

// Interfaces
import { ISigilBase, IERC165, ConfigId } from "@interfaces/ISigil.sol";
import { IOutcomeSigil } from "@interfaces/IOutcomeSigil.sol";

// forgefmt: disable-start
///  ________ ______ _____ _   _______ _____ _____ _____ _
/// /  ___| ___ \  ___|  \ | |  _  \  ___|  ___|_   _|  __ \_   _| |
/// \ `--.| |_/ / |__ |   \| | | | | |__ | |__   | | | |  \/ | | | |
///  `--. \  __/|  __|| . ` | | | | |  __||  __|  | | | | __  | | | |
/// /\__/ / |   | |___| |\  | |/ /| |___| |___ _| |_| |_\ \_| |_| |____
/// \____/\_|   \____/\_| \_/___/ \____/\____/ \___/ \____/\___/\_____/
///
///   pre  ─ snapshot balanceBefore (tstore)
///   post ─ itemize EVERY executed call → calldata-summed outflow (global, from the call set)
///          outflow = max(calldata-sum, balanceBefore − balanceAfter)
///          spent += outflow ≤ cap   ·   no dangling allowance
// forgefmt: disable-end
/// @title SpendSigil — a stateful, rolling-window spend cap (pure outcome guard)
/// @author highskore.eth
/// @notice A per-execution {IOutcomeSigil} that meters one budgeted asset's net outflow from the account against
///         a cap that resets on a rolling window. The budgeted asset is either an ERC-20 OR — when `token` is the
///         {NATIVE} sentinel (`0xEeee…EEeE`) — native ETH, bounding a self-relaying agent's native spend per
///         period. For an ERC-20 it closes the approval-bypass gap (ERC-1608 §Security): {postCheck} itemizes
///         EVERY executed call (the ERC-7579 set it is handed), summing each transfer/approve outflow of the
///         budgeted token, AND, as a backstop, the real balance delta is charged via `max(...)`, so an outflow
///         the calldata parse undercounts (an unparsed target, a flash-loan trick) is still metered; approvals
///         are recorded from the call set and must net to zero by the end of the execution — an approval is
///         *charged* to the budget yet can never dangle to be pulled out-of-band. For NATIVE the meter sums each
///         call's `value` directly (there is no allowance/pull primitive for ETH), with the native balance delta
///         as the same `max(...)` backstop.
/// @dev This is a PURE outcome sigil: the meter `max(calldata-summed outflow, balance delta)` plus the
///      auto-checked allowance is computed entirely from the executed call set in {postCheck}. {preCheck}
///      snapshots `balanceBefore` in EIP-1153 TRANSIENT storage (cancun), keyed by `(account, msg.sender,
///      token)` — the budgeted TOKEN, not the ConfigId. Transient storage auto-clears at end-of-tx, and
///      {preCheck} re-snapshots per execution so two executions bracketed in one transaction never leak. Only
///      the rolling `SpendState` is persistent.
///
///      Like every sigil it keys config by `(configId, msg.sender, account)`; the engine is baked into the
///      account, so `msg.sender == account` at runtime. This is a PURE outcome sigil: it has no ERC-1271 tier —
///      a 1271 per-op ceiling, when wanted, is a separate signature sigil ({Eip3009Sigil} / {AttestationSigil}).
///
///      SOUNDNESS INVARIANT (both ERC-20 and NATIVE): the calldata sum is GLOBAL — {postCheck} itemizes the
///      entire executed call set itself, so the sum over DIRECT budgeted-token outflows (transfer / account-from
///      transferFrom / approve / increaseAllowance, and each call's native `value`) is complete no matter which
///      action sigils gate the calls. This removes the prior per-action-attachment footgun: a same-execution
///      inflow can no longer MASK a direct budgeted-token outflow, because that outflow is in the global sum, not
///      only the (maskable) balance delta. Attachment is irrelevant for direct outflows.
///
///      RESIDUAL (by design, bounded — not closable in the meter): an outflow routed through an UNPARSED path —
///      a call to a NON-token target that moves the budgeted token (e.g. a pre-approved pull `sink`/router) — is
///      not in the calldata sum, so it is metered only by the balance delta, which a same-execution inflow can
///      mask. This is fundamental: two balance snapshots yield only the NET change for any flow the calldata
///      parse cannot see (and it matches the prior per-call model — a non-token target contributed zero to the
///      sum there too). It is bounded by the controls OUTSIDE the meter: a bounded agent cannot establish the
///      pull authority such a sink needs — an in-batch `approve`/`increaseAllowance` IS parsed and charged here,
///      blanket grants (permit / setApprovalForAll / authorizeOperator) revert {BlanketGrantBlocked}, and any
///      approve-spender left dangling reverts {DanglingAllowance} — so a standing allowance to an unparsed sink
///      can only come from the ROOT (owner) tier, which is unconstrained by design (ROOT bypasses the cap
///      outright). Within the bounded-agent threat model the residual is therefore unreachable; the per-action
///      allowlist further constrains which targets an agent may call at all.
///
///      SCOPE OF THE DANGLING SCAN — this is a MANDATE-LEVEL invariant, NOT a SpendSigil-alone guarantee (audit
///      M-3): {_scanDangling} checks only the BUDGETED token, and only the approve-spenders THIS execution
///      itemized. It cannot see a standing allowance on a DIFFERENT (un-budgeted) token. So "the residual is
///      unreachable" holds only if the WHOLE mandate's action set never lets the agent grant a standing
///      allowance on any token to a non-allowlisted sink — e.g. an `approve` action on an un-budgeted token would
///      re-open the cross-execution residual. The mandate builder (SDK) must uphold that; this sigil bounds only
///      its own budgeted token.
///
///      Accordingly this is a PURE outcome sigil ({IOutcomeSigil}): it implements neither the per-call action
///      gate nor the ERC-1271 signature gate, and advertises only the outcome tier via ERC-165 — so the engine's
///      per-tier bind guard reverts {MandateEngine.UnsupportedSigil} if it is placed in the action or signature
///      slot of a mandate. It must only ever be installed in the OUTCOME tier.
contract SpendSigil is IOutcomeSigil {
    using SafeTransferLib for address;
    using SpendSigilConfigLib for ConfigId;

    /*·:⛧:·──────── ERRORS ────────:⛧:·*/

    /// @notice Thrown when an execution's metered outflow would push cumulative spend over the cap.
    /// @param id The configuration id.
    /// @param spent The would-be cumulative spend for the period.
    /// @param cap The configured cap.
    error SpendCapExceeded(ConfigId id, uint256 spent, uint256 cap);

    /// @notice Thrown when an allowance the execution granted on the budgeted token was left dangling
    ///         (non-zero) at post-check — it could be pulled out-of-band, escaping the meter.
    /// @param id The configuration id.
    /// @param spender The spender whose allowance was not reset to zero.
    /// @param allowance The dangling allowance amount.
    error DanglingAllowance(ConfigId id, address spender, uint256 allowance);

    /// @notice Thrown at config time when the budgeted token is the zero address. Shares the {InvalidToken}
    ///         selector reverted by {SpendSigilConfigLib.initialize} (the configure path), so a revert there is
    ///         observable as `SpendSigil.InvalidToken`.
    error InvalidToken();

    /// @notice Thrown when an executed call is a Permit2 `approve` of the budgeted token. A Permit2 allowance
    ///         lives inside the Permit2 contract, not the token, so the post-check's `token.allowance(...)`
    ///         dangling-scan can't see it — the grant could persist and be pulled out-of-band in a later
    ///         period, escaping the cap. It cannot be safely metered/reset-checked here, so it is blocked.
    error Permit2GrantBlocked();

    /// @notice Thrown when an executed call is a blanket-grant primitive on the budgeted token — ERC-2612
    ///         `permit`, ERC-721/1155 `setApprovalForAll`, or ERC-777 `authorizeOperator`. Each grants pull
    ///         authority that the post-check's ERC-20 `allowance(owner,spender)` dangling-scan cannot see (an
    ///         operator flag / a 1271-permit allowance lives outside that mapping or is signed out-of-band), so
    ///         it could persist past this execution and be pulled in a later period, escaping the cap. The
    ///         meter cannot account for or revoke it, so it is blocked outright.
    error BlanketGrantBlocked();

    /*·:⛧:·──────── VIEWS ────────:⛧:·*/

    /// @notice The configuration for `(id, multiplexer, account)`. Mirrors a public-mapping getter over the
    ///         {SpendConfig} struct: returns its non-array members (the dynamic `spenders` list is omitted,
    ///         exactly as a Solidity auto-getter would).
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return token The budgeted ERC-20.
    /// @return cap The per-period cap.
    /// @return period The rolling window the cap resets on.
    function configs(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (address token, uint256 cap, Period period)
    {
        SpendConfig storage cfg = id.getConfig(multiplexer, account);
        return (cfg.token, cfg.cap, cfg.period);
    }

    /// @notice The rolling spend state for `(id, multiplexer, account)`. Mirrors a public-mapping getter over
    ///         the {SpendState} struct.
    /// @param id The configuration id.
    /// @param multiplexer The configuring caller (the engine/account).
    /// @param account The account the config applies to.
    /// @return spent The cumulative outflow charged within the current period.
    /// @return lastUpdated The unix-seconds timestamp of the last charge.
    function spendStates(
        ConfigId id,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256 spent, uint256 lastUpdated)
    {
        SpendState storage st = id.getState(multiplexer, account);
        return (st.spent, st.lastUpdated);
    }

    /*·:⛧:·──────── TRANSIENT KEYS ────────:⛧:·*/

    /// @dev Transient slot tag for the pre-execution balance snapshot, mixed into the per-execution key.
    uint256 private constant T_BALANCE_BEFORE = 0;

    /*·:⛧:·──────── SELECTORS ────────:⛧:·*/

    /// @dev ERC-20 `transfer(address,uint256)`; amount at calldata offset 0x24.
    bytes4 private constant TRANSFER = 0xa9059cbb;
    /// @dev ERC-20 `transferFrom(address,address,uint256)`; amount at offset 0x44.
    bytes4 private constant TRANSFER_FROM = 0x23b872dd;
    /// @dev ERC-20 `approve(address,uint256)`; spender at 0x04, amount at 0x24.
    bytes4 private constant APPROVE = 0x095ea7b3;
    /// @dev OZ ERC-20 `increaseAllowance(address,uint256)`; spender at 0x04, added value at 0x24.
    bytes4 private constant INCREASE_ALLOWANCE = 0x39509351;
    /// @dev Permit2 `approve(address,address,uint160,uint48)`; token at 0x04, spender at 0x24, amount at 0x44.
    bytes4 private constant PERMIT2_APPROVE = 0x87517c45;
    /// @dev EIP-2612 `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` — blanket grant, blocked.
    bytes4 private constant PERMIT = 0xd505accf;
    /// @dev ERC-721/1155 `setApprovalForAll(address,bool)` — operator grant, blocked.
    bytes4 private constant SET_APPROVAL_FOR_ALL = 0xa22cb465;
    /// @dev ERC-777 `authorizeOperator(address)` — operator grant, blocked.
    bytes4 private constant AUTHORIZE_OPERATOR = 0x959b8c3f;

    /*·:⛧:·──────── NATIVE ────────:⛧:·*/

    /// @dev Sentinel `token` selecting the NATIVE (ETH) budget instead of an ERC-20 — the canonical
    ///      `0xEeee…EEeE` native-asset address. When `cfg.token == NATIVE`, the meter charges the call's `value`
    ///      (and the account's native balance delta as a backstop) rather than parsing ERC-20 transfer/approve
    ///      calldata. Bounds a self-relaying agent's cumulative native spend per period — the native analogue of
    ///      the ERC-20 cap. Non-zero, so it passes {SpendSigilConfigLib.initialize}'s zero-token guard.
    address private constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /*·:⛧:·──────── PERIOD CONSTANTS ────────:⛧:·*/

    uint256 private constant MINUTE = 60;
    uint256 private constant HOUR = 3600;
    uint256 private constant DAY = 86_400;
    uint256 private constant WEEK = 604_800;

    /*·:⛧:·──────── INIT ────────:⛧:·*/

    /// @inheritdoc ISigilBase
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

    /*·:⛧:·──────── OUTCOME HOOKS ────────:⛧:·*/

    /// @inheritdoc IOutcomeSigil
    function preCheck(ConfigId id, address account) external {
        SpendConfig storage cfg = id.getConfig(msg.sender, account);
        address token = cfg.token;
        if (token == address(0)) revert PolicyNotInitialized(id, msg.sender, account);
        // Snapshot the pre-execution balance; {postCheck} charges the real delta as the meter backstop.
        // Keyed by the token (not the ConfigId) and overwritten each preCheck, so two executions bracketed
        // in one transaction never leak the first's snapshot into the second. NATIVE reads `account.balance`.
        _tstore(account, token, T_BALANCE_BEFORE, _balanceOf(token, account));
    }

    /// @inheritdoc IOutcomeSigil
    /// @dev The whole meter is computed HERE, globally, from the executed call set — no per-call attachment is
    ///      relied upon. It decodes every ERC-7579 call, sums the budgeted token's calldata outflow across all
    ///      of them, takes `max(...)` with the real balance delta, accrues against the rolling cap, and scans
    ///      every approve-spender the calls named for a dangling allowance.
    function postCheck(
        ConfigId id,
        address account,
        bytes32 mode,
        bytes calldata executionData
    )
        external
    {
        address token = id.getConfig(msg.sender, account).token;
        if (token == address(0)) revert PolicyNotInitialized(id, msg.sender, account);

        // Itemize the entire executed call set: the calldata-summed outflow is GLOBAL (built from every call),
        // and the approve-spenders are collected here for the dangling scan — neither relies on a per-call
        // checkAction having run. `spenders` is sized to the call count (an upper bound on distinct approves).
        (uint256 byCalldata, address[] memory spenders, uint256 spenderCount) =
            _itemize(account, token, mode, executionData);

        // Meter = max(calldata-summed outflow, real balance delta), accrued against the rolling cap.
        _accrue(id, account, token, byCalldata);

        // No dangling allowance (ERC-20 only): every approve-spender must net back to zero by close.
        _scanDangling(id, account, token, spenders, spenderCount);
    }

    /*·:⛧:·──────── INTERNAL: METER + ACCRUE ────────:⛧:·*/

    /// @dev Charge `max(byCalldata, real balance delta)` to the rolling spend and enforce the cap. The balance
    ///      delta catches outflows the calldata parse undercounts (an unparsed target, a pull via a granted
    ///      allowance, a flash trick); the global calldata sum catches outflows a same-execution inflow would
    ///      mask in the delta. Rolls the period (resetting `spent` across a window boundary) before accruing.
    function _accrue(ConfigId id, address account, address token, uint256 byCalldata) private {
        SpendConfig storage cfg = id.getConfig(msg.sender, account);
        uint256 delta =
            _saturatingSub(_tload(account, token, T_BALANCE_BEFORE), _balanceOf(token, account));
        uint256 outflow = byCalldata > delta ? byCalldata : delta;

        SpendState storage st = id.getState(msg.sender, account);
        uint256 spent = st.lastUpdated < startOfPeriod(cfg.period, block.timestamp) ? 0 : st.spent;
        spent += outflow;
        if (spent > cfg.cap) revert SpendCapExceeded(id, spent, cfg.cap);
        st.spent = spent;
        st.lastUpdated = block.timestamp;
    }

    /// @dev Require every approve-spender the execution named to have a zero allowance at close, so a grant is
    ///      charged to the budget yet can never be pulled out-of-band (verify-and-revert; the caller/SDK
    ///      includes the reset call in the same batch). Skipped for NATIVE — ETH has no allowance, the itemizer
    ///      never collects a spender for a native budget, and skipping it never calls `allowance` on the NATIVE
    ///      sentinel address.
    function _scanDangling(
        ConfigId id,
        address account,
        address token,
        address[] memory spenders,
        uint256 spenderCount
    )
        private
        view
    {
        if (token == NATIVE) return;
        for (uint256 i; i < spenderCount; ++i) {
            uint256 a = _allowance(token, account, spenders[i]);
            if (a != 0) revert DanglingAllowance(id, spenders[i], a);
        }
    }

    /*·:⛧:·──────── PERIOD ────────:⛧:·*/

    /// @notice Round `ts` down to the start of its `period` window — the boundary the rolling cap resets
    ///         on. A charge whose `lastUpdated` predates this boundary belongs to a closed window, so the
    ///         running `spent` is reset to zero before accruing.
    /// @param period The rolling window.
    /// @param ts The timestamp to round down.
    /// @return The unix-seconds start of the window containing `ts` (0 for `Forever`, so nothing resets).
    function startOfPeriod(Period period, uint256 ts) public pure returns (uint256) {
        if (period == Period.Minute) return ts - (ts % MINUTE);
        if (period == Period.Hour) return ts - (ts % HOUR);
        if (period == Period.Day) return ts - (ts % DAY);
        if (period == Period.Week) return ts - (ts % WEEK); // Thursday-aligned (unix epoch is a Thursday)
        if (period == Period.Month) return _startOfMonth(ts);
        if (period == Period.Year) return _startOfYear(ts);
        return 0; // Forever — sentinel; lastUpdated (>0 after the first charge) never predates it
    }

    /*·:⛧:·──────── ERC165 ────────:⛧:·*/

    /// @inheritdoc IERC165
    /// @dev Advertises the outcome tier only: {IERC165}, {ISigilBase}, {IOutcomeSigil}. It implements neither
    ///      the action nor the 1271 tier, so the engine's per-tier bind guard reverts {UnsupportedSigil} if it
    ///      is placed in an action or signature slot.
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IOutcomeSigil).interfaceId;
    }

    /*·:⛧:·──────── INTERNAL: GLOBAL ITEMIZER ────────:⛧:·*/

    /// @dev Decode the executed ERC-7579 call set (single or batch) and itemize the budgeted token's outflow
    ///      across EVERY call — the GLOBAL calldata sum {postCheck} meters against, plus the approve-spenders to
    ///      scan for a dangling allowance. No per-call attachment is relied upon, so the sum is complete no
    ///      matter how the actions are gated. Mirrors the old per-call parse, applied uniformly to all calls.
    /// @param account The account whose outflow is metered (own-funds transfers/approves only).
    /// @param token The budgeted token (or the {NATIVE} sentinel).
    /// @param mode The ERC-7579 execution mode (first byte: 0 single, 1 batch).
    /// @param executionData The ERC-7579-encoded call(s).
    /// @return sum The global calldata-summed outflow of the budgeted token.
    /// @return spenders The approve-spenders named by the calls (length is an upper bound; only the first
    ///         `spenderCount` are valid). Empty for a NATIVE budget.
    /// @return spenderCount The number of valid (de-duplicated) entries in `spenders`.
    function _itemize(
        address account,
        address token,
        bytes32 mode,
        bytes calldata executionData
    )
        private
        pure
        returns (uint256 sum, address[] memory spenders, uint256 spenderCount)
    {
        if (uint8(LibERC7579.getCallType(mode)) == 0) {
            (address to, uint256 value, bytes calldata data) =
                LibERC7579.decodeSingle(executionData);
            spenders = new address[](1);
            address spender;
            (sum, spender) = _itemizeOne(account, token, to, value, data);
            if (spender != address(0)) spenderCount = _collectSpender(spenders, 0, spender);
        } else {
            // callType 1 (batch). ExecLib rejects any other call type before the loop, so by the time the
            // outcome hooks run the execution data is a well-formed single or batch.
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
            spenders = new address[](pointers.length);
            (sum, spenderCount) = _itemizeBatch(account, token, pointers, spenders);
        }
    }

    /// @dev Itemize a decoded ERC-7579 batch into the global outflow sum + collected approve-spenders. Split
    ///      out of {_itemize} to keep each frame within stack limits without via-IR.
    function _itemizeBatch(
        address account,
        address token,
        bytes32[] calldata pointers,
        address[] memory spenders
    )
        private
        pure
        returns (uint256 sum, uint256 spenderCount)
    {
        for (uint256 i; i < pointers.length; ++i) {
            (address to, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
            (uint256 callOutflow, address spender) = _itemizeOne(account, token, to, value, data);
            sum += callOutflow;
            if (spender != address(0)) {
                spenderCount = _collectSpender(spenders, spenderCount, spender);
            }
        }
    }

    /// @dev Itemize ONE call's contribution to the budgeted token's outflow. Returns the call's calldata
    ///      outflow and, for an approve/increaseAllowance of the budgeted token, the granted `spender` (else
    ///      `address(0)`) for the caller to collect into the dangling-scan set.
    /// @return outflow The budgeted token's calldata outflow this call contributes.
    /// @return spender The approve-spender this call grants (or `address(0)` if none).
    function _itemizeOne(
        address account,
        address token,
        address target,
        uint256 value,
        bytes calldata data
    )
        private
        pure
        returns (uint256 outflow, address spender)
    {
        // NATIVE budget: the call's `value` IS the outflow — there is no token calldata to parse and no
        // allowance/pull primitive for native (the post-check still maxes it with the native balance delta).
        if (token == NATIVE) return (value, address(0));
        if (data.length < 4) return (0, address(0));
        bytes4 sel = bytes4(data[0:4]);

        // Permit2 `approve` is a call to the Permit2 contract (NOT the token), carrying the token as its first
        // arg; handle it before the `target == token` gate. A Permit2 allowance lives INSIDE the Permit2
        // contract, so the `token.allowance(...)` dangling-scan can't see it — a Permit2 grant of the budgeted
        // token could persist and be pulled out-of-band in a later period, escaping that period's cap. So a
        // Permit2-approve of the budgeted token is blocked outright (revert). Permit2 calls for OTHER tokens
        // pass through — any resulting outflow of the budgeted token is still caught by the balance delta.
        if (sel == PERMIT2_APPROVE) {
            if (data.length < 0x64) return (0, address(0));
            if (address(uint160(_word(data, 0x04))) == token) revert Permit2GrantBlocked();
            return (0, address(0));
        }

        // Everything else only matters when it targets the budgeted token directly; other targets are caught
        // by the balance-delta backstop in postCheck.
        if (target != token) return (0, address(0));

        // Blanket-grant primitives on the budgeted token grant pull authority the post-check's ERC-20
        // `allowance(owner,spender)` dangling-scan cannot see — an ERC-721/1155/777 operator flag lives in a
        // different mapping, and a 1271 `permit` is honored out-of-band — so the grant would persist past this
        // execution and be pulled in a later period, escaping the cap (the meter can neither account for nor
        // revoke it). Block them outright on the budgeted token, mirroring the Permit2 block above.
        if (sel == PERMIT || sel == SET_APPROVAL_FOR_ALL || sel == AUTHORIZE_OPERATOR) {
            revert BlanketGrantBlocked();
        }

        if (sel == TRANSFER) {
            return (data.length >= 0x44 ? _word(data, 0x24) : 0, address(0));
        }
        if (sel == TRANSFER_FROM) {
            // Only the account's own funds count as outflow; `transferFrom(from, to, amt)` where
            // `from != account` pulls a third party's tokens (the account's balance is unchanged), so the
            // delta backstop — not this calldata sum — is the right meter for it.
            if (data.length >= 0x64 && address(uint160(_word(data, 0x04))) == account) {
                return (_word(data, 0x44), address(0));
            }
            return (0, address(0));
        }
        if (sel == APPROVE || sel == INCREASE_ALLOWANCE) {
            // `approve` sets the allowance; `increaseAllowance` adds to it — both grant pull authority, so both
            // are metered (the named amount / added value) and their spender collected for the post
            // dangling-check, exactly alike. (Who may be approved is enforced by the permitting action sigil,
            // not here — this sigil is the meter, not the gate.)
            if (data.length >= 0x44) {
                return (_word(data, 0x24), address(uint160(_word(data, 0x04))));
            }
            return (0, address(0));
        }
        return (0, address(0));
    }

    /// @dev Append `spender` (de-duplicated) to `spenders[0:spenderCount]`, returning the new count.
    function _collectSpender(
        address[] memory spenders,
        uint256 spenderCount,
        address spender
    )
        private
        pure
        returns (uint256)
    {
        for (uint256 i; i < spenderCount; ++i) {
            if (spenders[i] == spender) return spenderCount;
        }
        spenders[spenderCount] = spender;
        return spenderCount + 1;
    }

    /*·:⛧:·──────── INTERNAL: TRANSIENT ────────:⛧:·*/

    /// @dev The transient slot for `(account, msg.sender, token, tag)`. Keyed by the budgeted TOKEN, not the
    ///      ConfigId. Domain-separated so concurrent accounts/tokens in one tx never collide; transient storage
    ///      auto-clears at the end of the transaction.
    function _tslot(address account, address token, uint256 tag) private view returns (bytes32 s) {
        s = keccak256(abi.encode(account, msg.sender, token, tag));
    }

    /// @dev Transient store at `(account, token, tag)`.
    function _tstore(address account, address token, uint256 tag, uint256 v) private {
        bytes32 s = _tslot(account, token, tag);
        assembly {
            tstore(s, v)
        }
    }

    /// @dev Transient load at `(account, token, tag)`.
    function _tload(address account, address token, uint256 tag) private view returns (uint256 v) {
        bytes32 s = _tslot(account, token, tag);
        assembly {
            v := tload(s)
        }
    }

    /*·:⛧:·──────── INTERNAL: MATH + CALLDATA ────────:⛧:·*/

    /// @dev `a - b`, floored at zero (no underflow).
    function _saturatingSub(uint256 a, uint256 b) private pure returns (uint256) {
        unchecked {
            return a > b ? a - b : 0;
        }
    }

    /// @dev The metered balance of `token` held by `account`: `account.balance` for the {NATIVE} sentinel, else
    ///      the ERC-20 `balanceOf`. Lets the pre/post balance-delta backstop serve both the ERC-20 and native budgets.
    function _balanceOf(address token, address account) private view returns (uint256) {
        return token == NATIVE ? account.balance : token.balanceOf(account);
    }

    /// @dev Read the 32-byte word at `offset` in `data` (offset is absolute, incl. the 4-byte selector).
    function _word(bytes calldata data, uint256 offset) private pure returns (uint256) {
        return uint256(bytes32(data[offset:offset + 32]));
    }

    /// @dev `IERC20.allowance(owner, spender)` via a low-level staticcall (solady's lib has no allowance).
    function _allowance(
        address token,
        address owner,
        address spender
    )
        private
        view
        returns (uint256 a)
    {
        (bool ok, bytes memory ret) =
            token.staticcall(abi.encodeWithSelector(0xdd62ed3e, owner, spender));
        if (ok && ret.length >= 32) a = abi.decode(ret, (uint256));
    }

    /*·:⛧:·──────── INTERNAL: CALENDAR ────────:⛧:·*/

    /// @dev Start (unix seconds, UTC) of the calendar month containing `ts`.
    function _startOfMonth(uint256 ts) private pure returns (uint256) {
        (uint256 y, uint256 m,) = _toDate(ts);
        return _toTimestamp(y, m, 1);
    }

    /// @dev Start (unix seconds, UTC) of the calendar year containing `ts`.
    function _startOfYear(uint256 ts) private pure returns (uint256) {
        (uint256 y,,) = _toDate(ts);
        return _toTimestamp(y, 1, 1);
    }

    /// @dev Civil-calendar conversion of a unix timestamp to (year, month, day), UTC. Algorithm by
    ///      Howard Hinnant (days_from_civil inverse), as used in BokkyPooBah's DateTime library.
    function _toDate(uint256 ts) private pure returns (uint256 year, uint256 month, uint256 day) {
        unchecked {
            int256 z = int256(ts / DAY) + 719_468;
            int256 era = (z >= 0 ? z : z - 146_096) / 146_097;
            uint256 doe = uint256(z - era * 146_097);
            uint256 yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            int256 y = int256(yoe) + era * 400;
            uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            uint256 mp = (5 * doy + 2) / 153;
            day = doy - (153 * mp + 2) / 5 + 1;
            month = mp < 10 ? mp + 3 : mp - 9;
            year = uint256(y + (month <= 2 ? int256(1) : int256(0)));
        }
    }

    /// @dev Civil-calendar (year, month, day) at 00:00:00 UTC to a unix timestamp (inverse of {_toDate}).
    function _toTimestamp(uint256 year, uint256 month, uint256 day) private pure returns (uint256) {
        unchecked {
            int256 y = int256(year);
            if (month <= 2) y -= 1;
            int256 era = (y >= 0 ? y : y - 399) / 400;
            uint256 yoe = uint256(y - era * 400);
            uint256 mp = month > 2 ? month - 3 : month + 9;
            uint256 doy = (153 * mp + 2) / 5 + day - 1;
            uint256 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            int256 days_ = era * 146_097 + int256(doe) - 719_468;
            return uint256(days_) * DAY;
        }
    }
}
