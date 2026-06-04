// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

// Contracts
import { OmniSigil } from "@sigils/OmniSigil/OmniSigil.sol";

// Interfaces
import { ConfigId, VALIDATION_SUCCESS } from "@interfaces/ISigil.sol";

/// @title OmniSigilLimitHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the OmniSigil `LimitUsage` cumulative-arg-cap invariants. One bounded
///         action ({charge}) drives the REAL {OmniSigil.checkAction} against a single `isLimited` rule, while
///         an INDEPENDENT ghost mirrors the on-chain `used` and counters record that both branches (an accepted
///         charge and an over-limit denial) were actually reached.
/// @dev The handler is its own oracle: a charge the ghost predicts is within the limit MUST be accepted (return
///      VALIDATION_SUCCESS) and one it predicts is over the limit MUST be denied — any disagreement reverts the
///      handler ("LIMIT BYPASSED" / "SPURIOUS DENY"), failing the run. There is no time/rollover dimension: the
///      cap is a monotone running total with no reset (unlike SpendSigil's rolling window). `checkAction`
///      returns a status (it does not revert on an over-limit charge), so no try/catch is needed; the accrual
///      only persists on a SUCCESS, matching the real engine where a FAILED check reverts the execution.
contract OmniSigilLimitHandler is CommonBase, StdCheats, StdUtils {
    OmniSigil internal immutable sigil;
    ConfigId internal immutable cid;
    address internal immutable account;
    uint256 internal immutable limit;

    /// @dev An arbitrary 4-byte selector; the limited rule reads the first word AFTER it (offset 0).
    bytes4 private constant SELECTOR = 0x12345678;

    /// @notice Independent ghost of the on-chain rule `used`.
    uint256 public ghostUsed;

    /// @notice Coverage telemetry: asserted > 0 in afterInvariant so a no-op fuzz run fails loudly.
    uint256 public successfulCharges;
    uint256 public deniedCharges;

    constructor(OmniSigil _sigil, ConfigId _cid, uint256 _limit) {
        sigil = _sigil;
        cid = _cid;
        limit = _limit;
        account = address(this); // multiplexer == account == this handler
    }

    /// @notice Charge a fuzzed value against the limited rule (the real `checkAction` accrual path).
    /// @param param The fuzzed argument value (bounded to straddle the per-charge and cumulative limit).
    function charge(uint256 param) external {
        param = bound(param, 0, limit * 2);
        bool predictAccept = ghostUsed + param <= limit;

        // Calldata the rule reads: a 4-byte selector then the param as the first 32-byte word (offset 0).
        bytes memory data = abi.encodePacked(SELECTOR, bytes32(param));
        uint256 r = sigil.checkAction(cid, account, address(0), 0, data);

        if (r == VALIDATION_SUCCESS) {
            require(predictAccept, "LIMIT BYPASSED: checkAction accepted an over-limit charge");
            ghostUsed += param; // accrual persists only on success (engine reverts a FAILED check)
            ++successfulCharges;
        } else {
            require(!predictAccept, "SPURIOUS DENY: checkAction rejected a within-limit charge");
            ++deniedCharges;
        }
    }
}
