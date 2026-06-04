// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { TimeFrameSigil, TimeFrameConfig } from "@sigils/TimeFrameSigil/TimeFrameSigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title TimeFrameSigil_Symbolic_Test — machine-proven ∀-input window correctness
/// @author highskore.eth
/// @notice Halmos symbolic proof (issue #106) that {TimeFrameSigil.checkAction} returns
///         {VALIDATION_SUCCESS} *iff* `block.timestamp` is inside the configured window, over
///         SYMBOLIC `validAfter`, `validUntil`, and `block.timestamp`. Mirrors the unit suite's
///         (ID, this-as-multiplexer, ACCOUNT) fixture so the post-`vm.warp` `checkAction` reads
///         exactly the config we wrote.
/// @dev The proven property (both directions, in a single equivalence assertion):
///        SUCCESS  ⇔  (now >= validAfter) AND (validUntil == 0 OR now <= validUntil)
///      so SUCCESS ⟹ in-window AND in-window ⟹ SUCCESS, with the two config sentinels covered:
///        - `validUntil == 0`  = NO upper bound (action never expires);
///        - `validAfter > validUntil` (validUntil != 0) = unsatisfiable window — REJECTED at init
///          ({TimeFrameConfigLib.UnsatisfiableWindow}), so it never reaches `checkAction`; this proof
///          assumes a satisfiable window and proves the in-window equivalence over the configurable space.
///
///      Symbolic bound: `validAfter`, `validUntil` are `uint48` (the real config field width). The
///      symbolic `block.timestamp` is constrained to `uint48` via {vm.assume} — timestamps are unix
///      seconds and the sigil only ever compares against `uint48` bounds, so a `now` above `2**48-1`
///      is uninteresting (always strictly greater than any bound) and would only bloat the solver.
///      No loops/arrays here, so the global `--loop`/`--array-lengths` bounds do not bite this proof.
contract TimeFrameSigil_Symbolic_Test is Test {
    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0x7A86E7);

    TimeFrameSigil internal timeFrame;

    function setUp() public {
        timeFrame = new TimeFrameSigil();
    }

    /// @notice ∀ (validAfter, validUntil, now): `checkAction` SUCCESS ⇔ now is inside the window.
    /// @dev Params are symbolic (halmos). We deploy + configure with the symbolic window, `vm.warp`
    ///      to the symbolic `now`, then assert the iff between the real return code and the spec.
    function check_checkAction_iff_inWindow(
        uint48 validAfter,
        uint48 validUntil,
        uint256 nowTs
    )
        public
    {
        // `block.timestamp` is unix seconds; the sigil only compares it to `uint48` bounds.
        vm.assume(nowTs <= type(uint48).max);
        // Unsatisfiable windows (validAfter > validUntil, validUntil != 0) are now rejected at init
        // ({TimeFrameConfigLib.UnsatisfiableWindow}), so configure only satisfiable ones — the in-window
        // equivalence is proven over the configurable space. The init-rejection is covered by the unit suite.
        vm.assume(validUntil == 0 || validAfter <= validUntil);

        // Configure the symbolic window for (ID, this-as-multiplexer, ACCOUNT).
        timeFrame.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(TimeFrameConfig({ validAfter: validAfter, validUntil: validUntil }))
        );

        // Move to the symbolic timestamp, then run the real check (reads no calldata).
        vm.warp(nowTs);
        uint256 code = timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, hex"");

        // The spec: in-window iff lower bound met AND (no upper bound OR upper bound met).
        bool inWindow = nowTs >= validAfter && (validUntil == 0 || nowTs <= validUntil);

        // Equivalence captures BOTH directions of the iff in one shot.
        assert((code == VALIDATION_SUCCESS) == inWindow);
        // The return is a strict two-valued code: not SUCCESS ⟹ exactly FAILED.
        assert(code == VALIDATION_SUCCESS || code == VALIDATION_FAILED);
    }
}
