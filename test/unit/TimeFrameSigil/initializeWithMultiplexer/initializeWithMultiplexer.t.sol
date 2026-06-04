// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { TimeFrameSigil_Unit_Test } from "../TimeFrameSigil.t.sol";

// Contracts
import { TimeFrameConfig } from "@sigils/TimeFrameSigil/TimeFrameSigil.sol";
import { TimeFrameConfigLib } from "@sigils/TimeFrameSigil/lib/TimeFrameConfigLib.sol";

// Interfaces
import { ISigilBase } from "@interfaces/ISigil.sol";

// Types
import { ConfigId, VALIDATION_SUCCESS, VALIDATION_FAILED } from "@interfaces/ISigil.sol";

/// @title TimeFrameSigil.initializeWithMultiplexer Unit Tests
/// @author highskore.eth
/// @notice Config installation: the `[validAfter, validUntil]` window is decoded from `initData` and persisted
///         keyed by (id, multiplexer, account), announced via SigilSet. Satisfiable windows are accepted
///         (including the open-ended `(0,0)` and any `validUntil == 0`); an unsatisfiable window
///         (`validAfter > validUntil` with a real `validUntil`) is rejected at init.
contract TimeFrameSigil_initializeWithMultiplexer_Unit_Test is TimeFrameSigil_Unit_Test {
    uint48 internal constant VALID_AFTER = 1000;
    uint48 internal constant VALID_UNTIL = 2000;

    /// @notice A valid window is persisted (validAfter, validUntil) keyed by (id, multiplexer, account).
    function test_initializeWithMultiplexer_persistsConfig() external {
        _init(VALID_AFTER, VALID_UNTIL);
        (uint48 validAfter, uint48 validUntil) =
            timeFrame.timeFrameConfigs(ID, address(this), ACCOUNT);
        assertEq(validAfter, VALID_AFTER, "validAfter");
        assertEq(validUntil, VALID_UNTIL, "validUntil");
    }

    /// @notice Configuration emits SigilSet keyed by (id, multiplexer, account).
    function test_initializeWithMultiplexer_emitsSigilSet() external {
        vm.expectEmit(true, true, true, true, address(timeFrame));
        emit ISigilBase.SigilSet(ID, address(this), ACCOUNT);
        timeFrame.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(TimeFrameConfig({ validAfter: VALID_AFTER, validUntil: VALID_UNTIL }))
        );
    }

    /// @notice Re-initializing the same (id, multiplexer, account) overwrites the window with the new one.
    function test_initializeWithMultiplexer_overwrites() external {
        _init(VALID_AFTER, VALID_UNTIL);
        _init(5000, 6000);
        (uint48 validAfter, uint48 validUntil) =
            timeFrame.timeFrameConfigs(ID, address(this), ACCOUNT);
        assertEq(validAfter, 5000, "validAfter overwritten");
        assertEq(validUntil, 6000, "validUntil overwritten");
    }

    /// @notice The config is scoped by `msg.sender` (the multiplexer): a window installed by THIS contract is
    ///         not read for a different multiplexer's slot. We verify by checking the configured slot is empty
    ///         for an unrelated multiplexer address (reads as the zero window).
    function test_initializeWithMultiplexer_scopedByMultiplexer() external {
        _init(VALID_AFTER, VALID_UNTIL);
        (uint48 otherAfter, uint48 otherUntil) =
            timeFrame.timeFrameConfigs(ID, address(0xDEAD), ACCOUNT);
        assertEq(otherAfter, 0, "other multiplexer slot is empty (validAfter)");
        assertEq(otherUntil, 0, "other multiplexer slot is empty (validUntil)");
    }

    /// @notice The persisted window is the one the check paths read back: configure [1000,2000], then a
    ///         timestamp inside it succeeds and one outside fails.
    function test_initializeWithMultiplexer_windowDrivesCheck() external {
        _init(VALID_AFTER, VALID_UNTIL);

        vm.warp(1500);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_SUCCESS,
            "configured window permits in-window"
        );

        vm.warp(uint256(VALID_UNTIL) + 1);
        assertEq(
            timeFrame.checkAction(ID, ACCOUNT, TARGET, 0, abi.encodePacked(SEL)),
            VALIDATION_FAILED,
            "configured window denies out-of-window"
        );
    }

    /// @notice An unsatisfiable window (`validAfter > validUntil`, `validUntil != 0`) is rejected at init
    ///         rather than binding a permanently-inert config.
    function test_initializeWithMultiplexer_revertsUnsatisfiableWindow() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                TimeFrameConfigLib.UnsatisfiableWindow.selector, VALID_UNTIL, VALID_AFTER
            )
        );
        timeFrame.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            // validAfter (2000) > validUntil (1000), validUntil real → unsatisfiable
            abi.encode(TimeFrameConfig({ validAfter: VALID_UNTIL, validUntil: VALID_AFTER }))
        );
    }

    /// @notice `validUntil == 0` is the open-ended sentinel and is accepted even with a large `validAfter`
    ///         (it is NOT treated as `validAfter > validUntil`).
    function test_initializeWithMultiplexer_acceptsOpenEndedWithLargeValidAfter() external {
        _init(VALID_AFTER, 0);
        (uint48 validAfter, uint48 validUntil) =
            timeFrame.timeFrameConfigs(ID, address(this), ACCOUNT);
        assertEq(validAfter, VALID_AFTER, "validAfter persisted");
        assertEq(validUntil, 0, "open-ended validUntil persisted");
    }
}
