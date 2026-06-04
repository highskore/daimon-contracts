// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { SpendSigil_Unit_Test } from "../SpendSigil.t.sol";

// Contracts
import { Period } from "@sigils/SpendSigil/SpendSigil.sol";

/// @title SpendSigil.startOfPeriod Unit Tests
/// @author highskore.eth
/// @notice Proves each period rounds the timestamp down to its window boundary — the instant the rolling
///         cap resets on — and that Forever is a zero sentinel that never resets.
contract SpendSigil_startOfPeriod_Unit_Test is SpendSigil_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev A fixed reference instant: 2021-06-22 12:34:56 UTC.
    uint256 internal constant TS = 1_624_365_296;

    // ── HARDCODED ground-truth boundaries for TS, independently derived from a calendar (NOT recomputed with
    //    the SUT's own `ts - ts % P` formula — that would co-hide a formula bug in both the SUT and the test).
    uint256 internal constant MINUTE_START = 1_624_365_240; // 2021-06-22 12:34:00 UTC
    uint256 internal constant HOUR_START = 1_624_363_200; // 2021-06-22 12:00:00 UTC
    uint256 internal constant DAY_START = 1_624_320_000; // 2021-06-22 00:00:00 UTC
    uint256 internal constant WEEK_START = 1_623_888_000; // 2021-06-17 00:00:00 UTC (a Thursday)
    uint256 internal constant MONTH_START = 1_622_505_600; // 2021-06-01 00:00:00 UTC
    uint256 internal constant YEAR_START = 1_609_459_200; // 2021-01-01 00:00:00 UTC

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minute rounds down to the start of the minute.
    function test_startOfPeriod_minute() external view {
        // Act & Assert
        assertEq(
            spendSigil.startOfPeriod(Period.Minute, TS), MINUTE_START, "2021-06-22 12:34:00 UTC"
        );
    }

    /// @notice Hour rounds down to the start of the hour.
    function test_startOfPeriod_hour() external view {
        // Act & Assert
        assertEq(spendSigil.startOfPeriod(Period.Hour, TS), HOUR_START, "2021-06-22 12:00:00 UTC");
    }

    /// @notice Day rounds down to UTC midnight.
    function test_startOfPeriod_day() external view {
        // Act & Assert
        assertEq(spendSigil.startOfPeriod(Period.Day, TS), DAY_START, "2021-06-22 00:00:00 UTC");
    }

    /// @notice Week rounds down to the Thursday-aligned week boundary (unix epoch is a Thursday).
    function test_startOfPeriod_week() external view {
        // Act & Assert
        assertEq(
            spendSigil.startOfPeriod(Period.Week, TS), WEEK_START, "2021-06-17 00:00 UTC (Thu)"
        );
    }

    /// @notice Month rounds down to 00:00:00 UTC on the 1st of the month (2021-06-01).
    function test_startOfPeriod_month() external view {
        // Act & Assert
        assertEq(spendSigil.startOfPeriod(Period.Month, TS), MONTH_START, "2021-06-01 00:00 UTC");
    }

    /// @notice Year rounds down to 00:00:00 UTC on Jan 1 of the year (2021-01-01).
    function test_startOfPeriod_year() external view {
        // Act & Assert
        assertEq(spendSigil.startOfPeriod(Period.Year, TS), YEAR_START, "2021-01-01 00:00 UTC");
    }

    /// @notice Forever is a sentinel (0): any positive `lastUpdated` is >= it, so the cap never resets.
    function test_startOfPeriod_forever_isZeroSentinel() external view {
        // Act & Assert
        assertEq(spendSigil.startOfPeriod(Period.Forever, TS), 0, "Forever sentinel");
    }
}
