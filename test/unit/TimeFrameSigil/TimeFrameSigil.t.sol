// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { TimeFrameSigil, TimeFrameConfig } from "@sigils/TimeFrameSigil/TimeFrameSigil.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title TimeFrameSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for the TimeFrameSigil unit suites: deploys the time-window sigil and exposes
///         the shared (account, configId) fixture plus an `_init` helper that configures a `[validAfter,
///         validUntil]` window for the test contract acting as the multiplexer (so `msg.sender` is fixed).
abstract contract TimeFrameSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant TARGET = address(0x7A86E7);

    /// @dev A 4-byte selector used to shape selector-only calldata in the check paths.
    bytes4 internal constant SEL = 0x12345678;

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    TimeFrameSigil internal timeFrame;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        timeFrame = new TimeFrameSigil();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Configure the sigil for (ID, this, ACCOUNT) with the given window. The test contract is the
    ///      multiplexer, so a later check from the same contract reads this config.
    function _init(uint48 validAfter, uint48 validUntil) internal {
        timeFrame.initializeWithMultiplexer(
            ACCOUNT,
            ID,
            abi.encode(TimeFrameConfig({ validAfter: validAfter, validUntil: validUntil }))
        );
    }
}
