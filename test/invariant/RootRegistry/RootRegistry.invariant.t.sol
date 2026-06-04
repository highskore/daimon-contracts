// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "forge-std/Test.sol";

// Contracts
import { RootRegistryHarness } from "@test/mock/RootRegistryHarness.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";

// Handlers
import { RootRegistryHandler } from "./RootRegistryHandler.sol";

/// @title RootRegistry Invariant Tests
/// @author highskore.eth
/// @notice Stateful-fuzz proof of the ROOT OR-set's access-control safety: across any interleaving of installs
///         and removes, (1) at least one root always remains (the account can never be bricked), and (2) the
///         on-chain installed set always equals an independent ghost. An installed scheme is active — membership
///         in the set is the only notion of "active", there is no timelock.
/// @dev FALSIFICATION PROTOCOL (designed to FAIL on a broken SUT):
///        - Drop the `length() <= 1` guard in {RootRegistry._removeRoot} → handler "BRICK" oracle +
///          {invariant_atLeastOneRoot} trip.
///        - Make `_removeRoot` skip the `validators.remove` / `_installRoot` skip the `validators.add` →
///          {invariant_setMatchesGhost} trips (the on-chain set diverges from the ghost).
contract RootRegistry_Invariant_Test is Test {
    RootRegistryHarness internal reg;
    RootRegistryHandler internal handler;

    uint256 internal constant POOL_SIZE = 10;

    function setUp() public {
        reg = new RootRegistryHarness();

        address[] memory pool = new address[](POOL_SIZE);
        for (uint256 i; i < POOL_SIZE; ++i) {
            pool[i] = address(new ECDSAValidator());
        }
        // Genesis: install pool[0], so there is always >= 1 root to start.
        reg.installRoot(pool[0], abi.encode(pool[0]));

        handler = new RootRegistryHandler(reg, pool);

        targetContract(address(handler));
    }

    /// @notice SAFETY: at least one root always remains — the account can never be bricked. Derived from the
    ///         INDEPENDENT ghost, NOT from a SUT counter: the count is PINNED to the ghost here, and
    ///         {invariant_setMatchesGhost} separately pins `reg.isRootInstalled()` per entry.
    function invariant_atLeastOneRoot() public view {
        uint256 ghostCount;
        uint256 n = handler.poolLength();
        for (uint256 i; i < n; ++i) {
            if (handler.ghostInstalled(handler.poolAt(i))) ++ghostCount;
        }
        assertGe(ghostCount, 1, "no root in the ghost (account would be bricked)");
        assertEq(reg.rootValidators().length, ghostCount, "reg root count diverged from the ghost");
    }

    /// @notice CORRECTNESS: the on-chain installed set equals the independent ghost. An installed scheme is
    ///         always active, so membership is the whole story.
    function invariant_setMatchesGhost() public view {
        uint256 n = handler.poolLength();
        for (uint256 i; i < n; ++i) {
            address v = handler.poolAt(i);
            assertEq(
                reg.isRootInstalled(v),
                handler.ghostInstalled(v),
                "installed set diverged from ghost"
            );
        }
    }

    /// @notice COVERAGE: the fuzz actually reached every interesting branch.
    function afterInvariant() public view {
        assertGt(handler.added(), 0, "no installs explored");
        assertGt(handler.removed(), 0, "no removes explored");
        assertGt(handler.removeRejectedLast(), 0, "last-root protection never exercised");
    }
}
