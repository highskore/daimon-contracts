// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

// Contracts
import { RootRegistryHarness } from "@test/mock/RootRegistryHarness.sol";

/// @title RootRegistryHandler
/// @author highskore.eth
/// @notice Stateful-fuzz handler for the RootRegistry OR-set invariants. Bounded actions over a fixed validator
///         pool — {installRoot} and {removeRoot} — drive the REAL registry, while an INDEPENDENT ghost mirrors
///         the installed set. An installed scheme is active (membership == active; there is no timelock). The
///         handler is its own oracle on the one safety rule: removing the last installed scheme MUST revert —
///         any disagreement reverts the handler ("BRICK" / "SPURIOUS REVERT"), failing the run. A driver action
///         ({drainToLastAndReject}) deterministically forces that boundary — a random-walk extreme the plain
///         action never reaches — so the reject oracle is reliably exercised. Branch counters prove the fuzz
///         reached each state.
contract RootRegistryHandler is CommonBase, StdCheats, StdUtils {
    RootRegistryHarness internal immutable reg;

    /// @dev The fixed candidate-validator pool (set once in the constructor; index 0 is bootstrapped by setUp).
    address[] internal pool;

    // ── independent ghost of the on-chain ROOT set ──
    mapping(address => bool) public ghostInstalled;

    // ── coverage telemetry: asserted > 0 in afterInvariant ──
    uint256 public added;
    uint256 public removed;
    uint256 public removeRejectedLast;

    constructor(RootRegistryHarness _reg, address[] memory _pool) {
        reg = _reg;
        pool = _pool;
        // pool[0] is installed by setUp BEFORE this handler is constructed (same block), so seed the ghost to
        // match. Done HERE (constructor), not via an external fn — the invariant fuzzer targets every external
        // non-view method, so a `recordBootstrap`-style setter would be fuzzed with a random address and corrupt
        // the ghost.
        ghostInstalled[_pool[0]] = true;
    }

    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    function poolAt(uint256 i) external view returns (address) {
        return pool[i];
    }

    function _pick(uint256 seed) internal view returns (address) {
        return pool[bound(seed, 0, pool.length - 1)];
    }

    /// @notice Install a fuzzed pool validator (active immediately).
    function installRoot(uint256 seed) external {
        address v = _pick(seed);
        if (ghostInstalled[v]) return; // already installed (RootAlreadyInstalled is unit-tested separately)
        reg.installRoot(v, abi.encode(v)); // no cap, not installed ⇒ must succeed
        ghostInstalled[v] = true;
        ++added;
    }

    /// @notice Remove a fuzzed installed pool validator (the can't-remove-last rule is the oracle).
    function removeRoot(uint256 seed) external {
        address v = _pick(seed);
        if (!ghostInstalled[v]) return; // not installed (RootNotInstalled is unit-tested separately)
        bool isLast = reg.rootValidators().length <= 1;
        try reg.removeRoot(v, "") {
            require(!isLast, "BRICK: removed the last root");
            ghostInstalled[v] = false;
            ++removed;
        } catch {
            require(isLast, "SPURIOUS REVERT: remove rejected a non-last root");
            ++removeRejectedLast;
        }
    }

    /// @notice Deterministically drain to a single root, then prove last-root removal is REJECTED. Like any
    ///         boundary this is a random-walk extreme the plain {removeRoot} action never reaches; this driver
    ///         guarantees the brick-protection oracle is exercised. Surplus roots are removable, so a single scan
    ///         drains down to exactly one protected root.
    function drainToLastAndReject() external {
        for (uint256 i; i < pool.length; ++i) {
            address v = pool[i];
            if (!ghostInstalled[v]) continue;
            if (reg.rootValidators().length <= 1) break; // the protected last root
            reg.removeRoot(v, ""); // not last ⇒ must succeed (no try: a revert here fails the run)
            ghostInstalled[v] = false;
            ++removed;
        }
        for (uint256 i; i < pool.length; ++i) {
            address v = pool[i];
            if (!ghostInstalled[v]) continue; // the sole survivor: the last root
            try reg.removeRoot(v, "") {
                revert("BRICK: removed the last root");
            } catch {
                require(reg.rootValidators().length <= 1, "SPURIOUS REVERT: non-last rejected");
                ++removeRejectedLast;
            }
            break;
        }
    }
}
