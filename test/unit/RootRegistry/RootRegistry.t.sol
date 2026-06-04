// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { RootRegistryHarness } from "@test/mock/RootRegistryHarness.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";

/// @title RootRegistry_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for RootRegistry unit suites: deploys the harness wrapping the abstract ROOT
///         layer plus a stable of real {ECDSAValidator} schemes, and provides the install/sign helpers the
///         function suites reuse. Exercises the real registry — only the enclosing account is harnessed.
abstract contract RootRegistry_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    RootRegistryHarness internal registry;

    ECDSAValidator internal validatorA;
    ECDSAValidator internal validatorB;

    address internal signerA;
    uint256 internal signerAPk;
    address internal signerB;
    uint256 internal signerBPk;

    /// @dev A digest reused across owner-check tests.
    bytes32 internal constant DIGEST = keccak256("daimon.root.digest");

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        registry = new RootRegistryHarness();
        validatorA = new ECDSAValidator();
        validatorB = new ECDSAValidator();

        (signerA, signerAPk) = makeAddrAndKey("signerA");
        (signerB, signerBPk) = makeAddrAndKey("signerB");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy a fresh, never-installed {ECDSAValidator} (for dedup tests).
    /// @return The new scheme.
    function _newValidator() internal returns (ECDSAValidator) {
        return new ECDSAValidator();
    }

    /// @notice ABI-encode an ECDSAValidator credential (signer address) for `onInstall`.
    /// @param signer The authorized signer.
    /// @return The encoded init data.
    function _initData(address signer) internal pure returns (bytes memory) {
        return abi.encode(signer);
    }
}
