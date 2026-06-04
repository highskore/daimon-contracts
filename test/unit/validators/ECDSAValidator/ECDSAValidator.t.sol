// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";

/// @title ECDSAValidator_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for ECDSAValidator unit suites: deploys the singleton scheme and seeds a
///         signer keypair. The test contract itself plays the *account* — it is `msg.sender` on `onInstall`,
///         so the credential is keyed by `address(this)`.
abstract contract ECDSAValidator_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    ECDSAValidator internal validator;

    address internal signer;
    uint256 internal signerPk;
    address internal attacker;
    uint256 internal attackerPk;

    /// @dev A digest reused across signature tests.
    bytes32 internal constant DIGEST = keccak256("daimon.ecdsa.digest");

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        validator = new ECDSAValidator();
        (signer, signerPk) = makeAddrAndKey("signer");
        (attacker, attackerPk) = makeAddrAndKey("attacker");
    }
}
