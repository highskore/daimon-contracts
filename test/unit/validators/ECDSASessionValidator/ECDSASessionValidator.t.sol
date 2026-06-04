// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";

/// @title ECDSASessionValidator_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for ECDSASessionValidator unit suites: deploys the stateless verifier and
///         seeds an agent (session-key) keypair. No install step — the credential travels in `data` on
///         every call.
abstract contract ECDSASessionValidator_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    ECDSASessionValidator internal validator;

    address internal agent;
    uint256 internal agentPk;
    address internal attacker;
    uint256 internal attackerPk;

    /// @dev A digest reused across signature tests.
    bytes32 internal constant DIGEST = keccak256("daimon.session.digest");

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        validator = new ECDSASessionValidator();
        (agent, agentPk) = makeAddrAndKey("agent");
        (attacker, attackerPk) = makeAddrAndKey("attacker");
    }
}
