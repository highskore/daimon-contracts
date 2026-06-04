// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { DaimonFactory } from "@src/DaimonFactory.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";
import {
    OmniSigil,
    ActionConfig,
    ParamRules,
    ParamRule,
    LimitUsage,
    ParamCondition
} from "@sigils/OmniSigil/OmniSigil.sol";

// Libraries
import { OmniSigilTreeLib } from "@sigils/OmniSigil/lib/OmniSigilTreeLib.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Types
import {
    Mandate,
    ActionData,
    ActionSigilData,
    OutcomeSigilData,
    SignatureSigilData,
    MandateId
} from "@types/MandateTypes.sol";

/// @title DaimonFactory_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for DaimonFactory unit suites: deploys the {Daimon} implementation, the CREATE2
///         factory pointing at it, and a pair of real {ECDSAValidator} schemes, and provides the canonical
///         root-set helper the function suites reuse. Exercises the real factory and the real account.
abstract contract DaimonFactory_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical deploy salt reused across suites.
    bytes32 internal constant SALT = bytes32(uint256(1));

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev A placeholder swap target the genesis mandate scopes (recipient-lock at offset 96).
    address internal constant ROUTER = address(0x9999);
    bytes4 internal constant SWAP_SELECTOR =
        bytes4(keccak256("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"));

    DaimonFactory internal factory;
    Daimon internal impl;

    ECDSAValidator internal v1;
    ECDSAValidator internal v2;

    address internal s1;
    address internal s2;

    /// @dev Session machinery for genesis-mandate suites (the session key + its validator + the sigil).
    ECDSASessionValidator internal sessionValidator;
    OmniSigil internal omni;
    address internal agent;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        impl = new Daimon();
        factory = new DaimonFactory(address(impl));
        v1 = new ECDSAValidator();
        v2 = new ECDSAValidator();
        s1 = makeAddr("s1");
        s2 = makeAddr("s2");
        sessionValidator = new ECDSASessionValidator();
        omni = new OmniSigil();
        agent = makeAddr("agent");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice The canonical two-scheme root arrays (validators + their encoded credentials).
    /// @return vs The validator addresses.
    /// @return ds The matching init-data blobs (each an ABI-encoded signer).
    function _roots() internal view returns (address[] memory vs, bytes[] memory ds) {
        vs = new address[](2);
        vs[0] = address(v1);
        vs[1] = address(v2);
        ds = new bytes[](2);
        ds[0] = abi.encode(s1);
        ds[1] = abi.encode(s2);
    }

    /// @notice The empty genesis-mandate set — the common "summon, no genesis bind" case.
    function _noMandates() internal pure returns (Mandate[] memory) {
        return new Mandate[](0);
    }

    /// @notice A recipient-locked swap mandate routing to `recipient`, salted by `salt` to disambiguate.
    ///         Mirrors the integration suite's MVP mandate so the genesis path is exercised on real shapes.
    function _mandate(address recipient, bytes32 salt) internal view returns (Mandate memory s) {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 96, // `to` in the swapExactTokensForTokens head
            isLimited: false,
            ref: bytes32(uint256(uint160(recipient))),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        uint256[] memory nodes = new uint256[](1);
        nodes[0] = OmniSigilTreeLib.createRuleNode(0);
        ActionConfig memory cfg = ActionConfig({
            valueLimitPerUse: type(uint256).max,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: nodes })
        });

        ActionSigilData[] memory sigils = new ActionSigilData[](1);
        sigils[0] = ActionSigilData({ sigil: address(omni), initData: abi.encode(cfg) });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ target: ROUTER, selector: SWAP_SELECTOR, sigils: sigils });

        s = Mandate({
            sessionValidator: ISessionValidator(address(sessionValidator)),
            sessionValidatorInitData: abi.encode(agent),
            salt: salt,
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @notice A one-element genesis-mandate array wrapping `s`.
    function _mandates(Mandate memory s) internal pure returns (Mandate[] memory ms) {
        ms = new Mandate[](1);
        ms[0] = s;
    }

    /// @notice The MandateId of `s` (mirrors {IdLib.toMandateId}).
    function _mandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }
}
