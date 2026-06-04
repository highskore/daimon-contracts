// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Integration_Test } from "../Base.integration.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { LibClone } from "solady/utils/LibClone.sol";
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

/// @title Daimon_Integration_Test
/// @author highskore.eth
/// @notice Per-contract base for Daimon integration suites: deploys the account with a two-scheme ROOT
///         set plus the session machinery, and provides the ROOT/MANDATE signature + digest builders the
///         direct-call (`executeWithSig`) flows reuse.
abstract contract Daimon_Integration_Test is Integration_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 internal constant SWAP_SELECTOR =
        bytes4(keccak256("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"));
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant MANDATE_BIND_TYPEHASH = keccak256(
        "DaimonMandateBind(bytes32 mandateId,uint48 validUntil,bytes32 actionsHash,bytes32 outcomeSigilsHash,bytes32 signatureSigilsHash,uint256 nonce)"
    );

    address internal constant ROUTER = address(0x9999);
    address internal constant TOKEN_IN = address(0x1111);
    address internal constant TOKEN_OUT = address(0x2222);
    address internal constant ATTACKER = address(0xBEEF);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    Daimon internal daimon;
    ECDSAValidator internal root1;
    ECDSAValidator internal root2;
    ECDSASessionValidator internal sessionValidator;
    OmniSigil internal omni;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal root2Signer;
    uint256 internal root2Pk;
    address internal agent;
    uint256 internal agentPk;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // Accounts run as ERC-1967 proxies (the impl disables initializers); deploy + init a proxy.
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
        root1 = new ECDSAValidator();
        root2 = new ECDSAValidator();
        sessionValidator = new ECDSASessionValidator();
        omni = new OmniSigil();
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (root2Signer, root2Pk) = makeAddrAndKey("root2");
        (agent, agentPk) = makeAddrAndKey("agent");

        address[] memory vs = new address[](2);
        vs[0] = address(root1);
        vs[1] = address(root2);
        bytes[] memory ds = new bytes[](2);
        ds[0] = abi.encode(rootSigner);
        ds[1] = abi.encode(root2Signer);
        daimon.initialize(vs, ds, new Mandate[](0));
    }

    /*//////////////////////////////////////////////////////////////
                            ROOT HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Build a ROOT-mode signature: `[0x00][20-byte validator][r,s,v]`.
    function _rootSig(
        address validator,
        uint256 pk,
        bytes32 hash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(bytes1(0x00), bytes20(validator), _sign(pk, hash));
    }

    /*//////////////////////////////////////////////////////////////
                           SESSION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice The canonical test mandate: a swap on ROUTER, recipient-locked to the account via OmniSigil.
    function _session() internal view returns (Mandate memory s) {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 96, // `to` in the swapExactTokensForTokens head
            isLimited: false,
            ref: bytes32(uint256(uint160(address(daimon)))),
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
            salt: bytes32(0),
            validUntil: 0,
            actions: actions,
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }

    /// @notice The MandateId of the MVP (swap) mandate.
    function _mandateId() internal view returns (MandateId) {
        return _mandateId(_session());
    }

    /// @notice The MandateId of an arbitrary mandate (reused by other capability suites).
    function _mandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }

    /// @notice The EIP-712 enable digest a ROOT scheme signs for the mandate at `nonce`.
    function _bindDigest(Mandate memory s, uint256 nonce) internal view returns (bytes32) {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = daimon.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                MANDATE_BIND_TYPEHASH,
                MandateId.unwrap(_mandateId(s)),
                s.validUntil,
                keccak256(abi.encode(s.actions)),
                keccak256(abi.encode(s.outcomeSigils)),
                keccak256(abi.encode(s.signatureSigils)),
                nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
