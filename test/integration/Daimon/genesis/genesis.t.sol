// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Integration_Test } from "../../Base.integration.t.sol";

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
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";
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

// Mocks
import { MockSwapRouter } from "@test/mock/MockSwapRouter.sol";
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title Daimon genesis "summon + bind" Integration Tests
/// @author highskore.eth
/// @notice Proves the one-transaction summon-and-bind end to end: a single `DaimonFactory.createAccount`
///         carrying a genesis mandate deploys the account AND binds the mandate atomically (no separate bind
///         tx, no ROOT-signed enable on first use). The safety argument is the CREATE2 address commitment —
///         the address commits to the exact genesis mandate, so this no-signature bind cannot be hijacked
///         (see {DaimonFactory}). After the summon, a session-key `executeWithSig` USE under the genesis
///         mandate succeeds within bounds (allowlisted recipient) and is contained out of bounds (attacker
///         recipient), exactly as a post-deploy-bound mandate would.
contract Daimon_genesis_Integration_Test is Integration_Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes4 internal constant SWAP_SELECTOR =
        bytes4(keccak256("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"));

    /// @dev ERC-7579 execution mode: single call (first byte = call type 0).
    bytes32 internal constant MODE_SINGLE = bytes32(0);

    /// @dev The canonical deploy salt.
    bytes32 internal constant SALT = bytes32(uint256(1));

    /// @dev Any relayer; security is the signature + sigils + address commitment, not msg.sender.
    address internal constant RELAYER = address(0xCAFE);
    address internal constant ATTACKER = address(0xBEEF);

    /// @dev The mock router pulls `amountIn` of the input token from the account before minting the output.
    uint256 internal constant AMOUNT_IN = 100e6;
    uint256 internal constant AMOUNT_OUT_MIN = 1;

    /// @dev The recipient the genesis mandate locks to. A genesis mandate must be self-contained — it cannot
    ///      lock to the account itself (the account address commits to the mandate, which would contain the
    ///      account address: an unsolvable fixed point). So it pins a FIXED allowlisted recipient instead.
    address internal constant ALLOWED = address(0xA11C0);

    DaimonFactory internal factory;
    Daimon internal impl;
    ECDSAValidator internal root1;
    ECDSAValidator internal root2;
    ECDSASessionValidator internal sessionValidator;
    OmniSigil internal omni;
    MockSwapRouter internal swapRouter;
    MockERC20 internal tokenIn;
    MockERC20 internal tokenOut;

    address internal rootSigner;
    uint256 internal rootPk;
    address internal root2Signer;
    address internal agent;
    uint256 internal agentPk;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        impl = new Daimon();
        factory = new DaimonFactory(address(impl));
        root1 = new ECDSAValidator();
        root2 = new ECDSAValidator();
        sessionValidator = new ECDSASessionValidator();
        omni = new OmniSigil();
        swapRouter = new MockSwapRouter();
        tokenIn = new MockERC20("In", "IN");
        tokenOut = new MockERC20("Out", "OUT");
        (rootSigner, rootPk) = makeAddrAndKey("root");
        (root2Signer,) = makeAddrAndKey("root2");
        (agent, agentPk) = makeAddrAndKey("agent");
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice One createAccount carrying a genesis mandate deploys the account and binds the mandate — the
    ///         mandate is enabled the instant the account exists, with no separate bind tx.
    function test_genesis_summonBindsMandate() external {
        address account = _summon();

        assertGt(account.code.length, 0, "account deployed");
        assertTrue(
            Daimon(payable(account)).isMandateBound(_mandateId(_genesisMandate())),
            "genesis mandate bound at summon (one tx)"
        );
    }

    /// @notice After the genesis summon, the session key USE-executes an in-bounds swap directly (no BIND
    ///         payload, no ROOT signature on first use): the swap runs and the allowlisted recipient receives
    ///         output. This proves "summon + bind" needs no separate bind on first execute.
    function test_genesis_sessionUse_allowedRecipient_succeeds() external {
        address account = _summon();

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(ALLOWED);
        bytes memory sig = _useSig(
            _mandateId(_genesisMandate()), _execDigest(account, mode, executionData, nonce)
        );
        uint256 balBefore = tokenOut.balanceOf(ALLOWED);
        uint256 inBefore = tokenIn.balanceOf(account);

        // Act
        vm.prank(RELAYER);
        Daimon(payable(account)).executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        // Assert
        assertEq(
            tokenOut.balanceOf(ALLOWED) - balBefore,
            AMOUNT_IN,
            "the genesis-bound mandate's USE swap delivers output to the allowlisted recipient"
        );
        assertEq(
            inBefore - tokenIn.balanceOf(account),
            AMOUNT_IN,
            "the router must pull amountIn of the input token from the summoned account"
        );
    }

    /// @notice The genesis-bound mandate contains an out-of-bounds action: a USE swap routed to an attacker
    ///         is denied by the recipient-lock sigil and surfaces as UnauthorizedExecution — the genesis
    ///         path enforces the exact same bounds as a post-deploy bind.
    function test_genesis_sessionUse_attackerRecipient_contained() external {
        address account = _summon();

        uint256 nonce = 1;
        (bytes32 mode, bytes memory executionData) = _swapExec(ATTACKER);
        bytes memory sig = _useSig(
            _mandateId(_genesisMandate()), _execDigest(account, mode, executionData, nonce)
        );

        // Act & Assert
        vm.prank(RELAYER);
        vm.expectRevert(IDaimon.UnauthorizedExecution.selector);
        Daimon(payable(account)).executeWithSig(mode, executionData, nonce, type(uint256).max, sig);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical two-scheme root arrays.
    function _roots() internal view returns (address[] memory vs, bytes[] memory ds) {
        vs = new address[](2);
        vs[0] = address(root1);
        vs[1] = address(root2);
        ds = new bytes[](2);
        ds[0] = abi.encode(rootSigner);
        ds[1] = abi.encode(root2Signer);
    }

    /// @dev The genesis recipient-lock swap mandate over the LIVE router, recipient pinned to `ALLOWED`.
    ///      Self-contained (no account dependency), so it can be committed to the CREATE2 address.
    function _genesisMandate() internal view returns (Mandate memory s) {
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 96, // `to` in the swapExactTokensForTokens head
            isLimited: false,
            ref: bytes32(uint256(uint160(ALLOWED))),
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
        actions[0] =
            ActionData({ target: address(swapRouter), selector: SWAP_SELECTOR, sigils: sigils });

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

    /// @dev Summon the account in ONE createAccount carrying the genesis mandate; assert it lands at the
    ///      mandate-committed address.
    function _summon() internal returns (address account) {
        (address[] memory vs, bytes[] memory ds) = _roots();
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _genesisMandate();
        account = factory.getAddress(SALT, vs, ds, ms);
        vm.prank(RELAYER);
        address deployed = factory.createAccount(SALT, vs, ds, ms);
        assertEq(deployed, account, "summon lands at the mandate-committed address");

        // The router now pulls `amountIn` of the input token from the account on every swap, so fund the
        // freshly-summoned account and have it approve the router (the recipient-lock sigil still gates `to`).
        tokenIn.mint(account, 1_000_000e6);
        vm.prank(account);
        tokenIn.approve(address(swapRouter), type(uint256).max);
    }

    /// @dev A single-call execution (ERC-7579 single mode) routing the swap to `recipient`.
    function _swapExec(address recipient)
        internal
        view
        returns (bytes32 mode, bytes memory executionData)
    {
        address[] memory path = new address[](2);
        path[0] = address(tokenIn);
        path[1] = address(tokenOut);
        bytes memory swapData = abi.encodeWithSelector(
            SWAP_SELECTOR, AMOUNT_IN, AMOUNT_OUT_MIN, path, recipient, uint256(0)
        );
        mode = MODE_SINGLE;
        executionData = abi.encodePacked(address(swapRouter), uint256(0), swapData);
    }

    /// @dev The EIP-712 execution digest the session key signs, under `account`'s domain.
    function _execDigest(
        address account,
        bytes32 mode,
        bytes memory executionData,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = Daimon(payable(account)).eip712Domain();
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
                HashLib.EXEC_TYPEHASH, mode, keccak256(executionData), nonce, type(uint256).max
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @dev A SESSION USE-mode signature over `digest`: `[0x01][0x00][32-byte mandateId][session-key sig]`.
    function _useSig(MandateId pid, bytes32 digest) internal view returns (bytes memory) {
        bytes memory keySig = _sign(agentPk, digest);
        return abi.encodePacked(bytes1(0x01), bytes1(0x00), MandateId.unwrap(pid), keySig);
    }

    /// @dev The MandateId of `s` (mirrors {IdLib.toMandateId}).
    function _mandateId(Mandate memory s) internal pure returns (MandateId) {
        return MandateId.wrap(
            keccak256(abi.encode(s.sessionValidator, s.sessionValidatorInitData, s.salt))
        );
    }
}
