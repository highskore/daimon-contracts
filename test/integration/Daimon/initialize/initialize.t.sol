// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Daimon_Integration_Test } from "../Daimon.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { LibClone } from "solady/utils/LibClone.sol";

// Libraries
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { IDaimon } from "@interfaces/IDaimon.sol";

// Types
import { Mandate } from "@types/MandateTypes.sol";

// Mocks
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title Daimon.initialize Integration Tests
/// @author highskore.eth
/// @notice Unit-of-behavior tests for bootstrapping the ROOT set on a fresh account.
contract Daimon_initialize_Integration_Test is Daimon_Integration_Test {
    function setUp() public override {
        super.setUp();
        // Replace the already-initialized account with a fresh, uninitialized PROXY so initialize() is the
        // SUT (the implementation disables initializers; only a proxy can be initialized).
        daimon = Daimon(payable(LibClone.deployERC1967(address(new Daimon()))));
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A two-scheme root set installs both schemes and seeds each validator's signer.
    function test_initialize_installsBothRoots() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _rootArrays();

        // Act
        daimon.initialize(vs, ds, new Mandate[](0));

        // Assert
        assertTrue(daimon.isRootInstalled(address(root1)), "root1 installed");
        assertTrue(daimon.isRootInstalled(address(root2)), "root2 installed");
        assertEq(daimon.rootValidators().length, 2, "two roots active");
        assertEq(root1.signerOf(address(daimon)), rootSigner, "root1 signer seeded");
    }

    /// @notice A single-validator root set is now allowed (>= 1): the one scheme installs and its signer is
    ///         seeded. The >= 2 default is opt-in for recovery (an OR-set), not a hard requirement.
    function test_initialize_installsSingleRoot() external {
        // Arrange: a one-scheme root.
        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);

        // Act
        daimon.initialize(vs, ds, new Mandate[](0));

        // Assert
        assertTrue(daimon.isRootInstalled(address(root1)), "root1 installed");
        assertEq(daimon.rootValidators().length, 1, "one root active");
        assertEq(root1.signerOf(address(daimon)), rootSigner, "root1 signer seeded");
    }

    /// @notice An empty root set is still rejected — the account must have at least one ROOT scheme.
    function test_initialize_revertsWhen_rootSetEmpty() external {
        // Arrange: zero validators.
        address[] memory vs = new address[](0);
        bytes[] memory ds = new bytes[](0);

        // Act & Assert
        vm.expectRevert(IDaimon.RootSetTooSmall.selector);
        daimon.initialize(vs, ds, new Mandate[](0));
    }

    /// @notice A single-validator root can ROOT-authorize a direct-call execution end to end: the lone
    ///         ECDSA scheme signs an `executeWithSig` digest and any relayer submits it. Proves a
    ///         single-validator root is fully functional, not just installable.
    function test_initialize_singleRoot_rootAuthorizes() external {
        // Arrange: bootstrap a one-scheme (ECDSA) root.
        address[] memory vs = new address[](1);
        vs[0] = address(root1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);
        daimon.initialize(vs, ds, new Mandate[](0));

        // A trivial target the ROOT execution drives: mint tokens to the account.
        MockERC20 token = new MockERC20("Tok", "TOK");
        uint256 amount = 42e6;
        bytes memory inner =
            abi.encodeWithSelector(MockERC20.mint.selector, address(daimon), amount);
        bytes32 mode = bytes32(0); // ERC-7579 single-call mode
        bytes memory executionData = abi.encodePacked(address(token), uint256(0), inner);

        uint256 nonce = 1;
        bytes32 digest = _execDigest(mode, executionData, nonce);
        bytes memory sig = _rootSig(address(root1), rootPk, digest);

        // Act: any relayer submits the ROOT-signed execution.
        vm.prank(address(0xCAFE));
        daimon.executeWithSig(mode, executionData, nonce, type(uint256).max, sig);

        // Assert: the ROOT-authorized call ran.
        assertEq(
            token.balanceOf(address(daimon)), amount, "single root must authorize the execution"
        );
    }

    /// @notice Mismatched validators/initDatas lengths are rejected before any install.
    function test_initialize_revertsWhen_lengthMismatch() external {
        // Arrange: two validators, one initData.
        address[] memory vs = new address[](2);
        vs[0] = address(root1);
        vs[1] = address(root2);
        bytes[] memory ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);

        // Act & Assert
        vm.expectRevert(IDaimon.LengthMismatch.selector);
        daimon.initialize(vs, ds, new Mandate[](0));
    }

    /// @notice A second initialize on an already-bootstrapped account reverts (owner already set).
    function test_initialize_revertsWhen_alreadyInitialized() external {
        // Arrange
        (address[] memory vs, bytes[] memory ds) = _rootArrays();
        daimon.initialize(vs, ds, new Mandate[](0));

        // Act & Assert: solady's _initializeOwner(address(this)) cannot run twice.
        vm.expectRevert();
        daimon.initialize(vs, ds, new Mandate[](0));
    }

    /// @notice The single-owner initializer is intentionally disabled on Daimon.
    function test_initialize_singleOwner_revertsNotSupported() external {
        // Act & Assert
        vm.expectRevert(IDaimon.NotSupported.selector);
        daimon.initialize(rootSigner);
    }

    /// @notice initialize is once-only, so the no-signature genesis bind cannot be re-run to inject a
    ///         mandate after deploy: a second initialize (with or without a mandate) reverts. This is the
    ///         guard that keeps genesis binding reachable ONLY at deploy time, where the address commits to it.
    function test_initialize_cannotReinitializeToInjectMandate() external {
        // Arrange: bootstrap with no genesis mandate (the normal post-deploy state).
        (address[] memory vs, bytes[] memory ds) = _rootArrays();
        daimon.initialize(vs, ds, new Mandate[](0));

        // Act & Assert: a second initialize carrying a genesis mandate cannot run (owner already set), so a
        // no-signature mandate can never be injected post-deploy.
        Mandate[] memory ms = new Mandate[](1);
        ms[0] = _session();
        vm.expectRevert();
        daimon.initialize(vs, ds, ms);

        // The mandate the attacker tried to inject is not bound.
        assertFalse(
            daimon.isMandateBound(_mandateId(ms[0])), "post-deploy mandate must not be bound"
        );
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical two-scheme root arrays used to bootstrap the account.
    function _rootArrays() internal view returns (address[] memory vs, bytes[] memory ds) {
        vs = new address[](2);
        vs[0] = address(root1);
        vs[1] = address(root2);
        ds = new bytes[](2);
        ds[0] = abi.encode(rootSigner);
        ds[1] = abi.encode(root2Signer);
    }

    /// @dev The EIP-712 execution digest a ROOT scheme signs for an `executeWithSig` at `nonce`. Mirrors the
    ///      contract: `_hashTypedData(keccak256(abi.encode(EXEC_TYPEHASH, mode, keccak256(executionData),
    ///      nonce, deadline)))` under the account's domain. Uses `type(uint256).max` (no expiry).
    function _execDigest(
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
                HashLib.EXEC_TYPEHASH, mode, keccak256(executionData), nonce, type(uint256).max
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
