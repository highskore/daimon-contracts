// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Integration_Test } from "../../Base.integration.t.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";
import { DaimonFactory } from "@src/DaimonFactory.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { Initializable } from "solady/utils/Initializable.sol";

// Types
import { Mandate } from "@types/MandateTypes.sol";

/// @title Daimon disabled-initializers Integration Tests
/// @author highskore.eth
/// @notice The {Daimon} constructor calls `_disableInitializers()`, so the shared implementation can never be
///         initialized directly (the uninitialized-implementation hijack is closed). Accounts are ERC-1967
///         proxies deployed + initialized atomically by {DaimonFactory}; their delegatecall-scoped init is
///         unaffected. These tests assert both halves: impl init reverts, proxy init succeeds.
contract Daimon_disableInitializers_Integration_Test is Integration_Test {
    /// @dev The canonical deploy salt.
    bytes32 internal constant SALT = bytes32(uint256(1));

    DaimonFactory internal factory;
    Daimon internal impl;
    ECDSAValidator internal root;

    address internal rootSigner;

    function setUp() public {
        impl = new Daimon();
        factory = new DaimonFactory(address(impl));
        root = new ECDSAValidator();
        (rootSigner,) = makeAddrAndKey("root");
    }

    /// @notice The implementation's ROOT-set `initialize` reverts (initializers disabled in the constructor),
    ///         so the deployed logic contract can never be hijacked into an initialized state.
    function test_disableInitializers_implInitialize_reverts() external {
        (address[] memory vs, bytes[] memory ds) = _root();
        Mandate[] memory ms = new Mandate[](0);

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(vs, ds, ms);
    }

    /// @notice A factory-deployed proxy initializes fine via delegatecall — disabling initializers on the
    ///         implementation does not affect proxy initialization.
    function test_disableInitializers_proxyInitialize_succeeds() external {
        (address[] memory vs, bytes[] memory ds) = _root();
        Mandate[] memory ms = new Mandate[](0);

        address account = factory.createAccount(SALT, vs, ds, ms);

        assertGt(account.code.length, 0, "proxy account deployed");
        assertTrue(
            Daimon(payable(account)).isRootInstalled(address(root)),
            "proxy initialized: ROOT validator installed"
        );
    }

    /// @notice The same proxy cannot be re-initialized — the `initializer` modifier is one-shot per proxy.
    function test_disableInitializers_proxyReinitialize_reverts() external {
        (address[] memory vs, bytes[] memory ds) = _root();
        Mandate[] memory ms = new Mandate[](0);

        address account = factory.createAccount(SALT, vs, ds, ms);

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        Daimon(payable(account)).initialize(vs, ds, ms);
    }

    /// @dev A single-scheme ROOT set bound to `rootSigner`.
    function _root() internal view returns (address[] memory vs, bytes[] memory ds) {
        vs = new address[](1);
        vs[0] = address(root);
        ds = new bytes[](1);
        ds[0] = abi.encode(rootSigner);
    }
}
