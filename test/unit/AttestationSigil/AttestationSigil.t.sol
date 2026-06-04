// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { AttestationSigil, AttestationConfig } from "@sigils/AttestationSigil/AttestationSigil.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title AttestationSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for AttestationSigil unit suites: deploys the sigil and provides the config +
///         engine-packed-content helpers each function suite reuses. The sigil receives the engine's packed
///         `abi.encode(sender, hash, content)` as its `content` argument, so these helpers build that shape.
abstract contract AttestationSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant ACCOUNT = address(0xA11CE);
    address internal constant DAPP = address(0xDA77);
    address internal constant ATTACKER = address(0xBEEF);

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    AttestationSigil internal policy;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        policy = new AttestationSigil();
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Install a config gating `senders` and `hashes` on `ID` for `ACCOUNT`.
    /// @param senders The requesting-dApp allowlist (use `AttestationSigil.ANY_SENDER` for wildcard).
    /// @param hashes The allowed-digest allowlist (empty => any hash allowed). These are the EXACT `hash`
    ///        values the dApp passes to `isValidSignature`, NOT hashes of a content blob.
    function _init(address[] memory senders, bytes32[] memory hashes) internal {
        AttestationConfig memory cfg =
            AttestationConfig({ allowedSenders: senders, allowedHashes: hashes });
        policy.initializeWithMultiplexer(ACCOUNT, ID, abi.encode(cfg));
    }

    /// @notice Install a config allowing exactly one sender and ANY hash.
    function _initSender(address sender) internal {
        address[] memory senders = new address[](1);
        senders[0] = sender;
        _init(senders, new bytes32[](0));
    }

    /// @notice Install a config allowing exactly one sender and exactly one allowed digest (`hash`).
    function _initSenderHash(address sender, bytes32 hash) internal {
        address[] memory senders = new address[](1);
        senders[0] = sender;
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hash;
        _init(senders, hashes);
    }

    /// @notice Pack the engine's `abi.encode(sender, hash, appDomainSeparator, contentsHash, content)` 1271
    ///         argument. These tests exercise the sender + hash gating, so the ERC-7739 content fields are zero
    ///         (the PersonalSign / opaque-hash path, which AttestationSigil ignores).
    /// @param sender The requesting dApp.
    /// @param hash The REAL (nested) digest — the value the gate now binds to.
    /// @param content The attested content blob (carried through, no longer gated on).
    function _packed(
        address sender,
        bytes32 hash,
        bytes memory content
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(sender, hash, bytes32(0), bytes32(0), content);
    }

    /// @notice Run the sigil's view check for `ID` against the engine-packed `(sender, hash, content)`.
    function _check1271(
        address sender,
        bytes32 hash,
        bytes memory content
    )
        internal
        view
        returns (uint256)
    {
        return policy.check1271(ID, ACCOUNT, _packed(sender, hash, content));
    }
}
