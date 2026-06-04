// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { IdLib } from "@lib/IdLib.sol";
import { ModeLib } from "@lib/ModeLib.sol";
import { HashLib } from "@lib/HashLib.sol";

// Interfaces
import { ConfigId } from "@interfaces/ISigil.sol";

// Types
import { Mandate, MandateId, ActionId, ChainBind } from "@types/MandateTypes.sol";

/// @title LibHarness
/// @author highskore.eth
/// @notice External wrappers exposing the internal pure libs (IdLib / ModeLib / HashLib) so each can
///         be unit-tested in isolation (and cross-checked against the off-chain SDK). Test-only.
contract LibHarness {
    function toMandateId(Mandate calldata m) external pure returns (MandateId) {
        return IdLib.toMandateId(m);
    }

    function toActionId(address target, bytes4 selector) external pure returns (ActionId) {
        return IdLib.toActionId(target, selector);
    }

    function toConfigId(MandateId pid, ActionId aid) external pure returns (ConfigId) {
        return IdLib.toConfigId(pid, aid);
    }

    function modeRoot() external pure returns (uint8) {
        return ModeLib.MODE_ROOT;
    }

    function modeMandate() external pure returns (uint8) {
        return ModeLib.MODE_MANDATE;
    }

    function mandateUse() external pure returns (uint8) {
        return ModeLib.MANDATE_USE;
    }

    function mandateBind() external pure returns (uint8) {
        return ModeLib.MANDATE_BIND;
    }

    function mandateBindMultichain() external pure returns (uint8) {
        return ModeLib.MANDATE_BIND_MULTICHAIN;
    }

    function multichainBindDigest(ChainBind[] calldata arr) external pure returns (bytes32) {
        return HashLib.multichainBindDigest(arr);
    }

    function multichainDomainSeparator() external pure returns (bytes32) {
        return HashLib.MULTICHAIN_DOMAIN_SEPARATOR;
    }

    function chainBindTypehash() external pure returns (bytes32) {
        return HashLib.CHAIN_BIND_TYPEHASH;
    }

    function multichainBindTypehash() external pure returns (bytes32) {
        return HashLib.MULTICHAIN_BIND_TYPEHASH;
    }

    function mandateBindTypehash() external pure returns (bytes32) {
        return HashLib.MANDATE_BIND_TYPEHASH;
    }

    function execTypehash() external pure returns (bytes32) {
        return HashLib.EXEC_TYPEHASH;
    }
}
