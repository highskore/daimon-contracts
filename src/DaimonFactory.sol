// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { LibClone } from "solady/utils/LibClone.sol";

// Contracts
import { Daimon } from "@src/Daimon.sol";

// Types
import { Mandate } from "@types/MandateTypes.sol";

/// @title DaimonFactory
/// @author highskore.eth
/// @notice CREATE2 factory for Daimon accounts. It deploys a minimal ERC-1967 proxy (pointing at the
///         shared {Daimon} implementation) at a deterministic address derived from the salt + the ROOT
///         set + the genesis mandates, then bootstraps it. Because the address is counterfactual (known
///         before deploy), a relayer can summon the account and run its first direct-call (ERC-1608)
///         execution in one transaction. Genesis mandates let "summon + bind" happen in a single tx.
/// @dev The CREATE2 salt commits to BOTH the ROOT set and the genesis mandates, so the address binds to
///      *who can own it* AND *what the agent may do at birth* — a different root set OR a different mandate
///      set yields a different account. This is the entire safety argument for binding genesis mandates with
///      NO ROOT signature: `createAccount` is permissionless, so without the commitment an attacker could
///      front-run the deploy with a malicious genesis mandate at the same address; with it, a different
///      mandate set ⇒ a different address ⇒ no hijack.
contract DaimonFactory {
    /// @notice The shared Daimon implementation every account proxies to.
    /// @dev Lowercase by design: a `public immutable` whose `implementation()` getter is part of the ABI
    ///      (consumed by Deploy.s.sol) — not a SCREAMING_CASE constant.
    // solhint-disable-next-line immutable-vars-naming
    address public immutable implementation;

    /// @param impl The Daimon implementation address.
    constructor(address impl) {
        implementation = impl;
    }

    /// @notice Deploy (or return) the account for `(salt, ROOT set, genesis mandates)`. Idempotent — safe
    ///         to call even if the account already exists, so a relayer may bundle it ahead of the first
    ///         execution. On a fresh deploy the genesis mandates are bound atomically (no separate bind tx);
    ///         the address commitment is what makes this no-signature genesis bind safe (see contract notice).
    /// @param salt A caller-chosen salt.
    /// @param validators The ROOT auth schemes to bootstrap (>= 1).
    /// @param initDatas Per-scheme credential data.
    /// @param mandates The genesis mandates to bind at deploy time (may be empty).
    /// @return account The account address (newly deployed or already existing).
    function createAccount(
        bytes32 salt,
        address[] calldata validators,
        bytes[] calldata initDatas,
        Mandate[] calldata mandates
    )
        external
        payable
        returns (address account)
    {
        bool alreadyDeployed;
        (alreadyDeployed, account) = LibClone.createDeterministicERC1967(
            msg.value, implementation, _salt(salt, validators, initDatas, mandates)
        );
        if (!alreadyDeployed) {
            Daimon(payable(account)).initialize(validators, initDatas, mandates);
        }
    }

    /// @notice The counterfactual address for `(salt, ROOT set, genesis mandates)`, whether or not it is
    ///         deployed yet.
    /// @param salt A caller-chosen salt.
    /// @param validators The ROOT auth schemes.
    /// @param initDatas Per-scheme credential data.
    /// @param mandates The genesis mandates.
    /// @return The deterministic account address.
    function getAddress(
        bytes32 salt,
        address[] calldata validators,
        bytes[] calldata initDatas,
        Mandate[] calldata mandates
    )
        external
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddressERC1967(
            implementation, _salt(salt, validators, initDatas, mandates), address(this)
        );
    }

    /// @dev Bind the ROOT set AND the genesis mandates into the CREATE2 salt so the counterfactual address
    ///      commits to both. The mandate commitment is the security crux for the no-signature genesis bind:
    ///      a different mandate set ⇒ a different salt ⇒ a different address (see contract notice).
    function _salt(
        bytes32 salt,
        address[] calldata validators,
        bytes[] calldata initDatas,
        Mandate[] calldata mandates
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(salt, validators, initDatas, mandates));
    }
}
