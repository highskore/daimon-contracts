// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    I1271Sigil,
    ISigilBase,
    ConfigId,
    IERC165,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "@interfaces/ISigil.sol";

/// @title MockContentSigil
/// @author highskore.eth
/// @notice TEST-ONLY signature sigil that PROVES {DaimonERC7739} threads the ERC-7739 TypedDataSign content. Its
///         {check1271} decodes the engine payload `(sender, hash, appDomainSeparator, contentsHash, content)` and
///         returns success iff the threaded `(appDomainSeparator, contentsHash)` equal the configured expected
///         values — i.e. it asserts the account delivered the solady-VERIFIED domain + struct hash, not zeros.
/// @dev Signature-only ({I1271Sigil}): keys config by `(configId, msg.sender, account)` like a real sigil (the
///      engine is the multiplexer, so `msg.sender == account` at runtime).
contract MockContentSigil is I1271Sigil {
    struct Expected {
        bytes32 appDomainSeparator;
        bytes32 contentsHash;
        bool set;
    }

    /// @dev configId => multiplexer => account => expected ERC-7739 content.
    mapping(bytes32 => mapping(address => mapping(address => Expected))) internal _cfg;

    /// @inheritdoc ISigilBase
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        (bytes32 appDS, bytes32 cH) = abi.decode(initData, (bytes32, bytes32));
        _cfg[ConfigId.unwrap(configId)][msg.sender][account] = Expected(appDS, cH, true);
        emit SigilSet(configId, msg.sender, account);
    }

    /// @inheritdoc I1271Sigil
    function check1271(
        ConfigId id,
        address account,
        bytes calldata content
    )
        external
        view
        override
        returns (uint256)
    {
        Expected memory e = _cfg[ConfigId.unwrap(id)][msg.sender][account];
        if (!e.set) revert PolicyNotInitialized(id, msg.sender, account);
        (,, bytes32 appDomainSeparator, bytes32 contentsHash,) =
            abi.decode(content, (address, bytes32, bytes32, bytes32, bytes));
        if (appDomainSeparator != e.appDomainSeparator) return VALIDATION_FAILED;
        if (contentsHash != e.contentsHash) return VALIDATION_FAILED;
        return VALIDATION_SUCCESS;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(I1271Sigil).interfaceId
            || interfaceID == type(ISigilBase).interfaceId
            || interfaceID == type(IERC165).interfaceId;
    }
}
