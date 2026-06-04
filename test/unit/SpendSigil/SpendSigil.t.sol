// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { SpendSigil, SpendConfig, Period } from "@sigils/SpendSigil/SpendSigil.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title SpendSigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for the SpendSigil unit suites: deploys the sigil and provides the config
///         install + calldata-shaping helpers each function suite reuses. Configures one (account, configId)
///         for a single budgeted token, cap, and allowlisted spender.
abstract contract SpendSigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    address internal constant TOKEN = address(0x7E57);
    address internal constant SPENDER = address(0x5);
    uint256 internal constant CAP = 100e6;
    ConfigId internal constant CID = ConfigId.wrap(bytes32(uint256(0xC0)));

    /// @dev ERC-20 `transfer(address,uint256)`.
    bytes4 internal constant TRANSFER_SELECTOR = 0xa9059cbb;
    /// @dev ERC-20 `transferFrom(address,address,uint256)`.
    bytes4 internal constant TRANSFER_FROM_SELECTOR = 0x23b872dd;
    /// @dev ERC-20 `approve(address,uint256)`.
    bytes4 internal constant APPROVE_SELECTOR = 0x095ea7b3;
    /// @dev OZ ERC-20 `increaseAllowance(address,uint256)`.
    bytes4 internal constant INCREASE_ALLOWANCE_SELECTOR = 0x39509351;
    /// @dev EIP-2612 `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` — a blanket grant, blocked.
    bytes4 internal constant PERMIT_SELECTOR = 0xd505accf;
    /// @dev ERC-721/1155 `setApprovalForAll(address,bool)` — a blanket grant, blocked.
    bytes4 internal constant SET_APPROVAL_FOR_ALL_SELECTOR = 0xa22cb465;
    /// @dev ERC-777 `authorizeOperator(address)` — a blanket grant, blocked.
    bytes4 internal constant AUTHORIZE_OPERATOR_SELECTOR = 0x959b8c3f;
    /// @dev Permit2 `approve(address,address,uint160,uint48)`; token at 0x04 — a grant the dangling-scan can't see.
    bytes4 internal constant PERMIT2_APPROVE_SELECTOR = 0x87517c45;

    /// @dev The canonical Permit2 contract address (a plausible target for a Permit2-approve call; the block
    ///      keys on selector + token arg, not the target, so the exact value only needs to be non-token).
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /// @dev ERC-7579 single-call mode (call type byte 0x00).
    bytes32 internal constant MODE_SINGLE = bytes32(0);
    /// @dev ERC-7579 batch mode (call type byte 0x01).
    bytes32 internal constant MODE_BATCH = bytes32(uint256(1) << 248);

    /// @dev One batch entry, matching solady `LibERC7579`'s `abi.encode(Call[])` batch layout.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    SpendSigil internal spendSigil;
    address internal account = address(this);

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        spendSigil = new SpendSigil();
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Configure the sigil for (CID, this, account) over `TOKEN` with the given period.
    /// @param period The rolling window the cap resets on.
    function _init(Period period) internal {
        _init(TOKEN, period);
    }

    /// @dev Configure the sigil for (CID, this, account) over `token` with the given period.
    /// @param token The budgeted ERC-20.
    /// @param period The rolling window the cap resets on.
    function _init(address token, Period period) internal {
        address[] memory spenders = new address[](1);
        spenders[0] = SPENDER;
        SpendConfig memory cfg =
            SpendConfig({ token: token, cap: CAP, period: period, spenders: spenders });
        spendSigil.initializeWithMultiplexer(account, CID, abi.encode(cfg));
    }

    /// @dev `transfer(to, amount)` content.
    /// @param to The transfer recipient.
    /// @param amount The transfer amount.
    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFER_SELECTOR, to, amount);
    }

    /// @dev `approve(spender, amount)` content.
    /// @param spender The approval spender.
    /// @param amount The approval amount.
    function _approve(address spender, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount);
    }

    /// @dev `transferFrom(from, to, amount)` content.
    function _transferFrom(
        address from,
        address to,
        uint256 amount
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(TRANSFER_FROM_SELECTOR, from, to, amount);
    }

    /// @dev A single-call ERC-7579 execution: `ed = abi.encodePacked(to, value, data)`.
    function _single(
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        pure
        returns (bytes32 mode, bytes memory ed)
    {
        mode = MODE_SINGLE;
        ed = abi.encodePacked(to, value, data);
    }

    /// @dev A one-entry batch ERC-7579 execution.
    function _batch1(
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        pure
        returns (bytes32 mode, bytes memory ed)
    {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({ to: to, value: value, data: data });
        return _batch(calls);
    }

    /// @dev A batch ERC-7579 execution: `ed = abi.encode(Call[])`.
    function _batch(Call[] memory calls) internal pure returns (bytes32 mode, bytes memory ed) {
        mode = MODE_BATCH;
        ed = abi.encode(calls);
    }
}
