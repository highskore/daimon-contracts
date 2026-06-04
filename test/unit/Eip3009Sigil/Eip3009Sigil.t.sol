// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { Eip3009Sigil } from "@sigils/Eip3009Sigil/Eip3009Sigil.sol";
import { Eip3009Config } from "@sigils/Eip3009Sigil/lib/Eip3009ConfigLib.sol";

// Types
import { ConfigId } from "@interfaces/ISigil.sol";

/// @title Eip3009Sigil_Unit_Test
/// @author highskore.eth
/// @notice Per-contract base for the {Eip3009Sigil} unit suites: deploys the sigil and provides the config
///         install + engine-packed-content helpers each function suite reuses. {check1271} receives the
///         engine's packed `abi.encode(sender, hash, appDomainSeparator, contentsHash, inner)` blob, where
///         `inner = abi.encode(from, to, value, validAfter, validBefore, nonce)` is the EIP-3009 authorization
///         the relayer supplies. These tests call {check1271} DIRECTLY (this contract is the multiplexer +
///         account), bypassing solady's TypedDataSign wrapper, so each individual sigil branch — sender /
///         domain / soundness-anchor / payer / time-bound / payee / cap — can be exercised in isolation with a
///         well-formed (`contentsHash == keccak(fields)`) or deliberately-broken blob.
abstract contract Eip3009Sigil_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev The EIP-3009 `TransferWithAuthorization` struct typehash — the soundness anchor's typehash.
    bytes32 internal constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /// @dev solady {EnumerableSetLib}'s reserved zero-sentinel narrowed to an address (mirrors the sigil).
    address internal constant SENTINEL_PAYEE = address(uint160(0xfbb67fda52d4bfb8bf));

    ConfigId internal constant ID = ConfigId.wrap(bytes32(uint256(1)));
    address internal constant TOKEN = address(0x70C0);
    bytes32 internal constant DOMAIN = keccak256("mock-usdc-3009-domain");
    address internal constant PAYEE = address(0xBEEF);
    address internal constant EVIL_PAYEE = address(0xBADD);
    uint256 internal constant CAP = 10e6;

    /// @dev The signing account (the EIP-3009 `from`). These suites are the multiplexer + account, so this is
    ///      `address(this)`; set in {setUp}.
    address internal account;

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    Eip3009Sigil internal sigil;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        sigil = new Eip3009Sigil();
        account = address(this);
        // A non-zero baseline so the default `validAfter = 0` is strictly in the past and a default
        // `validBefore = max` is strictly in the future (the happy-path window).
        vm.warp(1_000_000);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Install a config on `ID` for `account` over `TOKEN`/`DOMAIN`/`CAP` allowing exactly `[PAYEE]`.
    function _init() internal {
        address[] memory payees = new address[](1);
        payees[0] = PAYEE;
        _init(payees);
    }

    /// @notice Install a config on `ID` for `account` allowing `payees` (an empty list is default-deny).
    /// @param payees The payee allowlist.
    function _init(address[] memory payees) internal {
        Eip3009Config memory cfg = Eip3009Config({
            token: TOKEN, tokenDomainSeparator: DOMAIN, allowedPayees: payees, cap: CAP
        });
        sigil.initializeWithMultiplexer(account, ID, abi.encode(cfg));
    }

    /// @notice The EIP-3009 inner authorization blob: `abi.encode(from, to, value, validAfter, validBefore,
    ///         nonce)`.
    function _inner(
        address from,
        address to,
        uint256 value,
        uint256 va,
        uint256 vb,
        bytes32 nonce
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(from, to, value, va, vb, nonce);
    }

    /// @notice The EIP-3009 struct hash (the soundness anchor: a well-formed `contentsHash`) over the fields.
    function _contents(
        address from,
        address to,
        uint256 value,
        uint256 va,
        uint256 vb,
        bytes32 nonce
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, va, vb, nonce)
        );
    }

    /// @notice The engine-packed `check1271` blob: `abi.encode(sender, hash, appDomainSeparator, contentsHash,
    ///         inner)`. `hash` is unused by the sigil (solady already verified it), so it is zero here.
    function _packed(
        address sender,
        bytes32 appDS,
        bytes32 contentsHash,
        bytes memory inner
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(sender, bytes32(0), appDS, contentsHash, inner);
    }

    /// @notice A fully well-formed (soundness-anchored) packed blob for a voucher to `to`/`value`/`nonce` over
    ///         the default open time window (`validAfter = 0`, `validBefore = max`), with `sender == TOKEN`,
    ///         `appDS == DOMAIN`, and `from == account`.
    function _packedVoucher(
        address to,
        uint256 value,
        bytes32 nonce
    )
        internal
        view
        returns (bytes memory)
    {
        return _packedVoucherTimed(to, value, 0, type(uint256).max, nonce);
    }

    /// @notice A well-formed packed blob with an explicit `validAfter`/`validBefore` window (for the time-bound
    ///         branches), `sender == TOKEN`, `appDS == DOMAIN`, `from == account`.
    function _packedVoucherTimed(
        address to,
        uint256 value,
        uint256 va,
        uint256 vb,
        bytes32 nonce
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory inner = _inner(account, to, value, va, vb, nonce);
        bytes32 contents = _contents(account, to, value, va, vb, nonce);
        return _packed(TOKEN, DOMAIN, contents, inner);
    }

    /// @notice Run the sigil's view check for `ID`/`account` against the packed `blob`.
    function _check1271(bytes memory blob) internal view returns (uint256) {
        return sigil.check1271(ID, account, blob);
    }
}
