// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "solady/tokens/ERC20.sol";

/// @dev Minimal ERC-1271 surface — just the bytes32-digest `isValidSignature` (the form solady accounts
///      expose and the form a 1271-capable EIP-3009 payer is verified against).
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// @title MockUSDC3009
/// @notice A freely-mintable ERC-20 with EIP-3009 `transferWithAuthorization` and a 1271 payer branch —
///         the GASLESS x402 demo token. Real USDC's EIP-3009 path is `ecrecover`-only (it cannot verify a
///         smart-account payer), which is exactly why a Daimon account needs a 1271-capable token to settle
///         an x402 payment gaslessly: the account 1271-signs the authorization and a relayer submits it.
///         Test + demo only — `mint` is open.
/// @dev EIP-712 + EIP-3009 are inlined (no library) to keep this a minimal, self-contained mock. The
///      signature branch follows the standard EIP-3009 + ERC-1271 pattern: if the payer `from` has code,
///      verify via {IERC1271.isValidSignature}; otherwise `ecrecover`. SCOPE: implements ONLY
///      `transferWithAuthorization` (the single primitive x402 settlement uses); the EIP-3009 extras
///      `receiveWithAuthorization` and `cancelAuthorization` are intentionally omitted as unneeded for the demo.
contract MockUSDC3009 is ERC20 {
    /*·:⛧:·──────── CONSTANTS ────────:⛧:·*/

    bytes4 internal constant _ERC1271_MAGIC = 0x1626ba7e;

    /// @notice keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)").
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /*·:⛧:·──────── STORAGE ────────:⛧:·*/

    string private _name;
    string private _symbol;

    /// @dev Per-payer authorization-nonce usage; an EIP-3009 nonce is single-use (replay protection).
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    /*·:⛧:·──────── EVENTS / ERRORS ────────:⛧:·*/

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    error AuthorizationNotYetValid();
    error AuthorizationExpired();
    error AuthorizationUsedAlready();
    error InvalidSignature();

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /*·:⛧:·──────── ERC20 METADATA ────────:⛧:·*/

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    /// @notice 6 decimals, matching real USDC (solady's ERC20 defaults to 18) — so demo amounts are USDC-true.
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /// @notice Mint `amount` to `to` — open, for demo funding only.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /*·:⛧:·──────── EIP-3009 ────────:⛧:·*/

    /// @notice Whether `(authorizer, nonce)` has already been used (replay marker).
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    /// @notice Settle a gasless transfer authorized off-chain by `from` (EIP-3009). The relayer (any caller)
    ///         submits it; the payer pays no gas. The payer's signature is verified via ERC-1271 when `from`
    ///         is a contract (the Daimon-account case), else `ecrecover`.
    /// @param from The payer (debited).
    /// @param to The payee (credited).
    /// @param value The amount.
    /// @param validAfter The authorization is invalid at/before this timestamp.
    /// @param validBefore The authorization is invalid at/after this timestamp.
    /// @param nonce The single-use authorization nonce (replay protection).
    /// @param signature The payer's signature over the EIP-3009 digest (ERC-1271 or ECDSA).
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    )
        external
    {
        if (block.timestamp <= validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp >= validBefore) revert AuthorizationExpired();
        if (_authorizationStates[from][nonce]) revert AuthorizationUsedAlready();
        _authorizationStates[from][nonce] = true;

        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), structHash));

        if (from.code.length > 0) {
            // Smart-account payer (e.g. a Daimon account): verify via ERC-1271. This is the branch that
            // makes a GASLESS x402 payment possible for a contract account — the value real USDC cannot serve.
            // A rejecting signer may REVERT (e.g. solady ERC-7739 probing) rather than return a non-magic
            // value, so catch both into a single clean {InvalidSignature} instead of bubbling an opaque revert.
            try IERC1271(from).isValidSignature(digest, signature) returns (bytes4 magic) {
                if (magic != _ERC1271_MAGIC) revert InvalidSignature();
            } catch {
                revert InvalidSignature();
            }
        } else {
            // EOA payer: standard ECDSA recovery (real-USDC-equivalent path). `ecrecover` (and a malformed
            // signature) returns `address(0)`, so reject that explicitly — never let a zero recovery match a
            // zero `from`.
            address recovered = _recover(digest, signature);
            if (recovered == address(0) || recovered != from) revert InvalidSignature();
        }

        _transfer(from, to, value);
        emit AuthorizationUsed(from, nonce);
    }

    /*·:⛧:·──────── INTERNAL ────────:⛧:·*/

    /// @dev Minimal 65-byte `[r][s][v]` ECDSA recovery; returns address(0) on a malformed length.
    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        return ecrecover(digest, v, r, s);
    }
}
