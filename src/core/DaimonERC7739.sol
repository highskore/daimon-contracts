// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC1271 } from "solady/accounts/ERC1271.sol";

/// @title DaimonERC7739
/// @author highskore.eth
/// @notice Surfaces the ERC-7739 **content** of a TypedDataSign 1271 signature to the account's validation.
///         solady's `ERC1271` only ever hands its `_erc1271IsValidSignatureNowCalldata` hook the final, nested
///         `hash` — the app domain and the signed struct are discarded after solady verifies them. That is fine
///         for an opaque-hash gate, but it means a MANDATE signature sigil can only pin an exact `hash`, never
///         reason about the *signed typed-data* (which dApp domain, which struct). This mixin forks solady's
///         `_erc1271IsValidSignatureViaNestedEIP712` so that, on the TypedDataSign path, it ALSO threads the
///         (solady-verified) `appDomainSeparator` and the `contentsHash` (the bytes32 struct hash of the signed
///         content) to a new {_erc1271IsValidSignatureNowCalldataWithContents} hook. The account can then gate on
///         the signed domain + content — e.g. an x402 voucher that authorizes ANY EIP-3009 transfer to an
///         allowlisted payee under a cap, not just one pre-pinned digest.
/// @dev The PersonalSign path is preserved BYTE-FOR-BYTE from solady and routes to the existing 2-arg
///      {_erc1271IsValidSignatureNowCalldata}, so opaque-hash 1271 (ROOT signing, exact-hash vouchers) is
///      unchanged. The TypedDataSign reconstruction + the PersonalSign-vs-TypedDataSign selection is solady's
///      (`solady 0.1.26` `accounts/ERC1271.sol`), verbatim; DAIMON adds exactly two things, both flagged
///      `DAIMON:` below — (1) capturing `appDomainSeparator` + `contentsHash` from the appended data that solady
///      uses to verify `hash`, and (2) routing the TypedDataSign branch to the with-contents hook.
abstract contract DaimonERC7739 is ERC1271 {
    /// @dev The with-contents counterpart of {ERC1271._erc1271IsValidSignatureNowCalldata}: same `(hash,
    ///      signature)` contract, but ALSO carries the solady-VERIFIED `appDomainSeparator` and `contentsHash`
    ///      from a TypedDataSign signature. `hash` is the final account-domain digest (already checked to be
    ///      consistent with `appDomainSeparator` + `contentsHash`), so a sigil may trust `contentsHash` as the
    ///      struct hash of the thing actually signed. Only called on the TypedDataSign path; the PersonalSign
    ///      path still flows through the 2-arg hook (with no content).
    /// @param hash The final nested digest the inner signature must cover (the value the session key signs).
    /// @param signature The inner signature, with the TypedDataSign trailer already stripped.
    /// @param appDomainSeparator The signed content's EIP-712 domain separator (verified against `hash`).
    /// @param contentsHash The bytes32 struct hash of the signed content (verified against `hash`).
    /// @return True iff the account authorizes this signature.
    function _erc1271IsValidSignatureNowCalldataWithContents(
        bytes32 hash,
        bytes calldata signature,
        bytes32 appDomainSeparator,
        bytes32 contentsHash
    )
        internal
        view
        virtual
        returns (bool);

    /// @dev Fork of `solady 0.1.26` `ERC1271._erc1271IsValidSignatureViaNestedEIP712`. Identical EIP-712
    ///      reconstruction + PersonalSign/TypedDataSign selection; the ONLY changes are the two `DAIMON:` lines
    ///      (capture + route). See the contract NatSpec for why.
    function _erc1271IsValidSignatureViaNestedEIP712(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        virtual
        override
        returns (bool result)
    {
        // DAIMON: captured on the TypedDataSign branch; left zero on the PersonalSign branch.
        bytes32 appDomainSeparator;
        bytes32 contentsHash;
        uint256 t = uint256(uint160(address(this)));
        // Forces the compiler to pop the variables after the scope, avoiding stack-too-deep.
        if (t != uint256(0)) {
            (
                ,
                string memory name,
                string memory version,
                uint256 chainId,
                address verifyingContract,
                bytes32 salt,
            ) = eip712Domain();
            assembly ("memory-safe") {
                t := mload(0x40) // Grab the free memory pointer.
                // Skip 2 words for the `typedDataSignTypehash` and `contents` struct hash.
                mstore(add(t, 0x40), keccak256(add(name, 0x20), mload(name)))
                mstore(add(t, 0x60), keccak256(add(version, 0x20), mload(version)))
                mstore(add(t, 0x80), chainId)
                mstore(add(t, 0xa0), shr(96, shl(96, verifyingContract)))
                mstore(add(t, 0xc0), salt)
                mstore(0x40, add(t, 0xe0)) // Allocate the memory.
            }
        }
        assembly ("memory-safe") {
            let m := mload(0x40) // Cache the free memory pointer.
            // `c` is `contentsDescription.length`, which is stored in the last 2 bytes of the signature.
            let c := shr(240, calldataload(add(signature.offset, sub(signature.length, 2))))
            for { } 1 { } {
                let l := add(0x42, c) // Total length of appended data (32 + 32 + c + 2).
                let o := add(signature.offset, sub(signature.length, l)) // Offset of appended data.
                mstore(0x00, 0x1901) // Store the "\x19\x01" prefix.
                calldatacopy(0x20, o, 0x40) // Copy the `APP_DOMAIN_SEPARATOR` and `contents` struct hash.
                // Use the `PersonalSign` workflow if the reconstructed hash doesn't match,
                // or if the appended data is invalid, i.e.
                // `appendedData.length > signature.length || contentsDescription.length == 0`.
                if or(xor(keccak256(0x1e, 0x42), hash), or(lt(signature.length, l), iszero(c))) {
                    t := 0 // Set `t` to 0, denoting that we need to `hash = _hashTypedData(hash)`.
                    mstore(t, _PERSONAL_SIGN_TYPEHASH)
                    mstore(0x20, hash) // Store the `prefixed`.
                    hash := keccak256(t, 0x40) // Compute the `PersonalSign` struct hash.
                    break
                }
                // DAIMON: the appended data (just verified against `hash` above) is
                // `APP_DOMAIN_SEPARATOR ‖ contents(struct hash) ‖ contentsType ‖ uint16(len)`. Capture the
                // first two words to thread to the with-contents hook.
                appDomainSeparator := calldataload(o)
                contentsHash := calldataload(add(o, 0x20))
                // Else, use the `TypedDataSign` workflow.
                // `TypedDataSign({ContentsName} contents,string name,...){ContentsType}`.
                mstore(m, "TypedDataSign(") // Store the start of `TypedDataSign`'s type encoding.
                let p := add(m, 0x0e) // Advance 14 bytes to skip "TypedDataSign(".
                calldatacopy(p, add(o, 0x40), c) // Copy `contentsName`, optimistically.
                mstore(add(p, c), 40) // Store a '(' after the end.
                if iszero(eq(byte(0, mload(sub(add(p, c), 1))), 41)) {
                    let e := 0 // Length of `contentsName` in explicit mode.
                    for { let q := sub(add(p, c), 1) } 1 { } {
                        e := add(e, 1) // Scan backwards until we encounter a ')'.
                        if iszero(gt(lt(e, c), eq(byte(0, mload(sub(q, e))), 41))) {
                            break
                        }
                    }
                    c := sub(c, e) // Truncate `contentsDescription` to `contentsType`.
                    calldatacopy(p, add(add(o, 0x40), c), e) // Copy `contentsName`.
                    mstore8(add(p, e), 40) // Store a '(' exactly right after the end.
                }
                // `d & 1 == 1` means that `contentsName` is invalid.
                let d := shr(byte(0, mload(p)), 0x7fffffe000000000000010000000000) // Starts with `[a-z(]`.
                // Advance `p` until we encounter '('.
                for { } iszero(eq(byte(0, mload(p)), 40)) { p := add(p, 1) } {
                    d := or(shr(byte(0, mload(p)), 0x120100000001), d) // Has a byte in ", )\x00".
                }
                mstore(p, " contents,string name,string") // Store the rest of the encoding.
                mstore(add(p, 0x1c), " version,uint256 chainId,address")
                mstore(add(p, 0x3c), " verifyingContract,bytes32 salt)")
                p := add(p, 0x5c)
                calldatacopy(p, add(o, 0x40), c) // Copy `contentsType`.
                // Fill in the missing fields of the `TypedDataSign`.
                calldatacopy(t, o, 0x40) // Copy the `contents` struct hash to `add(t, 0x20)`.
                mstore(t, keccak256(m, sub(add(p, c), m))) // Store `typedDataSignTypehash`.
                // The "\x19\x01" prefix is already at 0x00.
                // `APP_DOMAIN_SEPARATOR` is already at 0x20.
                mstore(0x40, keccak256(t, 0xe0)) // `hashStruct(typedDataSign)`.
                // Compute the final hash, corrupted if `contentsName` is invalid.
                hash := keccak256(0x1e, add(0x42, and(1, d)))
                signature.length := sub(signature.length, l) // Truncate the signature.
                break
            }
            mstore(0x40, m) // Restore the free memory pointer.
        }
        if (t == uint256(0)) {
            // PersonalSign workflow — identical to solady: route to the existing (content-less) modal hook.
            hash = _hashTypedData(hash);
            result = _erc1271IsValidSignatureNowCalldata(hash, signature);
        } else {
            // DAIMON: TypedDataSign — route with the solady-verified domain + content struct hash.
            result = _erc1271IsValidSignatureNowCalldataWithContents(
                hash, signature, appDomainSeparator, contentsHash
            );
        }
    }
}
