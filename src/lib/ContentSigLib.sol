// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ContentSigLib
/// @author highskore.eth
/// @notice A pure, fail-closed, bounds-checked decoder for the ERC-1271 MANDATE payload tail
///         `abi.encode(bytes content, bytes keySig)`. The tail is attacker-controlled (it arrives inside a
///         dApp-supplied 1271 signature), so the decode must NEVER panic-revert on a malformed/truncated
///         encoding — it returns `ok == false` with empty slices instead.
/// @dev Returns calldata slices (zero-copy) so the caller pays no memory-copy cost. Every offset/length read
///      from the tail is validated against `tail.length` with overflow-safe arithmetic before it is used; on
///      any violation the function fails closed (`ok == false`, empty `content`/`keySig`). The accepted shape
///      is the canonical two-`bytes` ABI head: two 32-byte offsets, each pointing at a 32-byte length word
///      followed by that many bytes, all within `tail`.
library ContentSigLib {
    /// @notice Decode the 1271 payload tail `abi.encode(bytes content, bytes keySig)` into calldata slices.
    /// @dev Fail-closed: a malformed or truncated `tail` yields `(false, empty, empty)` rather than reverting.
    ///      Bounds are checked overflow-safely against `tail.length` for both the offset words and the
    ///      length-prefixed payloads before any slice is formed.
    /// @param tail The bytes after the 32-byte mandate id — expected to be `abi.encode(bytes, bytes)`.
    /// @return ok True iff `tail` is a well-formed two-`bytes` ABI encoding fully contained within its bounds.
    /// @return content The first decoded `bytes` (empty calldata slice when `ok` is false).
    /// @return keySig The second decoded `bytes` (empty calldata slice when `ok` is false).
    function tryDecodeContentSig(bytes calldata tail)
        internal
        pure
        returns (bool ok, bytes calldata content, bytes calldata keySig)
    {
        // The two-`bytes` head is two 32-byte offset words; each field is validated independently against the
        // tail's bounds. Accept only when the full head is present AND both fields are well-formed.
        (bool cValid, bytes calldata c) = _slice(tail, 0x00);
        (bool kValid, bytes calldata k) = _slice(tail, 0x20);
        if (tail.length >= 0x40 && cValid && kValid) {
            return (true, c, k);
        }
        // Fail-closed: empty slices for both return values (never leak a partially-validated slice).
        assembly {
            c.offset := 0
            c.length := 0
        }
        return (false, c, c);
    }

    /// @dev Validate a single length-prefixed `bytes` whose 32-byte offset word sits at `headPos` within
    ///      `tail`, returning a calldata slice over its payload. Every read is bounds-checked against
    ///      `tail.length` with overflow-safe arithmetic; on any violation `valid` is false and the slice is
    ///      empty. Caller must additionally require `tail.length >= 0x40` (the two-offset head).
    /// @param tail The ABI-encoded payload tail.
    /// @param headPos The byte position of this field's offset word within `tail` (0x00 or 0x20).
    /// @return valid True iff the offset + length-prefixed payload lie fully within `tail`.
    /// @return slice The calldata slice over the payload (empty when `valid` is false).
    function _slice(
        bytes calldata tail,
        uint256 headPos
    )
        private
        pure
        returns (bool valid, bytes calldata slice)
    {
        assembly {
            slice.offset := 0
            slice.length := 0
            valid := 0
            let len := tail.length
            // The offset word must itself be inside the head we already require (>= 0x40).
            if iszero(lt(len, add(headPos, 0x20))) {
                let off := calldataload(add(tail.offset, headPos))
                // off <= len AND off + 0x20 <= len (room for the length word); overflow-safe since off<=len.
                if iszero(gt(off, len)) {
                    if iszero(gt(add(off, 0x20), len)) {
                        let dlen := calldataload(add(tail.offset, off))
                        // dlen <= len (can't exceed the tail) AND off + 0x20 + dlen <= len; addends <= len.
                        if iszero(gt(dlen, len)) {
                            if iszero(gt(add(add(off, 0x20), dlen), len)) {
                                slice.offset := add(add(tail.offset, off), 0x20)
                                slice.length := dlen
                                valid := 1
                            }
                        }
                    }
                }
            }
        }
    }
}
