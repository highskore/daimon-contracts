// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IERC1608
/// @author highskore.eth
/// @notice ERC-1608 — signature-authorized, relayer-submittable execution for smart accounts. Any low-trust
///         relayer may submit a signed ERC-7579 execution and pay the gas; the account validates the
///         signature over the EIP-712 execution digest and enforces its own policy (including stateful spend
///         budgets) over every call. Signature-scheme-agnostic; no shared sequencer or relay infrastructure.
/// @dev The ERC-165 interface id (`type(IERC1608).interfaceId`) is the ERC-1608 feature id a
///      conforming account advertises via `supportsInterface`. The execution digest is EIP-712 over
///      `Execute(bytes32 mode,bytes32 executionDataHash,uint256 nonce,uint256 deadline)`. See ERC-1608.md.
interface IERC1608 {
    /// @notice Validate `sig` over the execution digest, then run the ERC-7579 single/batch atomically.
    /// @dev Permissionless to call — security is the signature + the account's policy, not the caller. The
    ///      single-use `nonce` is burned before execution (checks-effects-interactions); because a revert
    ///      rolls that write back, a failed execution leaves its nonce reusable (retryable). `to == address(0)`
    ///      in a call resolves to the account itself.
    /// @param mode The ERC-7579 execution mode (selects single vs batch decoding of `executionData`).
    /// @param executionData The ERC-7579-encoded call(s): single `to‖value‖data`, or batch `abi.encode(Call[])`.
    /// @param nonce A caller-chosen single-use nonce (order-independent replay guard).
    /// @param deadline The unix timestamp after which the signed execution expires (checked before the nonce
    ///        is burned, so an expired payload cannot burn its nonce).
    /// @param sig An account-defined authorization over the EIP-712 execution digest.
    /// @return results Each call's return data, in order.
    function executeWithSig(
        bytes32 mode,
        bytes calldata executionData,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    )
        external
        payable
        returns (bytes[] memory results);
}
