// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Minimal ERC-20 surface the sink needs.
interface IERC20Pull {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title MockPullSink
/// @notice A target whose `pull(token, amount)` selector the SpendSigil does NOT parse, yet which moves
///         the caller's tokens out via a pre-existing allowance. Used to prove the balance-delta `max(...)`
///         backstop charges an outflow the calldata parse would undercount (test-only).
contract MockPullSink {
    /// @notice Pull `amount` of `token` from the caller into this sink (requires a prior allowance).
    /// @param token The ERC-20 to pull.
    /// @param amount The amount to pull.
    function pull(address token, uint256 amount) external {
        IERC20Pull(token).transferFrom(msg.sender, address(this), amount);
    }
}
