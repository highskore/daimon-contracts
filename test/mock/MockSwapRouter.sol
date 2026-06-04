// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { MockERC20 } from "./MockERC20.sol";

/// @title MockSwapRouter
/// @notice A minimal v2-style router for the demo/testnet. Its `swapExactTokensForTokens` matches the
///         Uniswap v2 signature so the recipient `to` sits at the fixed calldata offset 96 — exactly what
///         OmniSigil's recipient-lock pins. It pulls `amountIn` of the input token from the caller (via
///         `transferFrom`, so the caller's balance actually decreases) and then mints a 1:1 `amountIn` of
///         the output token to `to` (`amountOutMin` is honored as a slippage floor). There is no real
///         liquidity or price curve, but the input/output value movement is real, which is enough to
///         exercise the policy: a self-recipient swap
///         succeeds, an attacker-recipient swap is rejected at validation by the sigil and never reaches
///         here.
contract MockSwapRouter {
    event Swapped(
        address indexed caller, address tokenIn, address tokenOut, uint256 amountIn, address to
    );

    /// @notice Uniswap-v2-style swap. `to` is the recipient the mandate locks.
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 /* deadline */
    )
        external
        returns (uint256[] memory amounts)
    {
        MockERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        // Demo rate: 1:1, no liquidity or price curve — the point is that REAL output value moves to `to`
        // (enough to exercise the policy and show a non-dust balance), not a realistic price. `amountOutMin`
        // is still honored as a slippage floor: a swap that would mint less than the caller demanded reverts.
        uint256 amountOut = amountIn;
        require(amountOut >= amountOutMin, "MockSwapRouter: insufficient output amount");
        MockERC20(path[path.length - 1]).mint(to, amountOut);
        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = amountOut;
        emit Swapped(msg.sender, path[0], path[path.length - 1], amountIn, to);
    }
}
