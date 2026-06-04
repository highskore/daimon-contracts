// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "solady/tokens/ERC20.sol";

/// @title MockERC20
/// @notice A freely-mintable ERC-20 for the demo/testnet (mock USDC / WETH). Test + demo only.
contract MockERC20 is ERC20 {
    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    /// @notice Mint `amount` to `to` — open, for demo funding only.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
