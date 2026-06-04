// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { MockUSDC3009 } from "@test/mock/MockUSDC3009.sol";

/// @title DeployMockUSDC3009
/// @notice Deploys ONLY {MockUSDC3009} — the GASLESS x402 demo token: a freely-mintable ERC-20 with EIP-3009
///         `transferWithAuthorization` and a 1271 payer branch, so a (contract) Daimon account can 1271-sign a
///         payment and a relayer settles it gaslessly (real USDC's EIP-3009 path is `ecrecover`-only and cannot
///         verify a smart-account payer). Deployed in isolation so it slots into the existing system without
///         touching the factory. Reads `DEPLOYER_PRIVATE_KEY` from `contracts/.env`; copy the logged address
///         into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `forge script script/DeployMockUSDC3009.s.sol:DeployMockUSDC3009 --rpc-url <url> --broadcast`.
contract DeployMockUSDC3009 is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        MockUSDC3009 token = new MockUSDC3009("Mock USDC 3009", "mUSDC3009");
        vm.stopBroadcast();
        console2.log("MockUSDC3009        %s", address(token));
    }
}
