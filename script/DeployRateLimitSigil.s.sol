// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { RateLimitSigil } from "@sigils/RateLimitSigil/RateLimitSigil.sol";

/// @title DeployRateLimitSigil
/// @notice Deploys ONLY the new {RateLimitSigil} — not the full system. Running `Deploy.s.sol` would re-deploy
///         the factory and thus change every counterfactual account address, so a new sigil that slots into
///         existing deployments is deployed in isolation. Reads `DEPLOYER_PRIVATE_KEY` from `contracts/.env`;
///         copy the logged address into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `forge script script/DeployRateLimitSigil.s.sol:DeployRateLimitSigil --rpc-url <url> --broadcast`.
contract DeployRateLimitSigil is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        RateLimitSigil rateLimitSigil = new RateLimitSigil();
        vm.stopBroadcast();
        console2.log("RateLimitSigil     %s", address(rateLimitSigil));
    }
}
