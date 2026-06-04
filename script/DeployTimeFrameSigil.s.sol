// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { TimeFrameSigil } from "@sigils/TimeFrameSigil/TimeFrameSigil.sol";

/// @title DeployTimeFrameSigil
/// @notice Deploys ONLY {TimeFrameSigil} — not the full system. Running `Deploy.s.sol` would re-deploy the factory
///         and thus change every counterfactual account address, so a sigil that slots into existing deployments
///         is deployed in isolation. Reads `DEPLOYER_PRIVATE_KEY` from `contracts/.env`; copy the logged
///         address into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `forge script script/DeployTimeFrameSigil.s.sol:DeployTimeFrameSigil --rpc-url <url> --broadcast`.
contract DeployTimeFrameSigil is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        TimeFrameSigil sigil = new TimeFrameSigil();
        vm.stopBroadcast();
        console2.log("TimeFrameSigil", address(sigil));
    }
}
