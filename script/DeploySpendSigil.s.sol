// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { SpendSigil } from "@sigils/SpendSigil/SpendSigil.sol";

/// @title DeploySpendSigil
/// @notice Deploys ONLY {SpendSigil} — not the full system. Running `Deploy.s.sol` would re-deploy the factory
///         and thus change every counterfactual account address, so a sigil that slots into existing deployments
///         is deployed in isolation. Use this to ship a new SpendSigil build (e.g. the NATIVE-budget support)
///         without disturbing the rest. Reads `DEPLOYER_PRIVATE_KEY` from `contracts/.env`; copy the logged
///         address into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `forge script script/DeploySpendSigil.s.sol:DeploySpendSigil --rpc-url <url> --broadcast`.
contract DeploySpendSigil is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        SpendSigil spendSigil = new SpendSigil();
        vm.stopBroadcast();
        console2.log("SpendSigil          %s", address(spendSigil));
    }
}
