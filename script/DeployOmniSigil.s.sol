// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { OmniSigil } from "@sigils/OmniSigil/OmniSigil.sol";

/// @title DeployOmniSigil
/// @notice Deploys ONLY {OmniSigil} — not the full system. Running `Deploy.s.sol` would re-deploy the factory
///         and thus change every counterfactual account address, so a sigil that slots into existing deployments
///         is deployed in isolation. Reads `DEPLOYER_PRIVATE_KEY` from `contracts/.env`; copy the logged
///         address into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `forge script script/DeployOmniSigil.s.sol:DeployOmniSigil --rpc-url <url> --broadcast`.
contract DeployOmniSigil is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        OmniSigil sigil = new OmniSigil();
        vm.stopBroadcast();
        console2.log("OmniSigil", address(sigil));
    }
}
