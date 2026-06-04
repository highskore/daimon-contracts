// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { AttestationSigil } from "@sigils/AttestationSigil/AttestationSigil.sol";

/// @title DeployAttestationSigil
/// @notice Deploys ONLY {AttestationSigil} — not the full system. Running `Deploy.s.sol` would re-deploy the factory
///         and thus change every counterfactual account address, so a sigil that slots into existing deployments
///         is deployed in isolation. Reads `DEPLOYER_PRIVATE_KEY` from `contracts/.env`; copy the logged
///         address into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `forge script script/DeployAttestationSigil.s.sol:DeployAttestationSigil --rpc-url <url> --broadcast`.
contract DeployAttestationSigil is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        AttestationSigil sigil = new AttestationSigil();
        vm.stopBroadcast();
        console2.log("AttestationSigil", address(sigil));
    }
}
