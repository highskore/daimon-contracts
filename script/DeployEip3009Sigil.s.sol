// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { Eip3009Sigil } from "@sigils/Eip3009Sigil/Eip3009Sigil.sol";

/// @title DeployEip3009Sigil
/// @notice Deploys ONLY {Eip3009Sigil} — the content-aware x402 voucher gate (signs EIP-3009
///         `transferWithAuthorization`s to allowlisted payees under a per-auth cap). Running `Deploy.s.sol`
///         would re-deploy the factory and thus change every counterfactual account address, so a sigil that
///         slots into existing deployments is deployed in isolation (mirrors {DeploySpendSigil}). Reads
///         `DEPLOYER_PRIVATE_KEY` from `contracts/.env`; copy the logged address into `deployments.ts` +
///         `base-sepolia.json` (replacing the `0x0…0` placeholder).
/// @dev Usage: `forge script script/DeployEip3009Sigil.s.sol:DeployEip3009Sigil --rpc-url <url> --broadcast`.
contract DeployEip3009Sigil is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        Eip3009Sigil eip3009Sigil = new Eip3009Sigil();
        vm.stopBroadcast();
        console2.log("Eip3009Sigil        %s", address(eip3009Sigil));
    }
}
