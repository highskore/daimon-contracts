// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { Daimon } from "@src/Daimon.sol";

/// @title DeployDaimon
/// @notice Deploys ONLY a new {Daimon} implementation — the shared UUPS impl every account proxy delegates to.
///         Use this to ship engine changes (the impl carries the {MandateEngine} logic + the inlined internal
///         libs) without redeploying sigils. A new impl needs a matching {DeployDaimonFactory} run (the
///         factory's impl address is immutable), so new accounts pick it up. Reads `DEPLOYER_PRIVATE_KEY` from
///         `contracts/.env`; copy the logged address into `deployments.ts` + `base-sepolia.json` AND pass it as
///         `DAIMON_IMPL` to {DeployDaimonFactory}.
/// @dev Usage: `forge script script/DeployDaimon.s.sol:DeployDaimon --rpc-url <url> --broadcast`.
contract DeployDaimon is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        Daimon impl = new Daimon();
        vm.stopBroadcast();
        console2.log("Daimon (impl)       %s", address(impl));
    }
}
