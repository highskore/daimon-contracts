// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { DaimonFactory } from "@src/DaimonFactory.sol";

/// @title DeployDaimonFactory
/// @notice Deploys ONLY a new {DaimonFactory} pointing at a {Daimon} implementation. The factory's
///         `implementation` is immutable, so shipping a new impl ({DeployDaimon}) requires a matching factory
///         so new counterfactual accounts delegate to the new code. NOTE: a new factory changes every
///         counterfactual account address — intended when rolling a new impl. Reads `DEPLOYER_PRIVATE_KEY` and
///         the target impl from `DAIMON_IMPL` (set it to the address {DeployDaimon} just logged). Copy the
///         logged factory address into `deployments.ts` + `base-sepolia.json`.
/// @dev Usage: `DAIMON_IMPL=0x… forge script script/DeployDaimonFactory.s.sol:DeployDaimonFactory --rpc-url <url> --broadcast`.
contract DeployDaimonFactory is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address impl = vm.envAddress("DAIMON_IMPL");
        // The factory bakes `impl` into immutable storage and proxies every account to it — a wrong/zero/EOA
        // value would deploy fine but brick every new account. Require real code at it on the target chain.
        require(impl.code.length != 0, "DeployDaimonFactory: DAIMON_IMPL has no code on this chain");
        vm.startBroadcast(pk);
        DaimonFactory factory = new DaimonFactory(impl);
        vm.stopBroadcast();
        console2.log("Daimon (impl)       %s", impl);
        console2.log("DaimonFactory       %s", address(factory));
    }
}
