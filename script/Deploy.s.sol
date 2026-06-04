// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { Daimon } from "@src/Daimon.sol";
import { DaimonFactory } from "@src/DaimonFactory.sol";
import { ECDSAValidator } from "@validators/ECDSAValidator.sol";
import { WebAuthnValidator } from "@validators/WebAuthnValidator.sol";
import { ECDSASessionValidator } from "@validators/ECDSASessionValidator.sol";
import { WebAuthnSessionValidator } from "@validators/WebAuthnSessionValidator.sol";
import { OmniSigil } from "@sigils/OmniSigil/OmniSigil.sol";
import { SpendSigil } from "@sigils/SpendSigil/SpendSigil.sol";
import { SudoSigil } from "@sigils/SudoSigil/SudoSigil.sol";
import { AttestationSigil } from "@sigils/AttestationSigil/AttestationSigil.sol";
import { TimeFrameSigil } from "@sigils/TimeFrameSigil/TimeFrameSigil.sol";
import { NativeValueLimitSigil } from "@sigils/NativeValueLimitSigil/NativeValueLimitSigil.sol";
import { MockSwapRouter } from "@test/mock/MockSwapRouter.sol";
import { MockERC20 } from "@test/mock/MockERC20.sol";

/// @title Deploy
/// @notice Idempotent canonical deploy of the Daimon system + demo mocks (Base Sepolia for the demo). Each
///         contract is deployed ONLY if its address env var is unset/zero — so a re-run deploys just the
///         missing/changed pieces and re-emits the full address set straight for `deployments.ts` /
///         `deployments/<name>.json`. To FORCE a redeploy of a contract whose code changed, leave its env var
///         unset; to PRESERVE an existing deployment, pass its address (a redeploy of {DaimonFactory} changes
///         every counterfactual account address, so preserve the rest when shipping one new piece).
///
///         Env: `DEPLOYER_PRIVATE_KEY` (required); optional per-contract addresses to REUSE —
///         `DAIMON`, `DAIMON_FACTORY`, `ECDSA_VALIDATOR`, `WEBAUTHN_VALIDATOR`, `ECDSA_SESSION_VALIDATOR`,
///         `WEBAUTHN_SESSION_VALIDATOR`,
///         `OMNI_SIGIL`, `SPEND_SIGIL`, `SUDO_SIGIL`, `ATTESTATION_SIGIL`, `TIMEFRAME_SIGIL`,
///         `NATIVE_VALUE_LIMIT_SIGIL`, `MOCK_SWAP_ROUTER`, `MUSDC`, `MWETH`. A reused address is REQUIRED to have code
///         on the target chain (a typo / wrong env value reverts rather than wiring a non-contract); and a
///         reused {DaimonFactory} must already point at the resolved {Daimon} impl (else the set is inconsistent).
///
///         For a single-contract roll (the usual path — e.g. a new sigil or a new impl) prefer the focused
///         `DeploySpendSigil` / `DeployDaimon` / `DeployDaimonFactory` scripts so nothing else is disturbed.
/// @dev Usage: `forge script script/Deploy.s.sol:Deploy --rpc-url <base-sepolia> --broadcast`. Daimon is
///      direct-call (ERC-1608) only — a relayer submits the signed execution and pays gas; no EntryPoint.
contract Deploy is Script {
    /// @dev The resolved address set — a single memory struct so `run()` stays within stack limits (15 separate
    ///      locals across the broadcast block overflow the stack under the optimizer without via-IR).
    struct Addrs {
        address daimon;
        address factory;
        address ecdsa;
        address webauthn;
        address session;
        address webauthnSession;
        address omni;
        address spend;
        address sudo;
        address attestation;
        address timeframe;
        address nativeValueLimit;
        address router;
        address usdc;
        address weth;
    }

    /// @dev The address to REUSE for `key`, or `address(0)` if unset (→ deploy a fresh one). A non-zero env
    ///      value MUST have code on the target chain, so a typo / wrong address reverts here instead of wiring a
    ///      non-contract into the deployment record.
    function _reuse(string memory key) internal view returns (address a) {
        // `envOr` returns `address(0)` ONLY when the var is unset (→ deploy fresh); a var that IS set but
        // malformed (typo / wrong length / non-hex) reverts here rather than being silently treated as unset.
        a = vm.envOr(key, address(0));
        if (a != address(0)) {
            require(a.code.length != 0, string.concat("Deploy: reused ", key, " has no code"));
        }
    }

    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");

        // Resolve reuse-or-deploy for each contract into a single memory struct. A non-zero (code-verified) env
        // address is kept; a zero one is deployed below, so the broadcast only touches what actually changes.
        Addrs memory a;
        a.daimon = _reuse("DAIMON");
        a.factory = _reuse("DAIMON_FACTORY");
        a.ecdsa = _reuse("ECDSA_VALIDATOR");
        a.webauthn = _reuse("WEBAUTHN_VALIDATOR");
        a.session = _reuse("ECDSA_SESSION_VALIDATOR");
        a.webauthnSession = _reuse("WEBAUTHN_SESSION_VALIDATOR");
        a.omni = _reuse("OMNI_SIGIL");
        a.spend = _reuse("SPEND_SIGIL");
        a.sudo = _reuse("SUDO_SIGIL");
        a.attestation = _reuse("ATTESTATION_SIGIL");
        a.timeframe = _reuse("TIMEFRAME_SIGIL");
        a.nativeValueLimit = _reuse("NATIVE_VALUE_LIMIT_SIGIL");
        a.router = _reuse("MOCK_SWAP_ROUTER");
        a.usdc = _reuse("MUSDC");
        a.weth = _reuse("MWETH");

        vm.startBroadcast(pk);
        if (a.daimon == address(0)) a.daimon = address(new Daimon());
        // The factory's implementation is immutable. A fresh factory commits to the resolved impl; a REUSED
        // factory must already point at it, or the set is internally inconsistent (new accounts would run code
        // the logged impl doesn't describe).
        if (a.factory == address(0)) {
            a.factory = address(new DaimonFactory(a.daimon));
        } else {
            require(
                DaimonFactory(a.factory).implementation() == a.daimon,
                "Deploy: reused DAIMON_FACTORY does not point at the resolved DAIMON impl"
            );
        }
        if (a.ecdsa == address(0)) a.ecdsa = address(new ECDSAValidator());
        if (a.webauthn == address(0)) a.webauthn = address(new WebAuthnValidator());
        if (a.session == address(0)) a.session = address(new ECDSASessionValidator());
        if (a.webauthnSession == address(0)) {
            a.webauthnSession = address(new WebAuthnSessionValidator());
        }
        if (a.omni == address(0)) a.omni = address(new OmniSigil());
        if (a.spend == address(0)) a.spend = address(new SpendSigil());
        if (a.sudo == address(0)) a.sudo = address(new SudoSigil());
        if (a.attestation == address(0)) a.attestation = address(new AttestationSigil());
        if (a.timeframe == address(0)) a.timeframe = address(new TimeFrameSigil());
        if (a.nativeValueLimit == address(0)) {
            a.nativeValueLimit = address(new NativeValueLimitSigil());
        }
        if (a.usdc == address(0)) a.usdc = address(new MockERC20("Mock USDC", "mUSDC"));
        if (a.weth == address(0)) a.weth = address(new MockERC20("Mock WETH", "mWETH"));
        if (a.router == address(0)) a.router = address(new MockSwapRouter());
        vm.stopBroadcast();

        _log(a);
    }

    /// @dev Emit the full final address set (for `deployments.ts` / `deployments/<name>.json`). Split out of
    ///      `run()` to keep its stack small.
    function _log(Addrs memory a) internal pure {
        console2.log("Daimon (impl)       %s", a.daimon);
        console2.log("DaimonFactory       %s", a.factory);
        console2.log("ECDSAValidator      %s", a.ecdsa);
        console2.log("WebAuthnValidator   %s", a.webauthn);
        console2.log("ECDSASessionValid.  %s", a.session);
        console2.log("WebAuthnSessionVal. %s", a.webauthnSession);
        console2.log("OmniSigil           %s", a.omni);
        console2.log("SpendSigil          %s", a.spend);
        console2.log("SudoSigil           %s", a.sudo);
        console2.log("AttestationSigil    %s", a.attestation);
        console2.log("TimeFrameSigil      %s", a.timeframe);
        console2.log("NativeValueLimitSigil     %s", a.nativeValueLimit);
        console2.log("MockSwapRouter      %s", a.router);
        console2.log("mUSDC               %s", a.usdc);
        console2.log("mWETH               %s", a.weth);
    }
}
