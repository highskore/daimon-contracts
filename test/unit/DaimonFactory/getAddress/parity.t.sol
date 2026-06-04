// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { DaimonFactory_Unit_Test } from "../DaimonFactory.t.sol";

// Libraries
import { LibClone } from "solady/utils/LibClone.sol";

// Interfaces
import { ISessionValidator } from "@interfaces/ISessionValidator.sol";

// Types
import { Mandate, ActionData, OutcomeSigilData, SignatureSigilData } from "@types/MandateTypes.sol";

/// @title DaimonFactory.getAddress SDK-parity Vector
/// @author highskore.eth
/// @notice Emits the deterministic `_salt` + predicted address for a FIXED sample, so the SDK's
///         {deriveSalt} / {predictDaimonAddress} can be asserted byte-for-byte against the on-chain
///         derivation (the cross-language hash must not drift — a mismatch silently yields a wrong address).
///         The SDK test pins the same sample (fixed factory/impl/validator/session addresses) and expects
///         equality. Run with `forge test --mt test_parity_emitVector -vv` to print the vector.
contract DaimonFactory_getAddress_Parity_Test is DaimonFactory_Unit_Test {
    /// @dev Fixed addresses so the vector is reproducible across the SDK and the contract.
    address internal constant FACTORY_FIXED = address(0x00000000000000000000000000000000000fAc70);
    address internal constant IMPL_FIXED = address(0x000000000000000000000000000000000000bEEF);
    address internal constant V1_FIXED = address(0x1111111111111111111111111111111111111111);
    address internal constant V2_FIXED = address(0x2222222222222222222222222222222222222222);
    address internal constant SESSION_FIXED = address(0x3333333333333333333333333333333333333333);
    address internal constant AGENT_FIXED = address(0x7777777777777777777777777777777777777777);

    /// @dev The fixed sample salt + the genesis-mandate salt.
    bytes32 internal constant SAMPLE_SALT = bytes32(uint256(0xABCD));
    bytes32 internal constant MANDATE_SALT = bytes32(uint256(0x1234));

    /// @notice Log the SDK-parity vector: salt + predicted address for the fixed sample.
    function test_parity_emitVector() external {
        bytes32 salt = keccak256(abi.encode(SAMPLE_SALT, _vs(), _ds(), _sampleMandates()));
        address predicted =
            LibClone.predictDeterministicAddressERC1967(IMPL_FIXED, salt, FACTORY_FIXED);

        emit log_named_bytes32("parity.salt", salt);
        emit log_named_address("parity.predicted", predicted);
    }

    /// @dev The fixed validators.
    function _vs() internal pure returns (address[] memory vs) {
        vs = new address[](2);
        vs[0] = V1_FIXED;
        vs[1] = V2_FIXED;
    }

    /// @dev The fixed init datas.
    function _ds() internal pure returns (bytes[] memory ds) {
        ds = new bytes[](2);
        ds[0] = abi.encode(V1_FIXED);
        ds[1] = abi.encode(V2_FIXED);
    }

    /// @dev A deterministic one-element genesis-mandate set with NO actions/outcomes/signature-sigils, so the
    ///      SDK vector is just (session, cred, salt, validUntil, [], [], []) — trivially reproducible across
    ///      languages.
    function _sampleMandates() internal pure returns (Mandate[] memory ms) {
        ms = new Mandate[](1);
        ms[0] = Mandate({
            sessionValidator: ISessionValidator(SESSION_FIXED),
            sessionValidatorInitData: abi.encode(AGENT_FIXED),
            salt: MANDATE_SALT,
            validUntil: 0,
            actions: new ActionData[](0),
            outcomeSigils: new OutcomeSigilData[](0),
            signatureSigils: new SignatureSigilData[](0)
        });
    }
}
