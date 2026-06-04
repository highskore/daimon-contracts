// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

/// @title Integration_Test
/// @author highskore.eth
/// @notice Base for end-to-end suites that drive an account through the direct-call (ERC-1608)
///         `executeWithSig` path. Shared integration setup/helpers live in the per-contract bases.
abstract contract Integration_Test is Base_Test { }
