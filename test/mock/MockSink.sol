// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MockSink
/// @notice A trivial call target that accepts ANY call (any selector, any value) and succeeds. Used by the
///         nonce-replay invariants as a benign execution destination, so a relayer submission's success or
///         failure turns ONLY on the nonce / authorization logic under test, never on the call itself.
contract MockSink {
    fallback() external payable { }
    receive() external payable { }
}
