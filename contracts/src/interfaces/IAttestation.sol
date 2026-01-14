// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @notice Interface for attestation verification (Automata DCAP compatible)
interface IAttestation {
    /// @notice Verify a TDX quote and return parsed output
    /// @param rawQuote The raw TDX attestation quote
    /// @return success Whether verification succeeded
    /// @return output The parsed quote data (TD10ReportBody encoded)
    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        payable
        returns (bool success, bytes memory output);
}
