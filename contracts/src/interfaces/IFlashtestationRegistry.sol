// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TD10ReportBody} from "automata-dcap-attestation/types/TDXStruct.sol";

/// @notice Interface for the Flashtestation Registry
interface IFlashtestationRegistry {
    /// @notice Stored data for a registered TEE
    struct RegisteredTEE {
        bool isValid;
        bytes rawQuote;
        TD10ReportBody parsedReportBody;
        bytes extendedRegistrationData;
        bytes32 quoteHash;
    }

    /// @notice Emitted when a TEE service is registered
    event TEEServiceRegistered(
        address indexed teeAddress,
        bytes32 indexed workloadId,
        bytes32 quoteHash
    );

    /// @notice Emitted when a TEE attestation is invalidated
    event TEEServiceInvalidated(address indexed teeAddress, bytes32 quoteHash);

    /// @notice Register a TEE service with an attestation quote
    /// @param rawQuote The raw TDX attestation quote
    /// @param extendedRegistrationData Application-specific data bound to the attestation
    function registerTEEService(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData
    ) external payable;

    /// @notice Get the registration for a TEE address
    /// @param teeAddress The address to look up
    /// @return isValid Whether the registration is valid
    /// @return registration The full registration data
    function getRegistration(address teeAddress)
        external
        view
        returns (bool isValid, RegisteredTEE memory registration);

    /// @notice Get registration status (lighter weight query)
    /// @param teeAddress The address to look up
    /// @return isValid Whether the registration is valid
    /// @return quoteHash Hash of the stored quote
    function getRegistrationStatus(address teeAddress)
        external
        view
        returns (bool isValid, bytes32 quoteHash);

    /// @notice Invalidate an attestation (e.g., when endorsements change)
    /// @param teeAddress The TEE address to invalidate
    function invalidateAttestation(address teeAddress) external;
}
