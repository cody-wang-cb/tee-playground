// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IAttestation} from "./interfaces/IAttestation.sol";
import {IFlashtestationRegistry} from "./interfaces/IFlashtestationRegistry.sol";
import {TD10ReportBody} from "automata-dcap-attestation/types/TDXStruct.sol";

/// @title FlashtestationRegistry
/// @notice Registry for TEE attestations with DCAP verification
/// @dev Simplified non-upgradeable version for MVP
contract FlashtestationRegistry is IFlashtestationRegistry, Ownable {
    // Constants for ReportData parsing
    uint256 constant TD_REPORTDATA_LENGTH = 52; // 20 (address) + 32 (hash)
    uint256 constant MAX_QUOTE_SIZE = 20 * 1024; // 20KB DoS protection

    // Attestation verifier contract
    IAttestation public attestationContract;

    // TEE address => registration data
    mapping(address => RegisteredTEE) private registeredTEEs;

    error QuoteTooLarge();
    error VerificationFailed();
    error InvalidReportData();
    error ExtendedDataHashMismatch();
    error NotRegistered();

    constructor(address _attestationContract) Ownable(msg.sender) {
        attestationContract = IAttestation(_attestationContract);
    }

    /// @inheritdoc IFlashtestationRegistry
    function registerTEEService(
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData
    ) external payable override {
        _doRegister(msg.sender, rawQuote, extendedRegistrationData);
    }

    /// @dev Internal registration logic
    function _doRegister(
        address signer,
        bytes calldata rawQuote,
        bytes calldata extendedRegistrationData
    ) internal {
        // DoS protection
        if (rawQuote.length > MAX_QUOTE_SIZE) {
            revert QuoteTooLarge();
        }

        // Verify the quote with the attestation contract
        (bool success, bytes memory output) = attestationContract
            .verifyAndAttestOnChain{value: msg.value}(rawQuote);

        if (!success) {
            revert VerificationFailed();
        }

        // Decode the parsed report body
        TD10ReportBody memory reportBody = abi.decode(output, (TD10ReportBody));

        // Extract TEE address from ReportData[0:20]
        bytes memory reportData = reportBody.reportData;
        if (reportData.length < TD_REPORTDATA_LENGTH) {
            revert InvalidReportData();
        }

        // Extract TEE address (first 20 bytes)
        address teeAddress;
        assembly {
            teeAddress := shr(96, mload(add(reportData, 32)))
        }

        // Extract extended data hash (bytes 20-52)
        bytes32 extDataHash;
        assembly {
            extDataHash := mload(add(reportData, 52)) // 32 (length prefix) + 20 (address)
        }

        // Verify extended data hash matches
        bytes32 computedHash = keccak256(extendedRegistrationData);
        if (extDataHash != computedHash) {
            revert ExtendedDataHashMismatch();
        }

        // Compute quote hash
        bytes32 quoteHash = keccak256(rawQuote);

        // Compute workload ID for event
        bytes32 workloadId = _computeWorkloadId(reportBody);

        // Store registration
        registeredTEEs[teeAddress] = RegisteredTEE({
            isValid: true,
            rawQuote: rawQuote,
            parsedReportBody: reportBody,
            extendedRegistrationData: extendedRegistrationData,
            quoteHash: quoteHash
        });

        emit TEEServiceRegistered(teeAddress, workloadId, quoteHash);
    }

    /// @inheritdoc IFlashtestationRegistry
    function getRegistration(address teeAddress)
        external
        view
        override
        returns (bool isValid, RegisteredTEE memory registration)
    {
        registration = registeredTEEs[teeAddress];
        return (registration.isValid, registration);
    }

    /// @inheritdoc IFlashtestationRegistry
    function getRegistrationStatus(address teeAddress)
        external
        view
        override
        returns (bool isValid, bytes32 quoteHash)
    {
        RegisteredTEE storage reg = registeredTEEs[teeAddress];
        return (reg.isValid, reg.quoteHash);
    }

    /// @inheritdoc IFlashtestationRegistry
    function invalidateAttestation(address teeAddress) external override onlyOwner {
        RegisteredTEE storage reg = registeredTEEs[teeAddress];
        if (!reg.isValid) {
            revert NotRegistered();
        }

        reg.isValid = false;
        emit TEEServiceInvalidated(teeAddress, reg.quoteHash);
    }

    /// @dev Compute workload ID from report body (matches BlockBuilderPolicy)
    function _computeWorkloadId(TD10ReportBody memory reportBody)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            bytes.concat(
                reportBody.mrTd,
                reportBody.rtMr0,
                reportBody.rtMr1,
                reportBody.rtMr2,
                reportBody.rtMr3,
                reportBody.mrConfigId,
                reportBody.xFAM,
                reportBody.tdAttributes
            )
        );
    }
}
