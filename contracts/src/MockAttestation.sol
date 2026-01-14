// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IAttestation} from "./interfaces/IAttestation.sol";
import {TD10ReportBody} from "automata-dcap-attestation/types/TDXStruct.sol";

/// @title MockAttestation
/// @notice A mock attestation verifier that accepts any quote and parses it
/// @dev For testing purposes only - skips cryptographic verification
contract MockAttestation is IAttestation {
    // Quote structure constants (simplified)
    uint256 constant HEADER_LENGTH = 48;
    uint256 constant TD_REPORT10_LENGTH = 584;

    // Byte offsets within TD10ReportBody
    uint256 constant TEE_TCB_SVN_OFFSET = 0;
    uint256 constant MR_SEAM_OFFSET = 16;
    uint256 constant MRSIGNER_SEAM_OFFSET = 64;
    uint256 constant SEAM_ATTRIBUTES_OFFSET = 112;
    uint256 constant TD_ATTRIBUTES_OFFSET = 120;
    uint256 constant XFAM_OFFSET = 128;
    uint256 constant MR_TD_OFFSET = 136;
    uint256 constant MR_CONFIG_ID_OFFSET = 184;
    uint256 constant MR_OWNER_OFFSET = 232;
    uint256 constant MR_OWNER_CONFIG_OFFSET = 280;
    uint256 constant RTMR0_OFFSET = 328;
    uint256 constant RTMR1_OFFSET = 376;
    uint256 constant RTMR2_OFFSET = 424;
    uint256 constant RTMR3_OFFSET = 472;
    uint256 constant REPORT_DATA_OFFSET = 520;

    /// @notice Verify and parse a TDX quote (mock - always succeeds)
    /// @param rawQuote The raw quote bytes (header + TD10ReportBody + signature)
    /// @return success Always true for mock
    /// @return output ABI-encoded TD10ReportBody
    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        payable
        override
        returns (bool success, bytes memory output)
    {
        require(
            rawQuote.length >= HEADER_LENGTH + TD_REPORT10_LENGTH,
            "Quote too short"
        );

        // Skip header, parse TD10ReportBody
        bytes calldata reportBody = rawQuote[HEADER_LENGTH:HEADER_LENGTH +
            TD_REPORT10_LENGTH];

        TD10ReportBody memory parsed = _parseReportBody(reportBody);

        // Return success and ABI-encoded report body
        return (true, abi.encode(parsed));
    }

    /// @dev Parse raw bytes into TD10ReportBody struct
    function _parseReportBody(bytes calldata data)
        internal
        pure
        returns (TD10ReportBody memory)
    {
        TD10ReportBody memory body;

        body.teeTcbSvn = bytes16(data[TEE_TCB_SVN_OFFSET:TEE_TCB_SVN_OFFSET + 16]);
        body.mrSeam = data[MR_SEAM_OFFSET:MR_SEAM_OFFSET + 48];
        body.mrsignerSeam = data[MRSIGNER_SEAM_OFFSET:MRSIGNER_SEAM_OFFSET + 48];
        body.seamAttributes = bytes8(data[SEAM_ATTRIBUTES_OFFSET:SEAM_ATTRIBUTES_OFFSET + 8]);
        body.tdAttributes = bytes8(data[TD_ATTRIBUTES_OFFSET:TD_ATTRIBUTES_OFFSET + 8]);
        body.xFAM = bytes8(data[XFAM_OFFSET:XFAM_OFFSET + 8]);
        body.mrTd = data[MR_TD_OFFSET:MR_TD_OFFSET + 48];
        body.mrConfigId = data[MR_CONFIG_ID_OFFSET:MR_CONFIG_ID_OFFSET + 48];
        body.mrOwner = data[MR_OWNER_OFFSET:MR_OWNER_OFFSET + 48];
        body.mrOwnerConfig = data[MR_OWNER_CONFIG_OFFSET:MR_OWNER_CONFIG_OFFSET + 48];
        body.rtMr0 = data[RTMR0_OFFSET:RTMR0_OFFSET + 48];
        body.rtMr1 = data[RTMR1_OFFSET:RTMR1_OFFSET + 48];
        body.rtMr2 = data[RTMR2_OFFSET:RTMR2_OFFSET + 48];
        body.rtMr3 = data[RTMR3_OFFSET:RTMR3_OFFSET + 48];
        body.reportData = data[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64];

        return body;
    }
}
