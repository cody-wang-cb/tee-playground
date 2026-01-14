// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IBlockBuilderPolicy, WorkloadId, WorkloadMetadata} from "./interfaces/IBlockBuilderPolicy.sol";
import {IFlashtestationRegistry} from "./interfaces/IFlashtestationRegistry.sol";

/// @title BlockBuilderPolicy
/// @notice Policy contract for managing approved TEE workloads
/// @dev Simplified non-upgradeable version for MVP
contract BlockBuilderPolicy is IBlockBuilderPolicy, Ownable {
    // Registry contract
    IFlashtestationRegistry public registry;

    // Approved workloads: workloadId => metadata
    mapping(bytes32 => WorkloadMetadata) private approvedWorkloads;

    error NotRegistered();
    error InvalidAttestation();
    error WorkloadNotApproved();
    error WorkloadAlreadyApproved();

    constructor(address _registry) Ownable(msg.sender) {
        registry = IFlashtestationRegistry(_registry);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function isAllowedPolicy(address teeAddress)
        public
        view
        override
        returns (bool allowed, WorkloadId workloadId)
    {
        // Get registration from registry
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) =
            registry.getRegistration(teeAddress);

        if (!isValid) {
            return (false, WorkloadId.wrap(bytes32(0)));
        }

        // Compute workload ID from registration
        workloadId = workloadIdForTDRegistration(registration);

        // Check if workload is approved
        if (bytes(approvedWorkloads[WorkloadId.unwrap(workloadId)].commitHash).length > 0) {
            return (true, workloadId);
        }

        return (false, WorkloadId.wrap(bytes32(0)));
    }

    /// @inheritdoc IBlockBuilderPolicy
    function workloadIdForTDRegistration(
        IFlashtestationRegistry.RegisteredTEE memory registration
    ) public pure override returns (WorkloadId) {
        return WorkloadId.wrap(
            keccak256(
                bytes.concat(
                    registration.parsedReportBody.mrTd,
                    registration.parsedReportBody.rtMr0,
                    registration.parsedReportBody.rtMr1,
                    registration.parsedReportBody.rtMr2,
                    registration.parsedReportBody.rtMr3,
                    registration.parsedReportBody.mrConfigId,
                    registration.parsedReportBody.xFAM,
                    registration.parsedReportBody.tdAttributes
                )
            )
        );
    }

    /// @inheritdoc IBlockBuilderPolicy
    function addWorkloadToPolicy(
        WorkloadId workloadId,
        string calldata commitHash,
        string[] calldata sourceLocators
    ) external override onlyOwner {
        bytes32 id = WorkloadId.unwrap(workloadId);

        if (bytes(approvedWorkloads[id].commitHash).length > 0) {
            revert WorkloadAlreadyApproved();
        }

        approvedWorkloads[id] = WorkloadMetadata({
            commitHash: commitHash,
            sourceLocators: sourceLocators
        });

        emit WorkloadAddedToPolicy(workloadId, commitHash, sourceLocators);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function removeWorkloadFromPolicy(WorkloadId workloadId) external override onlyOwner {
        bytes32 id = WorkloadId.unwrap(workloadId);

        if (bytes(approvedWorkloads[id].commitHash).length == 0) {
            revert WorkloadNotApproved();
        }

        delete approvedWorkloads[id];

        emit WorkloadRemovedFromPolicy(workloadId);
    }

    /// @inheritdoc IBlockBuilderPolicy
    function getWorkloadMetadata(WorkloadId workloadId)
        external
        view
        override
        returns (WorkloadMetadata memory)
    {
        return approvedWorkloads[WorkloadId.unwrap(workloadId)];
    }
}
