// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IFlashtestationRegistry} from "./IFlashtestationRegistry.sol";

/// @notice Type-safe wrapper for workload identifiers
type WorkloadId is bytes32;

/// @notice Metadata about an approved workload
struct WorkloadMetadata {
    string commitHash;
    string[] sourceLocators;
}

/// @notice Interface for the Block Builder Policy contract
interface IBlockBuilderPolicy {
    /// @notice Emitted when a workload is added to the policy
    event WorkloadAddedToPolicy(
        WorkloadId indexed workloadId,
        string commitHash,
        string[] sourceLocators
    );

    /// @notice Emitted when a workload is removed from the policy
    event WorkloadRemovedFromPolicy(WorkloadId indexed workloadId);

    /// @notice Check if a TEE address is allowed by policy
    /// @param teeAddress The address to check
    /// @return allowed Whether the TEE is allowed
    /// @return workloadId The workload ID if allowed
    function isAllowedPolicy(address teeAddress)
        external
        view
        returns (bool allowed, WorkloadId workloadId);

    /// @notice Compute the workload ID from a TEE registration
    /// @param registration The TEE registration data
    /// @return The computed workload ID
    function workloadIdForTDRegistration(
        IFlashtestationRegistry.RegisteredTEE memory registration
    ) external pure returns (WorkloadId);

    /// @notice Add a workload to the approved list
    /// @param workloadId The workload ID to approve
    /// @param commitHash Git commit hash for the workload source
    /// @param sourceLocators URLs where source can be found
    function addWorkloadToPolicy(
        WorkloadId workloadId,
        string calldata commitHash,
        string[] calldata sourceLocators
    ) external;

    /// @notice Remove a workload from the approved list
    /// @param workloadId The workload ID to remove
    function removeWorkloadFromPolicy(WorkloadId workloadId) external;

    /// @notice Get metadata for a workload
    /// @param workloadId The workload ID to query
    /// @return The workload metadata
    function getWorkloadMetadata(WorkloadId workloadId)
        external
        view
        returns (WorkloadMetadata memory);
}
