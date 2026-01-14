// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {MockAttestation} from "../src/MockAttestation.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {BlockBuilderPolicy} from "../src/BlockBuilderPolicy.sol";
import {WorkloadId} from "../src/interfaces/IBlockBuilderPolicy.sol";

contract DeployScript is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy MockAttestation
        MockAttestation attestation = new MockAttestation();
        console.log("MockAttestation deployed at:", address(attestation));

        // 2. Deploy FlashtestationRegistry
        FlashtestationRegistry registry = new FlashtestationRegistry(address(attestation));
        console.log("FlashtestationRegistry deployed at:", address(registry));

        // 3. Deploy BlockBuilderPolicy
        BlockBuilderPolicy policy = new BlockBuilderPolicy(address(registry));
        console.log("BlockBuilderPolicy deployed at:", address(policy));

        vm.stopBroadcast();

        // Output addresses as JSON for easy parsing
        string memory json = string.concat(
            '{"attestation":"', vm.toString(address(attestation)),
            '","registry":"', vm.toString(address(registry)),
            '","policy":"', vm.toString(address(policy)),
            '"}'
        );
        vm.writeFile("deployment.json", json);
        console.log("Deployment addresses written to deployment.json");
    }
}

/// @notice Script to add a workload to the policy
contract AddWorkloadScript is Script {
    function run(address policyAddress, bytes32 workloadId) public {
        uint256 deployerPrivateKey = vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));

        vm.startBroadcast(deployerPrivateKey);

        BlockBuilderPolicy policy = BlockBuilderPolicy(policyAddress);

        string[] memory sourceLocators = new string[](1);
        sourceLocators[0] = "https://github.com/example/mock-tee";

        policy.addWorkloadToPolicy(
            WorkloadId.wrap(workloadId),
            "mock-v1",
            sourceLocators
        );

        console.log("Workload added to policy:", vm.toString(workloadId));

        vm.stopBroadcast();
    }
}
