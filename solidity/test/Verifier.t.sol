// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol"; 

contract VerifierTest is Test {
    Verifier public verifier;

    // 1. SetUp: Runs before every test
    function setUp() public {
        // Always deploy a fresh instance for isolation
        verifier = new Verifier();
        console.log("Verifier deployed at:", address(verifier));
    }

    function test_VerifyProofFromFile() public {
        // 2. Read and Parse JSON
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/proof.json");
        
        // Fail the test early if file is missing
        try vm.readFile(path) returns (string memory json) {
            console.log("JSON loaded from:", path);

            // Decode Fields
            uint256[8] memory proof = abi.decode(vm.parseJson(json, ".proof"), (uint256[8]));
            uint256[2] memory commitments = abi.decode(vm.parseJson(json, ".commitments"), (uint256[2]));
            uint256[2] memory commitmentPok = abi.decode(vm.parseJson(json, ".commitmentPok"), (uint256[2]));
            uint256[128] memory input = abi.decode(vm.parseJson(json, ".input"), (uint256[128]));

            verifier.verifyProof(proof, commitments, commitmentPok, input);
            
            // If we reached here, it worked.
            assertTrue(true, "Proof verification completed successfully");

        } catch {
            fail("Could not read proof.json. Ensure it exists in the project root.");
        }
    }
}