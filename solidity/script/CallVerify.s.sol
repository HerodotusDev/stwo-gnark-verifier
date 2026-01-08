// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

interface IVerifier {
    function verifyProof(
        uint256[8] memory proof,
        uint256[2] memory commitments,
        uint256[2] memory commitmentPok,
        uint256[] memory input
    ) external view;
}

contract CallVerifyScript is Script {
    function run() public {
        // 1. Read and Parse JSON
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/proof.json"));
        
        uint256[8] memory proof = abi.decode(vm.parseJson(json, ".proof"), (uint256[8]));
        uint256[2] memory commitments = abi.decode(vm.parseJson(json, ".commitments"), (uint256[2]));
        uint256[2] memory commitmentPok = abi.decode(vm.parseJson(json, ".commitmentPok"), (uint256[2]));
        uint256[] memory input = abi.decode(vm.parseJson(json, ".input"), (uint256[]));

        address verifier = vm.envAddress("VERIFIER_ADDRESS");

        // 3. Call Verify (View function)
        console.log("Verifying proof on:", verifier);
        IVerifier(verifier).verifyProof(proof, commitments, commitmentPok, input);
        
        console.log("Proof is valid!");
    }
}