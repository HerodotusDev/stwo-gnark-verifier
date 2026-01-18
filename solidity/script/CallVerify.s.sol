// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

interface IVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external;
}

contract CallVerifyScript is Script {
    function run() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/calldata.json"));
        address verifier = vm.envAddress("VERIFIER_ADDRESS");

        console.log("Verifying proof on:", verifier);

        // Look for the private key in the .env file or command line
        vm.startBroadcast();

        IVerifier(verifier).verifyProof(
            abi.decode(_parse(json, ".proof"), (uint256[8])),
            abi.decode(_parse(json, ".commitments"), (uint256[2])),
            abi.decode(_parse(json, ".commitmentPok"), (uint256[2])),
            abi.decode(_parse(json, ".input"), (uint256[8]))
        );

        vm.stopBroadcast();

        console.log("Proof verified successfully!");
    }

    /// @dev Parses JSON string-array -> uint[] -> packed bytes.
    function _parse(string memory json, string memory key) internal pure returns (bytes memory) {
        string[] memory raw = abi.decode(vm.parseJson(json, key), (string[]));
        uint256[] memory converted = new uint256[](raw.length);

        for (uint256 i; i < raw.length;) {
            converted[i] = vm.parseUint(raw[i]);
            unchecked { ++i; }
        }

        return abi.encodePacked(converted);
    }
}