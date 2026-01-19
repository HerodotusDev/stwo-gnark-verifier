// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol"; 

contract VerifierTest is Test {
    Verifier public verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_VerifyProofFromFile() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/calldata.json"));

        verifier.verifyProof(
            abi.decode(_parse(json, ".proof"), (uint256[8])),
            abi.decode(_parse(json, ".commitments"), (uint256[2])),
            abi.decode(_parse(json, ".commitmentPok"), (uint256[2])),
            abi.decode(_parse(json, ".input"), (uint256[8]))
        );
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