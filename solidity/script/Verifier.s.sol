pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {Verifier} from "../src/Verifier.sol";

contract VerifierScript is Script {
    Verifier public verifier;

    function setUp() public {}

    function run() public {
        // Look for the private key in the .env file or command line
        vm.startBroadcast();

        verifier = new Verifier();

        vm.stopBroadcast();
    }
}