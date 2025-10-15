// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

import { Test, console } from "forge-std/Test.sol";
import { BLSUtils } from "../src/lib/BLSUtils.sol";
import { BLS } from "solady/utils/ext/ithaca/BLS.sol";
import { ISlasher } from "../src/ISlasher.sol";

/// @notice A simple test demonstrating BLS signature verification.
contract ScratchTest is Test {
    struct CommitmentRequest {
        uint64 commitmentType;
        bytes payload;
        address slasher;
    }

    struct Commitment {
        uint64 commitmentType;
        bytes payload;
        bytes32 requestHash;
        address slasher;
    }

    struct InclusionPayload {
        uint64 slot;
        bytes signedTx;
    }

    function test_Foo() public {
        Commitment memory commitment =
            Commitment({ commitmentType: 1, payload: "", requestHash: bytes32(0), slasher: address(0) });
        console.logBytes(abi.encode(commitment));
        console.logBytes32(keccak256(abi.encode(commitment)));
    }

    function test_Bar() public {
        CommitmentRequest memory commitment = CommitmentRequest({ commitmentType: 1, payload: "", slasher: address(0) });
        console.logBytes(abi.encode(commitment));
        console.logBytes32(keccak256(abi.encode(commitment)));
    }

    function test_Baz() public {
        InclusionPayload memory payload = InclusionPayload({ slot: 12345, signedTx: "" });
        console.logBytes(abi.encode(payload));
        console.logBytes32(keccak256(abi.encode(payload)));
    }
}
