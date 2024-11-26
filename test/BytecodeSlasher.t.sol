// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import { BLS } from "../src/lib/BLS.sol";
import { BytecodeSlasher, DummySlasher } from "../src/BytecodeSlasher.sol";

contract BytecodeSlasherTest is Test {
    event BytecodeExecuted(bytes bytecode, bool success);

    error ExecutionFailed();

    BytecodeSlasher public bytecodeSlasher;
    DummySlasher dummySlasher;

    function setUp() public {
        bytecodeSlasher = new BytecodeSlasher();
    }

    function testDummySlasher() public {
        // https://book.getfoundry.sh/cheatcodes/get-code#examples
        // creation bytecode
        bytes memory bytecode = vm.getCode("BytecodeSlasher.sol:DummySlasher");
        bytes memory callData = abi.encodeWithSignature("dummy()");

        uint256 result = bytecodeSlasher.slash(bytecode, callData);
        assertEq(result, 42);
    }
}
