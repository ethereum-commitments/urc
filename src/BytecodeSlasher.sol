// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract BytecodeSlasher {
    event BytecodeExecuted(bytes bytecode, bool success);

    error ExecutionFailed();
    error FundsLost();

    // modifiers
    modifier noFundsLost() {
        uint256 initialBalance = address(this).balance;
        _;
        if (address(this).balance < initialBalance) {
            revert FundsLost();
        }
    }

    // todo add to interface:
    // - signed bytecode
    // - slashing evidence (signature from proxy key)
    // - operator commitment
    function slash(
        bytes memory bytecode,
        bytes memory callData
    ) external noFundsLost returns (uint256 slashAmount) {
        bytes memory returnData = executeCode(
            bytecode,
            callData
        );
        slashAmount = abi.decode(returnData, (uint256));
    }

    function executeCode(
        bytes memory bytecode,
        bytes memory callData
    ) internal returns (bytes memory) {
        address slasher;

        assembly {
            // Deploy the slasher contract
            slasher := create(0, add(bytecode, 0x20), mload(bytecode))
            if iszero(slasher) {
                revert(0, 0)
            }
        }

        (bool success, bytes memory returnData) = slasher.call(callData);
        if (!success) {
            revert ExecutionFailed();
        }
        return returnData;
    }
}

contract DummySlasher {
    function dummy() external pure returns (uint256) {
        return 42;
    }
}
