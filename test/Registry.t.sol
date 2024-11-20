// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import {BLS} from "../src/lib/BLS.sol";

contract RegistryTest is Test {
    using BLS for *;

    Registry registry;
    address operator = address(0x1);

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether); // Give operator some ETH
    }
}
