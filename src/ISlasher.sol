// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";

interface ISlasher {
    struct Delegation {
        BLS.G1Point proposerPubKey;
        BLS.G1Point delegatePubKey;
        address slasher;
        uint64 validUntil;
        bytes metadata;
    }

    struct SignedDelegation {
        Delegation delegation;
        BLS.G2Point signature;
    }

    function slash(Delegation calldata delegation, bytes calldata evidence)
        external
        returns (uint256 slashAmountGwei);

    function DOMAIN_SEPARATOR() external view returns (bytes memory);
}
