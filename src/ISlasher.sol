// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";

interface ISlasher {
    /// @notice A Delegation message from a proposer's BLS key to a delegate's BLS key
    struct Delegation {
        /// The proposer's BLS public key
        BLS.G1Point proposerPubKey;
        /// The delegate's BLS public key
        BLS.G1Point delegatePubKey;
        /// The address of the slasher contract
        address slasher;
        /// The slot number after which the delegation expires
        uint64 validUntil;
        /// Arbitrary metadata reserved for use by the Slasher
        bytes metadata;
    }

    /// @notice A delegation message signed by a proposer's BLS key
    struct SignedDelegation {
        /// The delegation message
        Delegation delegation;
        /// The signature of the delegation message
        BLS.G2Point signature;
    }

    /// @notice Slash a proposer's BLS key for a given delegation
    /// @dev The URC will call this function to slash a registered operator if supplied with a valid delegation and evidence
    /// @param delegation The delegation message
    /// @param evidence Arbitrary evidence for the slashing
    /// @param challenger The address of the challenger
    /// @return slashAmountGwei The amount of Gwei slashed
    /// @return rewardAmountGwei The amount of Gwei rewarded to the caller
    function slash(Delegation calldata delegation, bytes calldata evidence, address challenger)
        external
        returns (uint256 slashAmountGwei, uint256 rewardAmountGwei);

    /// @notice The domain separator for the Slasher contract
    /// @dev The domain separator is used to prevent replay attacks from different Slasher contracts
    /// @return domainSeparator The domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes memory);
}
