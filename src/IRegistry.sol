// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS} from "./lib/BLS.sol";

interface IRegistry {
    // Structs
    struct Registration {
        /// Compressed validator BLS public key
        BLS.G1Point pubkey;
        /// Validator BLS signature
        BLS.G2Point signature;
    }

    struct Operator {
        /// The address used to deregister validators and claim collateral
        address withdrawalAddress;
        /// ETH collateral in GWEI
        uint56 collateralGwei;
        /// The block number when registration occured
        uint32 registeredAt;
        /// The block number when deregistration occured
        uint32 unregisteredAt;
        /// The number of blocks that must elapse between deregistering and claiming
        uint16 unregistrationDelay;
    }

    // Events
    event OperatorRegistered(bytes32 operatorCommitment, uint32 registeredAt);
    event OperatorUnregistered(bytes32 operatorCommitment, uint32 unregisteredAt);
    event OperatorDeleted(bytes32 operatorCommitment, uint72 amountToReturn);

    // Errors
    error InsufficientCollateral();
    error WrongOperator();
    error AlreadyUnregistered();
    error NotUnregistered();
    error UnregistrationDelayNotMet();
    error NoCollateralToClaim();
    error FraudProofWindowExpired();
    error FraudProofMerklePathInvalid();
    error FraudProofChallengeInvalid();
    error UnregistrationDelayTooShort();

    function register(
        Registration[] calldata registrations,
        address withdrawalAddress,
        uint16 unregistrationDelay,
        uint256 height
    ) external payable;

    function slashRegistration(
        bytes32 operatorCommitment,
        BLS.G1Point calldata pubkey,
        BLS.G2Point calldata signature,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external view;

    function unregister(bytes32 operatorCommitment) external;

    function claimCollateral(bytes32 operatorCommitment) external;
}