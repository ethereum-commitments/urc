// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";

interface IRegistry {
    // Structs

    struct Registration {
        /// Validator BLS public key
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
    event OperatorRegistered(bytes32 registrationRoot, uint256 collateral, uint16 unregistrationDelay);
    event OperatorUnregistered(bytes32 registrationRoot, uint32 unregisteredAt);
    event RegistrationSlashed(
        bytes32 registrationRoot, address challenger, address withdrawalAddress, Registration reg
    );
    event OperatorDeleted(bytes32 registrationRoot);
    event ValidatorRegistered(uint256 leafIndex, Registration reg, bytes32 leaf);

    // Errors
    error InsufficientCollateral();
    error UnregistrationDelayTooShort();
    error OperatorAlreadyRegistered();
    error InvalidRegistrationRoot();
    error EthTransferFailed();
    error WrongOperator();
    error AlreadyUnregistered();
    error NotUnregistered();
    error UnregistrationDelayNotMet();
    error NoCollateralToClaim();
    error FraudProofWindowExpired();
    error NotRegisteredValidator();
    error FraudProofMerklePathInvalid();
    error FraudProofChallengeInvalid();

    function register(Registration[] calldata registrations, address withdrawalAddress, uint16 unregistrationDelay)
        external
        payable
        returns (bytes32 registrationRoot);

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 collateral);

    function unregister(bytes32 registrationRoot) external;

    function claimCollateral(bytes32 registrationRoot) external;
}
