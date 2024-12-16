// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";
import { ISlasher } from "./ISlasher.sol";

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
    event ValidatorRegistered(uint256 leafIndex, Registration reg, bytes32 leaf);
    event RegistrationSlashed(
        bytes32 registrationRoot, address challenger, address withdrawalAddress, Registration reg
    );
    event OperatorSlashed(bytes32 registrationRoot, uint256 slashAmountGwei, BLS.G1Point validatorPubKey);
    event OperatorUnregistered(bytes32 registrationRoot, uint32 unregisteredAt);
    event CollateralClaimed(bytes32 registrationRoot, uint256 collateralGwei);
    event CollateralAdded(bytes32 registrationRoot, uint256 collateralGwei);

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
    error FraudProofWindowNotMet();
    error DelegationSignatureInvalid();
    error SlashAmountExceedsCollateral();
    error NoCollateralSlashed();
    error NotRegisteredValidator();
    error FraudProofMerklePathInvalid();
    error FraudProofChallengeInvalid();
    error CollateralOverflow();

    function register(Registration[] calldata registrations, address withdrawalAddress, uint16 unregistrationDelay)
        external
        payable
        returns (bytes32 registrationRoot);

    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei);

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 collateral);

    function unregister(bytes32 registrationRoot) external;

    function claimCollateral(bytes32 registrationRoot) external;

    function addCollateral(bytes32 registrationRoot) external payable;

    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei);
}
