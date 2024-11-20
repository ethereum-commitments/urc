// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS} from "./lib/BLS.sol";
import {MerkleUtils} from "./lib/MerkleUtils.sol";

contract Registry {
    using BLS for *;

    struct Registration {
        /// Compressed validator BLS public key
        BLS.G1Point pubkey; // todo compress
        /// Validator BLS signature
        BLS.G2Point signature;
    }

    struct Operator {
        /// Compressed ECDSA key without prefix
        bytes32 proxyKey;
        /// The address used to deregister validators and claim collateral
        address withdrawalAddress;
        /// ETH collateral in GWEI
        uint56 collateral;
        /// The block number when registration occured
        uint32 registeredAt;
        /// The block number when deregistration occured
        uint32 unregisteredAt;
        /// The number of blocks that must elapse between deregistering and claiming
        uint16 unregistrationDelay;
    }

    /// Mapping from registration merkle roots to Operator structs
    mapping(bytes32 operatorCommitment => Operator) public commitments;

    // Constants
    uint256 constant MIN_COLLATERAL = 0.1 ether;
    uint256 constant TWO_EPOCHS = 64;
    uint256 constant FRAUD_PROOF_WINDOW = 7200;
    bytes constant DOMAIN_SEPARATOR = bytes("Universal-Registry-Contract");

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

    // Events
    event OperatorRegistered(bytes32 operatorCommitment, uint32 registeredAt);
    event OperatorUnregistered(
        bytes32 operatorCommitment,
        uint32 unregisteredAt
    );
    event OperatorDeleted(bytes32 operatorCommitment, uint72 amountToReturn);

    function register(
        Registration[] calldata registrations,
        bytes32 proxyKey,
        address withdrawalAddress,
        uint16 unregistrationDelay,
        uint256 height
    ) external payable {
        // check collateral
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        if (unregistrationDelay < TWO_EPOCHS) {
            revert UnregistrationDelayTooShort();
        }

        // merklize registrations
        bytes32 operatorCommitment = createCommitment(
            registrations,
            proxyKey,
            height
        );

        // add operatorCommitment to mapping
        commitments[operatorCommitment] = Operator({
            withdrawalAddress: withdrawalAddress,
            proxyKey: proxyKey,
            collateral: uint56(msg.value), // todo save as GWEI
            registeredAt: uint32(block.number),
            unregistrationDelay: unregistrationDelay,
            unregisteredAt: 0
        });

        // emit events
    }

    function createCommitment(
        Registration[] calldata registrations,
        bytes32 proxyKey,
        uint256 height
    ) internal pure returns (bytes32 operatorCommitment) {
        uint256 batchSize = 1 << height; // guaranteed pow of 2
        require(
            registrations.length <= batchSize,
            "Batch size must be at least as big"
        );

        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](batchSize);

        // Create leaf nodes
        for (uint256 i = 0; i < registrations.length; i++) {
            // Create registration commitment by hashing signature and metadata
            // Flatten the signature
            BLS.G2Point memory signature = registrations[i].signature;
            uint256[8] memory signatureBytes = [
                signature.x.c0.a,
                signature.x.c0.b,
                signature.x.c1.a,
                signature.x.c1.b,
                signature.y.c0.a,
                signature.y.c0.b,
                signature.y.c1.a,
                signature.y.c1.b
            ];
            bytes32 registrationCommitment = sha256(
                abi.encodePacked(signatureBytes, proxyKey)
            );

            // Create leaf node by hashing pubkey and commitment
            BLS.G1Point memory pubkey = registrations[i].pubkey;
            leaves[i] = sha256(
                abi.encodePacked(
                    [pubkey.x.a, pubkey.x.b, pubkey.y.a, pubkey.y.b],
                    registrationCommitment
                )
            );

            // emit event
        }

        // Fill remaining leaves with empty hashes for padding
        for (uint256 i = registrations.length; i < batchSize; i++) {
            leaves[i] = bytes32(0);
        }

        operatorCommitment = MerkleUtils.merkleize(leaves);
        //emit final event
    }

    function slashRegistration(
        bytes32 operatorCommitment,
        BLS.G1Point calldata pubkey,
        BLS.G2Point calldata signature,
        bytes32 proxyKey,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external view {
        Operator storage operator = commitments[operatorCommitment];

        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        uint256[4] memory pubkeyBytes = [
            pubkey.x.a,
            pubkey.x.b,
            pubkey.y.a,
            pubkey.y.b
        ];
        uint256[8] memory signatureBytes = [
            signature.x.c0.a,
            signature.x.c0.b,
            signature.x.c1.a,
            signature.x.c1.b,
            signature.y.c0.a,
            signature.y.c0.b,
            signature.y.c1.a,
            signature.y.c1.b
        ];

        // reconstruct leaf
        bytes32 leaf = sha256(
            abi.encodePacked(
                pubkeyBytes,
                sha256(abi.encodePacked(signatureBytes, proxyKey))
            )
        );

        // verify proof against operatorCommitment
        if (
            MerkleUtils.verifyProof(proof, operatorCommitment, leaf, leafIndex)
        ) {
            revert FraudProofMerklePathInvalid();
        }

        // reconstruct message
        // todo what exactly are they signing?
        bytes memory message = bytes("");

        // verify signature
        if (BLS.verify(message, signature, pubkey, DOMAIN_SEPARATOR)) {
            revert FraudProofChallengeInvalid();
        }
    }

    function unregister(bytes32 operatorCommitment) external {
        Operator storage operator = commitments[operatorCommitment];

        if (operator.withdrawalAddress != msg.sender) {
            revert WrongOperator();
        }

        // Check that they haven't already unregistered
        if (operator.unregisteredAt != 0) {
            revert AlreadyUnregistered();
        }

        // Set unregistration timestamp
        operator.unregisteredAt = uint32(block.number);

        emit OperatorUnregistered(operatorCommitment, operator.unregisteredAt);
    }

    function claimCollateral(bytes32 operatorCommitment) external {
        Operator storage operator = commitments[operatorCommitment];

        // Check that they've unregistered
        if (operator.unregisteredAt == 0) {
            revert NotUnregistered();
        }

        // Check that enough time has passed
        if (
            block.number <
            operator.unregisteredAt + operator.unregistrationDelay
        ) {
            revert UnregistrationDelayNotMet();
        }

        // Check there's collateral to claim
        if (operator.collateral == 0) {
            revert NoCollateralToClaim();
        }

        uint72 amountToReturn = operator.collateral;

        // TODO safe transfer for rentrancy
        (bool success, ) = operator.withdrawalAddress.call{
            value: amountToReturn
        }("");
        require(success, "Transfer failed");

        emit OperatorDeleted(operatorCommitment, amountToReturn);

        // Clear operator info
        delete commitments[operatorCommitment];
    }
}
