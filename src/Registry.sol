// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";
import { MerkleTree } from "./lib/MerkleTree.sol";
import { IRegistry } from "./IRegistry.sol";
import { ISlasher } from "./ISlasher.sol";

contract Registry is IRegistry {
    using BLS for *;

    /// Mapping from registration merkle roots to Operator structs
    mapping(bytes32 registrationRoot => Operator) public registrations;

    // Constants
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant MIN_UNREGISTRATION_DELAY = 64; // Two epochs
    uint256 public constant FRAUD_PROOF_WINDOW = 7200; // 1 day
    bytes public constant DOMAIN_SEPARATOR = "0x00435255"; // "URC" in little endian
    uint256 public ETH2_GENESIS_TIMESTAMP;

    constructor() {
        if (block.chainid == 17000) {
            // Holesky
            ETH2_GENESIS_TIMESTAMP = 1695902400;
        } else if (block.chainid == 1) {
            // Mainnet
            ETH2_GENESIS_TIMESTAMP = 1606824023;
        } else if (block.chainid == 7014190335) {
            // Helder
            ETH2_GENESIS_TIMESTAMP = 1718967660;
        }
    }

    function register(Registration[] calldata regs, address withdrawalAddress, uint16 unregistrationDelay)
        external
        payable
        returns (bytes32 registrationRoot)
    {
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        if (unregistrationDelay < MIN_UNREGISTRATION_DELAY) {
            revert UnregistrationDelayTooShort();
        }

        registrationRoot = _merkleizeRegistrations(regs);

        if (registrationRoot == bytes32(0)) {
            revert InvalidRegistrationRoot();
        }

        if (registrations[registrationRoot].registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        registrations[registrationRoot] = Operator({
            withdrawalAddress: withdrawalAddress,
            collateralGwei: uint56(msg.value / 1 gwei),
            registeredAt: uint32(block.number),
            unregistrationDelay: unregistrationDelay,
            unregisteredAt: 0
        });

        emit OperatorRegistered(registrationRoot, msg.value, unregistrationDelay);
    }

    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei)
    {
        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);
    }

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 slashedCollateralWei) {
        Operator storage operator = registrations[registrationRoot];
        address operatorWithdrawalAddress = operator.withdrawalAddress;

        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        uint256 collateralGwei = _verifyMerkleProof(registrationRoot, keccak256(abi.encode(reg)), proof, leafIndex);

        if (collateralGwei == 0) {
            revert NotRegisteredValidator();
        }

        // Reconstruct registration message
        bytes memory message = abi.encodePacked(operatorWithdrawalAddress, operator.unregistrationDelay);

        // Verify registration signature
        if (BLS.verify(message, reg.signature, reg.pubkey, DOMAIN_SEPARATOR)) {
            revert FraudProofChallengeInvalid();
        }

        // Delete the operator
        delete registrations[registrationRoot];

        // Calculate the amount to transfer to challenger and return to operator
        slashedCollateralWei = MIN_COLLATERAL;
        uint256 remainingWei = uint256(collateralGwei) * 1 gwei - slashedCollateralWei;

        // Transfer to the challenger
        (bool success,) = msg.sender.call{ value: slashedCollateralWei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        (success,) = operatorWithdrawalAddress.call{ value: remainingWei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit RegistrationSlashed(registrationRoot, msg.sender, operatorWithdrawalAddress, reg);
    }

    function unregister(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];

        if (operator.withdrawalAddress != msg.sender) {
            revert WrongOperator();
        }

        // Check that they haven't already unregistered
        if (operator.unregisteredAt != 0) {
            revert AlreadyUnregistered();
        }

        // Set unregistration timestamp
        operator.unregisteredAt = uint32(block.number);

        emit OperatorUnregistered(registrationRoot, operator.unregisteredAt);
    }

    function claimCollateral(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];
        address operatorWithdrawalAddress = operator.withdrawalAddress;
        uint256 collateralGwei = operator.collateralGwei;

        // Check that they've unregistered
        if (operator.unregisteredAt == 0) {
            revert NotUnregistered();
        }

        // Check that enough time has passed
        if (block.number < operator.unregisteredAt + operator.unregistrationDelay) {
            revert UnregistrationDelayNotMet();
        }

        // Check there's collateral to claim
        if (collateralGwei == 0) {
            revert NoCollateralToClaim();
        }

        uint256 amountToReturn = collateralGwei * 1 gwei;

        // Clear operator info
        delete registrations[registrationRoot];

        // Transfer to operator
        (bool success,) = operatorWithdrawalAddress.call{ value: amountToReturn }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit CollateralClaimed(registrationRoot, collateralGwei);
    }

    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei) {
        Operator storage operator = registrations[registrationRoot];
        address operatorWithdrawalAddress = operator.withdrawalAddress;

        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        uint256 collateralGwei =
            _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, signedDelegation);

        slashAmountGwei = _executeSlash(signedDelegation, evidence, collateralGwei);

        // Delete the operator
        delete registrations[registrationRoot];

        // Distribute slashed funds
        _distributeSlashedFunds(operatorWithdrawalAddress, collateralGwei, slashAmountGwei);

        emit OperatorSlashed(registrationRoot, slashAmountGwei, signedDelegation.delegation.proposerPubKey);
    }

    function addCollateral(bytes32 registrationRoot) external payable {
        Operator storage operator = registrations[registrationRoot];
        if (operator.collateralGwei == 0) {
            revert NotRegisteredValidator();
        }

        if (msg.value / 1 gwei > type(uint56).max) {
            revert CollateralOverflow();
        }

        operator.collateralGwei += uint56(msg.value / 1 gwei);
        emit CollateralAdded(registrationRoot, operator.collateralGwei);
    }

    // Internal functions

    function _merkleizeRegistrations(Registration[] calldata regs) internal returns (bytes32 registrationRoot) {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](regs.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = keccak256(abi.encode(regs[i]));
            emit ValidatorRegistered(i, regs[i], leaves[i]);
        }

        registrationRoot = MerkleTree.generateTree(leaves);
    }

    function _verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        internal
        view
        returns (uint256 collateralGwei)
    {
        if (MerkleTree.verifyProofCalldata(registrationRoot, leaf, leafIndex, proof)) {
            collateralGwei = registrations[registrationRoot].collateralGwei;
        }
    }

    function _verifyDelegation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation
    ) internal view returns (uint256 collateralGwei) {
        // Reconstruct Leaf using pubkey in SignedDelegation to check equivalence
        bytes32 leaf = keccak256(abi.encode(signedDelegation.delegation.proposerPubKey, registrationSignature));

        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);

        if (collateralGwei == 0) {
            revert NotRegisteredValidator();
        }

        // Reconstruct Delegation message
        bytes memory message = abi.encode(signedDelegation.delegation);

        // Check if the delegation is fresh
        if (signedDelegation.delegation.validUntil < _getSlotFromTimestamp(block.timestamp)) {
            revert DelegationExpired();
        }

        // Recover Slasher contract domain separator
        bytes memory domainSeparator = ISlasher(signedDelegation.delegation.slasher).DOMAIN_SEPARATOR();

        if (
            !BLS.verify(message, signedDelegation.signature, signedDelegation.delegation.proposerPubKey, domainSeparator)
        ) {
            revert DelegationSignatureInvalid();
        }
    }

    function _executeSlash(
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence,
        uint256 collateralGwei
    ) internal returns (uint256 slashAmountGwei) {
        slashAmountGwei = ISlasher(signedDelegation.delegation.slasher).slash(signedDelegation.delegation, evidence);

        if (slashAmountGwei == 0) {
            revert NoCollateralSlashed();
        }

        if (slashAmountGwei > collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }
    }

    function _distributeSlashedFunds(address withdrawalAddress, uint256 collateralGwei, uint256 slashAmountGwei)
        internal
    {
        // Transfer to the slasher
        (bool success,) = msg.sender.call{ value: slashAmountGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        (success,) = withdrawalAddress.call{ value: (collateralGwei - slashAmountGwei) * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }
    }

    /// @notice Get the slot number from a given timestamp. Assumes 12 second slot time.
    /// @param _timestamp The timestamp
    /// @return The slot number
    function _getSlotFromTimestamp(uint256 _timestamp) public view returns (uint256) {
        return (_timestamp - ETH2_GENESIS_TIMESTAMP) / 12;
    }
}
