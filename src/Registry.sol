// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS} from "./lib/BLS.sol";
import {MerkleUtils} from "./lib/MerkleUtils.sol";
import {IRegistry} from "./IRegistry.sol";

contract Registry is IRegistry {
    using BLS for *;

    /// Mapping from registration merkle roots to Operator structs
    mapping(bytes32 registrationRoot => Operator) public registrations;

    // Constants
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant TWO_EPOCHS = 64;
    uint256 public constant FRAUD_PROOF_WINDOW = 7200;
    bytes public constant DOMAIN_SEPARATOR =
        bytes("Universal-Registry-Contract");

    function register(
        Registration[] calldata regs,
        address withdrawalAddress,
        uint16 unregistrationDelay,
        uint256 treeHeight
    ) external payable returns (bytes32 registrationRoot) {
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        if (unregistrationDelay < TWO_EPOCHS) {
            revert UnregistrationDelayTooShort();
        }

        registrationRoot = _merkleizeRegistrations(regs, treeHeight);

        registrations[registrationRoot] = Operator({
            withdrawalAddress: withdrawalAddress,
            collateralGwei: uint56(msg.value / 1 gwei),
            registeredAt: uint32(block.number),
            unregistrationDelay: unregistrationDelay,
            unregisteredAt: 0
        });

        emit OperatorRegistered(
            registrationRoot,
            msg.value,
            unregistrationDelay
        );
    }

    function _merkleizeRegistrations(
        Registration[] calldata regs,
        uint256 treeHeight
    ) internal returns (bytes32 registrationRoot) {
        // Check that the tree height is at least as big as the number of registrations
        uint256 numLeaves = 1 << treeHeight;
        if (regs.length > numLeaves) {
            revert TreeHeightTooSmall();
        }

        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](numLeaves);

        // Create leaf nodes by hashing pubkey and signature
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = sha256(abi.encode(regs[i]));
            emit ValidatorRegistered(i, regs[i]);
        }

        // Fill remaining leaves with empty bytes for padding
        for (uint256 i = regs.length; i < numLeaves; i++) {
            leaves[i] = bytes32(0);
        }

        registrationRoot = MerkleUtils.merkleize(leaves);
    }

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns(uint256 slashedCollateralWei) {
        Operator storage operator = registrations[registrationRoot];

        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        uint256 collateralGwei = verifyMerkleProof(
            registrationRoot,
            reg,
            proof,
            leafIndex
        );

        if (collateralGwei == 0) {
            revert NotRegisteredValidator();
        }

        // Reconstruct registration message
        bytes memory message = abi.encodePacked(
            operator.withdrawalAddress,
            operator.unregistrationDelay
        );

        // Verify registration signature
        if (BLS.verify(message, reg.signature, reg.pubkey, DOMAIN_SEPARATOR)) {
            revert FraudProofChallengeInvalid();
        }
        emit RegistrationSlashed(registrationRoot, msg.sender, operator.withdrawalAddress, reg);

        // Transfer to the challenger
        slashedCollateralWei = MIN_COLLATERAL;
        (bool success,) = msg.sender.call{ value: slashedCollateralWei }("");  // todo reentrancy
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        uint256 remainingWei = uint256(operator.collateralGwei) * 1 gwei - slashedCollateralWei;
        (success,) = operator.withdrawalAddress.call{ value: remainingWei }(""); // todo reentrancy
        if (!success) {
            revert EthTransferFailed();
        }

        // Delete the operator
        delete registrations[registrationRoot];
        emit OperatorDeleted(registrationRoot);
    }

    function verifyMerkleProof(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) public view returns (uint256 collateralGwei) {
        bytes32 leaf = sha256(abi.encode(reg));
        if (MerkleUtils.verifyProof(proof, registrationRoot, leaf, leafIndex)) {
            collateralGwei = registrations[registrationRoot].collateralGwei;
        }
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
        if (operator.collateralGwei == 0) {
            revert NoCollateralToClaim();
        }

        uint72 amountToReturn = operator.collateralGwei;

        // TODO safe transfer for rentrancy
        (bool success, ) = operator.withdrawalAddress.call{
            value: amountToReturn
        }("");
        require(success, "Transfer failed");

        emit OperatorDeleted(registrationRoot);

        // Clear operator info
        delete registrations[registrationRoot];
    }
}
