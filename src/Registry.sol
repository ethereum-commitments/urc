// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS} from "./lib/BLS.sol";
import {MerkleTree} from "./lib/MerkleTree.sol";
import {IRegistry} from "./IRegistry.sol";
import {ISlasher} from "./ISlasher.sol";

contract Registry is IRegistry {
    using BLS for *;

    /// Mapping from registration merkle roots to Operator structs
    mapping(bytes32 registrationRoot => Operator) public registrations;

    // Constants
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant MIN_UNREGISTRATION_DELAY = 64; // Two epochs
    uint256 public constant FRAUD_PROOF_WINDOW = 7200;
    bytes public constant DOMAIN_SEPARATOR =
        bytes("Universal-Registry-Contract");

    function register(
        Registration[] calldata regs,
        address withdrawalAddress,
        uint16 unregistrationDelay
    ) external payable returns (bytes32 registrationRoot) {
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

        emit OperatorRegistered(
            registrationRoot,
            msg.value,
            unregistrationDelay
        );
    }

    function _merkleizeRegistrations(
        Registration[] calldata regs
    ) internal returns (bytes32 registrationRoot) {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](regs.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = keccak256(abi.encode(regs[i]));
            emit ValidatorRegistered(i, regs[i], leaves[i]);
        }

        registrationRoot = MerkleTree.generateTree(leaves);
    }

    function slashRegistration(
        bytes32 registrationRoot,
        Registration calldata reg,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external returns (uint256 slashedCollateralWei) {
        Operator storage operator = registrations[registrationRoot];

        if (block.number > operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowExpired();
        }

        uint256 collateralGwei = verifyMerkleProof(
            registrationRoot,
            keccak256(abi.encode(reg)),
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
        emit RegistrationSlashed(
            registrationRoot,
            msg.sender,
            operator.withdrawalAddress,
            reg
        );

        // Transfer to the challenger
        slashedCollateralWei = MIN_COLLATERAL;
        (bool success, ) = msg.sender.call{value: slashedCollateralWei}(""); // todo reentrancy
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        uint256 remainingWei = uint256(operator.collateralGwei) *
            1 gwei -
            slashedCollateralWei;
        (success, ) = operator.withdrawalAddress.call{value: remainingWei}(""); // todo reentrancy
        if (!success) {
            revert EthTransferFailed();
        }

        // Delete the operator
        delete registrations[registrationRoot];
        emit OperatorDeleted(registrationRoot);
    }

    function verifyMerkleProof(
        bytes32 registrationRoot,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) public view returns (uint256 collateralGwei) {
        if (
            MerkleTree.verifyProofCalldata(
                registrationRoot,
                leaf,
                leafIndex,
                proof
            )
        ) {
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

        uint256 amountToReturn = uint256(operator.collateralGwei) * 1 gwei;

        // TODO safe transfer for rentrancy
        (bool success, ) = operator.withdrawalAddress.call{
            value: amountToReturn
        }("");
        require(success, "Transfer failed");

        emit OperatorDeleted(registrationRoot);

        // Clear operator info
        delete registrations[registrationRoot];
    }

    function slashOperator(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence
    ) external {
        Operator storage operator = registrations[registrationRoot];

        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        uint256 collateralGwei = _verifySlashProof(
            registrationRoot,
            registrationSignature,
            proof,
            leafIndex,
            signedDelegation
        );

        uint256 slashAmountGwei = _executeSlash(
            signedDelegation,
            evidence,
            collateralGwei
        );

        _distributeSlashedFunds(
            operator,
            collateralGwei,
            slashAmountGwei
        );

        emit OperatorSlashed(registrationRoot, slashAmountGwei, signedDelegation.delegation.validatorPubKey);

        // Delete the operator
        delete registrations[registrationRoot];
        emit OperatorDeleted(registrationRoot);
    }

    function _verifySlashProof(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation
    ) internal view returns (uint256) {
        // Reconstruct Leaf using pubkey in SignedDelegation to check equivalence
        bytes32 leaf = keccak256(
            abi.encode(
                signedDelegation.delegation.validatorPubKey,
                registrationSignature
            )
        );

        uint256 collateralGwei = verifyMerkleProof(
            registrationRoot,
            leaf,
            proof,
            leafIndex
        );

        if (collateralGwei == 0) {
            revert NotRegisteredValidator();
        }

        // Reconstruct Delegation message
        bytes memory message = abi.encode(signedDelegation.delegation);

        if (
            !BLS.verify(
                message,
                signedDelegation.signature,
                signedDelegation.delegation.validatorPubKey,
                DOMAIN_SEPARATOR
            )
        ) {
            revert DelegationSignatureInvalid();
        }

        return collateralGwei;
    }

    function _executeSlash(
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence,
        uint256 collateralGwei
    ) internal returns (uint256) {
        ISlasher slasher = ISlasher(signedDelegation.delegation.slasher);

        uint256 slashAmountGwei = slasher.slash(
            signedDelegation.delegation,
            evidence
        );

        if (slashAmountGwei > collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }

        if (slashAmountGwei == 0) {
            revert NoCollateralSlashed();
        }

        return slashAmountGwei;
    }

    function _distributeSlashedFunds(
        Operator storage operator,
        uint256 collateralGwei,
        uint256 slashAmountGwei
    ) internal {
        // Transfer to the slasher
        (bool success, ) = msg.sender.call{value: slashAmountGwei * 1 gwei}("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        (success, ) = operator.withdrawalAddress.call{
            value: (collateralGwei - slashAmountGwei) * 1 gwei
        }("");
        if (!success) {
            revert EthTransferFailed();
        }
    }
}
