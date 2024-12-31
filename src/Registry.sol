// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";
import { MerkleTree } from "./lib/MerkleTree.sol";
import { IRegistry } from "./IRegistry.sol";
import { ISlasher } from "./ISlasher.sol";

contract Registry is IRegistry {
    using BLS for *;

    /// @notice Mapping from registration merkle roots to Operator structs
    mapping(bytes32 registrationRoot => Operator) public registrations;

    // Constants
    uint256 public constant MIN_COLLATERAL = 0.1 ether;
    uint256 public constant MIN_UNREGISTRATION_DELAY = 64; // Two epochs
    uint256 public constant FRAUD_PROOF_WINDOW = 7200; // 1 day
    address internal constant BURNER_ADDRESS = address(0x0000000000000000000000000000000000000000);
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

    /// @notice Batch registers an operator's BLS keys and collateral to the registry
    /// @dev Registration signatures are optimistically verified. They are expected to be signed with the `DOMAIN_SEPARATOR` mixin.
    /// @dev The function will merkleize the supplied `regs` and map the registration root to an Operator struct.
    /// @dev The function will revert if the operator has already registered the same `regs`, if they sent less than `MIN_COLLATERAL`, if the unregistration delay is less than `MIN_UNREGISTRATION_DELAY`, or if the registration root is invalid.
    /// @param regs The BLS keys to register
    /// @param withdrawalAddress The authorized address to deregister from the registry and claim collateral
    /// @param unregistrationDelay The number of blocks before the operator can be unregistered
    /// @return registrationRoot The merkle root of the registration
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
            unregisteredAt: type(uint32).max
        });

        emit OperatorRegistered(registrationRoot, msg.value, unregistrationDelay);
    }

    /// @notice Verify a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralGwei The collateral amount in GWEI
    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei)
    {
        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);
    }

    /// @notice Slash an operator for submitting a fraudulent `Registration` in the register() function
    /// @dev To save BLS verification gas costs, the URC optimistically accepts registration signatures. This function allows a challenger to slash the operator by executing the BLS verification to prove the registration is fraudulent.
    /// @dev The function will delete the operator's registration, transfer `MIN_COLLATERAL` to the caller, and return any remaining funds to the operator's withdrawal address.
    /// @dev The function will revert if the operator has already unregistered, if the operator has not registered, if the fraud proof window has expired, or if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param reg The fraudulent Registration
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return slashedCollateralWei The amount of GWEI slashed
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
            revert NotRegisteredKey();
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
        uint256 remainingWei = uint256(collateralGwei) * 1 gwei - MIN_COLLATERAL;

        // Transfer to the challenger
        (bool success,) = msg.sender.call{ value: MIN_COLLATERAL }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        (success,) = operatorWithdrawalAddress.call{ value: remainingWei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        emit RegistrationSlashed(registrationRoot, msg.sender, operatorWithdrawalAddress, reg);

        return MIN_COLLATERAL;
    }

    /// @notice Starts the unregistration process for an operator
    /// @dev The function will revert if the operator has already unregistered, if the operator has not registered, or if the caller is not the operator's withdrawal address.
    /// @dev The function will mark the `unregisteredAt` timestamp in the Operator struct. The operator can claim their collateral after the `unregistrationDelay` more blocks have passed.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function unregister(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];

        if (operator.withdrawalAddress != msg.sender) {
            revert WrongOperator();
        }

        // Check that they haven't already unregistered
        if (operator.unregisteredAt != type(uint32).max) {
            revert AlreadyUnregistered();
        }

        // Set unregistration timestamp
        operator.unregisteredAt = uint32(block.number);

        emit OperatorUnregistered(registrationRoot, operator.unregisteredAt);
    }

    /// @notice Claims an operator's collateral after the unregistration delay
    /// @dev The function will revert if the operator does not exist, if the operator has not unregistered, if the `unregistrationDelay` has not passed, or if there is no collateral to claim.
    /// @dev The function will transfer the operator's collateral to their registered `withdrawalAddress`.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function claimCollateral(bytes32 registrationRoot) external {
        Operator storage operator = registrations[registrationRoot];
        address operatorWithdrawalAddress = operator.withdrawalAddress;
        uint256 collateralGwei = operator.collateralGwei;

        // Check that they've unregistered
        if (operator.unregisteredAt == type(uint32).max) {
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

    /// @notice Slashes an operator for breaking a commitment
    /// @dev The function verifies `proof` to first ensure the operator's key is in the registry, then verifies the `signedDelegation` was signed by the key. If the fraud proof window has passed, the URC will call the `slash()` function of the Slasher contract specified in the `signedDelegation`. The Slasher contract will determine if the operator has broken a commitment and return the amount of GWEI to be slashed at the URC.
    /// @dev The function will delete the operator's registration, transfer `slashAmountGwei` to the caller, and return any remaining funds to the operator's withdrawal address.
    /// @dev The function will revert if the operator has not registered, if the fraud proof window has not passed, if the operator has already unregistered, or if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param signedDelegation The SignedDelegation signed by the operator's BLS key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @return slashAmountGwei The amount of GWEI slashed
    /// @return rewardAmountGwei The amount of GWEI rewarded to the caller
    function slashCommitment(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence
    ) external returns (uint256 slashAmountGwei, uint256 rewardAmountGwei) {
        Operator storage operator = registrations[registrationRoot];
        address operatorWithdrawalAddress = operator.withdrawalAddress;

        if (block.number < operator.registeredAt + FRAUD_PROOF_WINDOW) {
            revert FraudProofWindowNotMet();
        }

        if (
            operator.unregisteredAt != type(uint32).max
                && block.number > operator.unregisteredAt + operator.unregistrationDelay
        ) {
            revert OperatorAlreadyUnregistered();
        }

        uint256 collateralGwei =
            _verifyDelegation(registrationRoot, registrationSignature, proof, leafIndex, signedDelegation);

        (slashAmountGwei, rewardAmountGwei) = _executeSlash(signedDelegation, evidence, collateralGwei);

        // Delete the operator
        delete registrations[registrationRoot];

        // Reward, burn, and return Ether
        _executeSlashingTransfers(operatorWithdrawalAddress, collateralGwei, slashAmountGwei, rewardAmountGwei);

        emit OperatorSlashed(
            registrationRoot, slashAmountGwei, rewardAmountGwei, signedDelegation.delegation.proposerPubKey
        );
    }

    /// @notice Adds collateral to an Operator struct
    /// @dev The function will revert if the operator does not exist or if the collateral amount overflows the `collateralGwei` field.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    function addCollateral(bytes32 registrationRoot) external payable {
        Operator storage operator = registrations[registrationRoot];
        if (operator.collateralGwei == 0) {
            revert NotRegisteredKey();
        }

        if (msg.value / 1 gwei > type(uint56).max) {
            revert CollateralOverflow();
        }

        operator.collateralGwei += uint56(msg.value / 1 gwei);
        emit CollateralAdded(registrationRoot, operator.collateralGwei);
    }

    /**
     *
     *                                Internal Functions                           *
     *
     */

    /// @notice Merkleizes an array of `Registration` structs
    /// @dev Leaves are created by abi-encoding the `Registration` structs, then hashing with keccak256.
    /// @param regs The array of `Registration` structs to merkleize
    /// @return registrationRoot The merkle root of the registration
    function _merkleizeRegistrations(Registration[] calldata regs) internal returns (bytes32 registrationRoot) {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](regs.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = keccak256(abi.encode(regs[i]));
            emit KeyRegistered(i, regs[i], leaves[i]);
        }

        registrationRoot = MerkleTree.generateTree(leaves);
    }

    /// @notice Verifies a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralGwei The collateral amount in GWEI
    function _verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        internal
        view
        returns (uint256 collateralGwei)
    {
        if (MerkleTree.verifyProofCalldata(registrationRoot, leaf, leafIndex, proof)) {
            collateralGwei = registrations[registrationRoot].collateralGwei;
        }
    }

    /// @notice Verifies a delegation was signed by a registered operator's key
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @dev The `signedDelegation.signature` is expected to be the abi-encoded `Delegation` message mixed with the Slasher's `DOMAIN_SEPARATOR`.
    /// @dev The function will revert if the delegation message expired, if the delegation signature is invalid, or if the delegation is not signed by the operator's BLS key.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param signedDelegation The SignedDelegation signed by the operator's BLS key
    /// @return collateralGwei The collateral amount in GWEI
    function _verifyDelegation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation
    ) internal view returns (uint256 collateralGwei) {
        // Reconstruct leaf using pubkey in SignedDelegation to check equivalence
        bytes32 leaf = keccak256(abi.encode(signedDelegation.delegation.proposerPubKey, registrationSignature));

        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);

        if (collateralGwei == 0) {
            revert NotRegisteredKey();
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

    /// @notice Executes the slash function of the Slasher contract and returns the amount of GWEI to be slashed
    /// @dev The function will revert if the `slashAmountGwei` is 0, if the `slashAmountGwei` exceeds the operator's collateral, or if the Slasher.slash() function reverts.
    /// @param signedDelegation The SignedDelegation signed by the operator's BLS key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @param collateralGwei The operator's collateral amount in GWEI
    /// @return slashAmountGwei The amount of GWEI to be slashed
    function _executeSlash(
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence,
        uint256 collateralGwei
    ) internal returns (uint256 slashAmountGwei, uint256 rewardAmountGwei) {
        (slashAmountGwei, rewardAmountGwei) =
            ISlasher(signedDelegation.delegation.slasher).slash(signedDelegation.delegation, evidence);

        if (slashAmountGwei > collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }
    }

    /// @notice Distributes rewards to the challenger, burns the slash amount, and returns any remaining funds to the operator
    /// @dev The function will revert if the transfer to the slasher fails, if the transfer to the operator fails, or if the rewardAmountGwei is less than `MIN_COLLATERAL`.
    /// @param withdrawalAddress The address to return any remaining funds to
    /// @param collateralGwei The operator's collateral amount in GWEI
    /// @param slashAmountGwei The amount of GWEI to be transferred to the caller
    /// @param rewardAmountGwei The amount of GWEI to be transferred to the caller
    function _executeSlashingTransfers(
        address withdrawalAddress,
        uint256 collateralGwei,
        uint256 slashAmountGwei,
        uint256 rewardAmountGwei
    ) internal {
        // Burn the slash amount
        (bool success,) = BURNER_ADDRESS.call{ value: slashAmountGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Transfer to the challenger
        (success,) = msg.sender.call{ value: rewardAmountGwei * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }

        // Return any remaining funds to Operator
        (success,) = withdrawalAddress.call{ value: (collateralGwei - slashAmountGwei - rewardAmountGwei) * 1 gwei }("");
        if (!success) {
            revert EthTransferFailed();
        }
    }

    /// @notice Get the slot number from a given timestamp. Assumes 12 second slot time.
    /// @param _timestamp The timestamp
    /// @return slot The slot number
    function _getSlotFromTimestamp(uint256 _timestamp) internal view returns (uint256 slot) {
        slot = (_timestamp - ETH2_GENESIS_TIMESTAMP) / 12;
    }
}
