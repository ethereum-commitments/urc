// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import { BLS } from "../src/lib/BLS.sol";
import { MerkleTree } from "../src/lib/MerkleTree.sol";
import "../src/Registry.sol";
import { IRegistry } from "../src/IRegistry.sol";
import { ISlasher } from "../src/ISlasher.sol";
import { UnitTestHelper } from "./UnitTestHelper.sol";

contract DummySlasher is ISlasher {
    uint256 public SLASH_AMOUNT_GWEI;

    constructor(uint256 slashAmountGwei) {
        SLASH_AMOUNT_GWEI = slashAmountGwei;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes memory) {
        return bytes("DUMMY-SLASHER-DOMAIN-SEPARATOR");
    }

    function slash(ISlasher.Delegation calldata delegation, bytes calldata evidence)
        external
        returns (uint256 slashAmountGwei)
    {
        slashAmountGwei = SLASH_AMOUNT_GWEI;
    }
}

contract DummySlasherTest is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;

    function setUp() public {
        registry = new Registry();
        vm.deal(alice, 100 ether); // Give alice some ETH
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
    }

    function testDummySlasherUpdatesRegistry() public {
        uint256 slashAmountGwei = 42;
        dummySlasher = new DummySlasher(slashAmountGwei);

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // slash from a different address
        vm.prank(bob);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            result.registrationRoot, slashAmountGwei, result.signedDelegation.delegation.validatorPubKey
        );
        emit IRegistry.OperatorDeleted(result.registrationRoot);
        uint256 gotSlashAmountGwei = registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );
        assertEq(slashAmountGwei, gotSlashAmountGwei, "Slash amount incorrect");

        // verify balances updated correctly
        _verifySlashingBalances(
            bob, alice, slashAmountGwei * 1 gwei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
        );

        // Verify operator was deleted
        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0);
    }

    function testRevertFraudProofWindowNotMet() public {
        uint256 slashAmountGwei = 42;
        dummySlasher = new DummySlasher(slashAmountGwei);

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        bytes memory evidence = "";

        // Try to slash before fraud proof window expires
        vm.expectRevert(IRegistry.FraudProofWindowNotMet.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );
    }

    function testRevertNotRegisteredValidator() public {
        uint256 slashAmountGwei = 42;
        dummySlasher = new DummySlasher(slashAmountGwei);

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create invalid proof
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = bytes32(0);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.NotRegisteredValidator.selector);
        registry.slashCommitment(
            result.registrationRoot, result.registrations[0].signature, invalidProof, 0, result.signedDelegation, ""
        );
    }

    function testRevertDelegationSignatureInvalid() public {
        uint256 slashAmountGwei = 42;
        dummySlasher = new DummySlasher(slashAmountGwei);

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Sign delegation with different secret key
        ISlasher.SignedDelegation memory badSignedDelegation =
            signDelegation(SECRET_KEY_2, result.signedDelegation.delegation, params.domainSeparator);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.DelegationSignatureInvalid.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            badSignedDelegation,
            ""
        );
    }

    function testRevertNoCollateralSlashed() public {
        // Create DummySlasher that returns 0 slash amount
        dummySlasher = new DummySlasher(0);

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.NoCollateralSlashed.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            ""
        );
    }

    function testRevertSlashAmountExceedsCollateral() public {
        // Create DummySlasher that returns more than collateral
        uint256 excessiveSlashAmount = collateral / 1 gwei + 1;
        dummySlasher = new DummySlasher(excessiveSlashAmount);

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.SlashAmountExceedsCollateral.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            ""
        );
    }

    function testRevertEthTransferFailed() public {
        uint256 slashAmountGwei = 42;
        dummySlasher = new DummySlasher(slashAmountGwei);

        // Deploy a contract that rejects ETH transfers
        RejectEther rejectEther = new RejectEther();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            validatorSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: address(rejectEther),
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: ""
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.EthTransferFailed.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            ""
        );
    }
}

// Helper contract that rejects ETH transfers
contract RejectEther {
    receive() external payable {
        revert("No ETH accepted");
    }
}
