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
    uint256 public SLASH_AMOUNT_GWEI = 42;
    uint256 public REWARD_AMOUNT_GWEI = 10;

    function DOMAIN_SEPARATOR() external view returns (bytes memory) {
        return bytes("DUMMY-SLASHER-DOMAIN-SEPARATOR");
    }

    function slash(ISlasher.Delegation calldata delegation, bytes calldata evidence)
        external
        returns (uint256 slashAmountGwei, uint256 rewardAmountGwei)
    {
        slashAmountGwei = SLASH_AMOUNT_GWEI;
        rewardAmountGwei = REWARD_AMOUNT_GWEI;
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
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
            result.registrationRoot, dummySlasher.SLASH_AMOUNT_GWEI(), dummySlasher.REWARD_AMOUNT_GWEI(), result.signedDelegation.delegation.proposerPubKey
        );
        (uint256 gotSlashAmountGwei, uint256 gotRewardAmountGwei) = registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );
        assertEq(dummySlasher.SLASH_AMOUNT_GWEI(), gotSlashAmountGwei, "Slash amount incorrect");

        // verify balances updated correctly
        _verifySlashingBalances(
            bob, alice, dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
        );

        // Verify operator was deleted
        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0);
    }

    function testRevertFraudProofWindowNotMet() public {
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create invalid proof
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = bytes32(0);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.slashCommitment(
            result.registrationRoot, result.registrations[0].signature, invalidProof, 0, result.signedDelegation, ""
        );
    }

    function testRevertDelegationSignatureInvalid() public {
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
        dummySlasher = new DummySlasher();

        // Deploy a contract that rejects ETH transfers
        RejectEther rejectEther = new RejectEther();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: address(rejectEther),
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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

    function testRevertDelegationExpired() public {
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: alice,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(block.timestamp - 1) // Delegation expired
         });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);
        vm.warp(block.number * 12);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.prank(bob);
        vm.expectRevert(IRegistry.DelegationExpired.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            ""
        );
    }

    // For setup we register() and delegate to the dummy slasher
    // The registration's withdrawal address is the reentrant contract
    // Triggering a slash causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral(), slashCommitment()
    // The test succeeds because the reentract contract catches the errors
    function testSlashCommitmentIsReentrantProtected() public {
        dummySlasher = new DummySlasher();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: address(0),
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
        });

        (RegisterAndDelegateResult memory result, address reentrantContract) = registerAndDelegateReentrant(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        uint256 bobBalanceBefore = bob.balance;
        uint256 balanceBefore = address(reentrantContract).balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // slash from a different address
        vm.startPrank(bob);
        // vm.prank(bob);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            result.registrationRoot, dummySlasher.SLASH_AMOUNT_GWEI(), dummySlasher.REWARD_AMOUNT_GWEI(), result.signedDelegation.delegation.proposerPubKey
        );
        (uint256 gotSlashAmountGwei, uint256 gotRewardAmountGwei) = registry.slashCommitment(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            evidence
        );
        assertEq(dummySlasher.SLASH_AMOUNT_GWEI(), gotSlashAmountGwei, "Slash amount incorrect");

        // verify balances updated correctly
        _verifySlashingBalances(
            bob,
            address(reentrantContract),
            dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei,
            1 ether,
            bobBalanceBefore,
            balanceBefore,
            urcBalanceBefore
        );

        // Verify operator was deleted
        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0);
    }
}

// Helper contract that rejects ETH transfers
contract RejectEther {
    receive() external payable {
        revert("No ETH accepted");
    }
}
