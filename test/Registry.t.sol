// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import { BLS } from "../src/lib/BLS.sol";
import {
    UnitTestHelper, ReentrantRegistrationContract, ReentrantSlashableRegistrationContract
} from "./UnitTestHelper.sol";

contract RegistryTest is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(alice, 100 ether); // Give alice some ETH
        vm.deal(bob, 100 ether); // Give bob some ETH
    }

    function test_register() public {
        uint256 collateral = registry.MIN_COLLATERAL();
        basicRegistration(SECRET_KEY_1, collateral, alice);
    }

    function test_register_insufficientCollateral() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        vm.expectRevert(IRegistry.InsufficientCollateral.selector);
        registry.register{ value: collateral - 1 }(registrations, alice, unregistrationDelay);
    }

    function test_register_unregistrationDelayTooShort() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay // delay that is signed by validator key
        );

        vm.expectRevert(IRegistry.UnregistrationDelayTooShort.selector);
        registry.register{ value: collateral }(
            registrations,
            alice,
            unregistrationDelay - 1 // submit shorter delay than the one signed by validator key
        );
    }

    function test_register_OperatorAlreadyRegistered() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        // Attempt duplicate registration
        vm.expectRevert(IRegistry.OperatorAlreadyRegistered.selector);
        registry.register{ value: collateral }(registrations, alice, unregistrationDelay);
    }

    function test_verifyMerkleProofHeight1() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 gotCollateral = registry.verifyMerkleProof(
            registrationRoot,
            leaves[0],
            proof,
            0 // leafIndex
        );
        assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
    }

    function test_slashRegistrationHeight1_DifferentUnregDelay() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay // delay that is signed by validator key
        );

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            alice,
            unregistrationDelay + 1 // submit different delay
        );

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay + 1
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.prank(bob);
        uint256 slashedCollateralWei = registry.slashRegistration(registrationRoot, registrations[0], proof, 0);
        assertEq(slashedCollateralWei, collateral, "Wrong slashedCollateralWei amount");

        _verifySlashingBalances(
            bob, alice, slashedCollateralWei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
        );

        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);
    }

    function test_slashRegistrationHeight1_DifferentWithdrawalAddress() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice, // withdrawal that is signed by validator key
            unregistrationDelay
        );

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            bob, // Bob tries to frontrun alice by setting his address as withdrawal address
            unregistrationDelay
        );

        _assertRegistration(
            registrationRoot,
            bob, // confirm bob's address is what was registered
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // alice is the challenger
        vm.prank(alice);
        uint256 slashedCollateralWei = registry.slashRegistration(
            registrationRoot,
            registrations[0],
            proof,
            0 // leafIndex
        );

        _verifySlashingBalances(
            alice, bob, slashedCollateralWei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
        );

        // ensure operator was deleted
        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);
    }

    function test_verifyMerkleProofHeight2() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);

        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_2, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test first proof path
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[0], proof, leafIndex);
        assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");

        // Test second proof path
        leafIndex = 1;
        proof = MerkleTree.generateProof(leaves, leafIndex);
        gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[1], proof, leafIndex);
        assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
    }

    function test_slashRegistrationHeight2_DifferentUnregDelay() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);
        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_2, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            alice,
            unregistrationDelay + 1 // submit different delay than the one signed by validator key
        );

        console.log("registrationRoot");
        console.logBytes32(registrationRoot);

        // Verify initial registration state
        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay + 1 // confirm different delay
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.prank(bob);
        uint256 slashedCollateralWei = registry.slashRegistration(registrationRoot, registrations[0], proof, leafIndex);

        _verifySlashingBalances(
            bob, alice, slashedCollateralWei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
        );
    }

    function test_slashRegistrationHeight2_DifferentWithdrawalAddress() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);
        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_2, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            bob, // Bob tries to frontrun alice by setting his address as withdrawal address
            unregistrationDelay
        );

        // Verify initial registration state
        _assertRegistration(
            registrationRoot,
            bob,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        // Create proof for alice's registration
        bytes32[] memory leaves = _hashToLeaves(registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.prank(alice);
        uint256 slashedCollateralWei = registry.slashRegistration(registrationRoot, registrations[0], proof, leafIndex);

        _verifySlashingBalances(
            alice, bob, slashedCollateralWei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
        );
    }

    function test_verifyMerkleProofHeight3() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](3); // will be padded to 4

        registrations[0] = _createRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_1 + 1, alice, unregistrationDelay);

        registrations[2] = _createRegistration(SECRET_KEY_1 + 2, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[i], proof, i);
            assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
        }
    }

    function test_fuzzRegister(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, alice, unregistrationDelay);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[i], proof, i);
            assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
        }
    }

    function test_slashRegistrationFuzz_DifferentUnregDelay(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, alice, unregistrationDelay);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            alice,
            unregistrationDelay + 1 // submit different delay than the one signed by validator keys
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            vm.prank(bob);
            uint256 slashedCollateralWei = registry.slashRegistration(registrationRoot, registrations[i], proof, i);
            _verifySlashingBalances(
                bob, alice, slashedCollateralWei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
            );

            _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);

            // Re-register to reset the state
            registrationRoot = registry.register{ value: collateral }(
                registrations,
                alice,
                unregistrationDelay + 1 // submit different delay than the one signed by validator keys
            );

            // update balances
            bobBalanceBefore = bob.balance;
            aliceBalanceBefore = alice.balance;
            urcBalanceBefore = address(registry).balance;
        }
    }

    function test_slashRegistrationFuzz_DifferentWithdrawalAddress(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, alice, unregistrationDelay);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            bob, // submit different withdrawal address than the one signed by validator keys
            unregistrationDelay
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            vm.prank(bob);
            uint256 slashedCollateralWei = registry.slashRegistration(registrationRoot, registrations[i], proof, i);
            _verifySlashingBalances(
                bob, alice, slashedCollateralWei, collateral, bobBalanceBefore, aliceBalanceBefore, urcBalanceBefore
            );

            _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);

            // Re-register to reset the state
            registrationRoot = registry.register{ value: collateral }(
                registrations,
                bob, // submit different withdrawal address than the one signed by validator keys
                unregistrationDelay
            );

            // update balances
            bobBalanceBefore = bob.balance;
            aliceBalanceBefore = alice.balance;
            urcBalanceBefore = address(registry).balance;
        }
    }

    function test_unregister() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        vm.prank(alice);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorUnregistered(registrationRoot, uint32(block.number));
        registry.unregister(registrationRoot);

        (,, uint32 registeredAt, uint32 unregisteredAt,) = registry.registrations(registrationRoot);
        assertEq(unregisteredAt, uint32(block.number), "Wrong unregistration block");
        assertEq(registeredAt, uint32(block.number), "Wrong registration block"); // Should remain unchanged
    }

    function test_unregister_wrongOperator() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        // Bob tries to unregister Alice's registration
        vm.prank(bob);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.unregister(registrationRoot);
    }

    function test_unregister_alreadyUnregistered() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        vm.prank(alice);
        registry.unregister(registrationRoot);

        // Try to unregister again
        vm.prank(alice);
        vm.expectRevert(IRegistry.AlreadyUnregistered.selector);
        registry.unregister(registrationRoot);
    }

    function test_claimCollateral() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        vm.prank(alice);
        registry.unregister(registrationRoot);

        // Wait for unregistration delay
        vm.roll(block.number + unregistrationDelay);

        uint256 balanceBefore = alice.balance;

        vm.prank(alice);
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(registrationRoot, uint256(collateral / 1 gwei));
        registry.claimCollateral(registrationRoot);

        assertEq(alice.balance, balanceBefore + collateral, "Collateral not returned");

        // Verify registration was deleted
        (address withdrawalAddress,,,,) = registry.registrations(registrationRoot);
        assertEq(withdrawalAddress, address(0), "Registration not deleted");
    }

    function test_claimCollateral_notUnregistered() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        // Try to claim without unregistering first
        vm.prank(alice);
        vm.expectRevert(IRegistry.NotUnregistered.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_delayNotMet() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        vm.prank(alice);
        registry.unregister(registrationRoot);

        // Try to claim before delay has passed
        vm.roll(block.number + unregistrationDelay - 1);

        vm.prank(alice);
        vm.expectRevert(IRegistry.UnregistrationDelayNotMet.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_alreadyClaimed() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        vm.prank(alice);
        registry.unregister(registrationRoot);

        vm.roll(block.number + unregistrationDelay);

        vm.prank(alice);
        registry.claimCollateral(registrationRoot);

        // Try to claim again
        vm.prank(alice);
        vm.expectRevert(IRegistry.NoCollateralToClaim.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_addCollateral(uint56 addAmount) public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        vm.assume((addAmount + collateral) / 1 gwei < uint256(2 ** 56));

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        uint256 expectedCollateralGwei = (collateral + addAmount) / 1 gwei;
        vm.deal(alice, addAmount);
        vm.prank(alice);

        vm.expectEmit(address(registry));
        emit IRegistry.CollateralAdded(registrationRoot, expectedCollateralGwei);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        (, uint56 collateralGwei,,,) = registry.registrations(registrationRoot);
        assertEq(collateralGwei, expectedCollateralGwei, "Collateral not added");
    }

    function test_addCollateral_overflow() public {
        (uint16 unregistrationDelay, uint256 collateral) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, alice, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, alice, unregistrationDelay);

        uint256 addAmount = 2 ** 56 * 1 gwei; // overflow uint56
        vm.deal(alice, addAmount);
        vm.prank(alice);

        vm.expectRevert(IRegistry.CollateralOverflow.selector);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        (, uint56 collateralGwei,,,) = registry.registrations(registrationRoot);
        assertEq(collateralGwei, uint56(collateral / 1 gwei), "Collateral should not be changed");
    }

    function test_addCollateral_notRegistered() public {
        bytes32 registrationRoot = bytes32(uint256(0));
        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.addCollateral{ value: 1 gwei }(registrationRoot);
    }

    // For setup we register() -> unregister() -> claimCollateral()
    // The registration's withdrawal address is the reentrant contract
    // Claiming collateral causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral()
    // The test succeeds because the reentract contract catches the errors
    function test_reentrantClaimCollateral() public {
        ReentrantRegistrationContract reentrantContract = new ReentrantRegistrationContract(address(registry));
        vm.deal(address(reentrantContract), 1000 ether);

        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, address(reentrantContract), unregistrationDelay);

        reentrantContract.register(registrations, unregistrationDelay);

        // pretend to unregister
        reentrantContract.unregister();

        // wait for unregistration delay
        vm.roll(block.number + unregistrationDelay);

        uint256 balanceBefore = address(reentrantContract).balance;

        vm.prank(address(reentrantContract));
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(reentrantContract.registrationRoot(), uint256(1 ether / 1 gwei));

        // initiate reentrancy
        reentrantContract.claimCollateral();

        assertEq(address(reentrantContract).balance, balanceBefore + 1 ether, "Collateral not returned");

        // Verify registration was deleted
        (address withdrawalAddress,,,,) = registry.registrations(reentrantContract.registrationRoot());
        assertEq(withdrawalAddress, address(0), "Registration not deleted");
    }

    // For setup we register() -> slashRegistration()
    // The registration's withdrawal address is the reentrant contract
    // Triggering a slash causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral(), slashRegistration()
    // Finally it re-registers and the registration root should not change
    // The test succeeds because the reentract contract catches the errors
    function test_reentrantSlashRegistration() public {
        ReentrantSlashableRegistrationContract reentrantContract =
            new ReentrantSlashableRegistrationContract(address(registry));
        vm.deal(address(reentrantContract), 1000 ether);

        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, bob, unregistrationDelay);

        // set operator's withdrawal address to reentrantContract
        reentrantContract.register(registrations, unregistrationDelay);

        _assertRegistration(
            reentrantContract.registrationRoot(),
            address(reentrantContract),
            uint56(1 ether / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // bob can slash the registration
        vm.startPrank(bob);
        uint256 slashedCollateralWei = registry.slashRegistration(
            reentrantContract.registrationRoot(),
            registrations[0],
            proof,
            0 // leafIndex
        );
    }
}
