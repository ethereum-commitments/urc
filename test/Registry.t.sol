// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import {BLS} from "../src/lib/BLS.sol";

contract RegistryTest is Test {
    using BLS for *;

    Registry registry;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    // Preset secret keys for deterministic testing
    uint256 constant SECRET_KEY_1 = 12345;
    uint256 constant SECRET_KEY_2 = 67890;

    function setUp() public {
        registry = new Registry();
        vm.deal(alice, 100 ether); // Give alice some ETH
        vm.deal(bob, 100 ether); // Give bob some ETH
    }

    /// @dev Helper to create a BLS signature for a registration
    function _registrationSignature(
        uint256 secretKey,
        address withdrawalAddress,
        uint16 unregistrationDelay
    ) internal view returns (BLS.G2Point memory) {
        bytes memory message = abi.encodePacked(
            withdrawalAddress,
            unregistrationDelay
        );
        return BLS.sign(message, secretKey, registry.DOMAIN_SEPARATOR());
    }

    /// @dev Creates a Registration struct with a real BLS keypair
    function _createRegistration(
        uint256 secretKey,
        address withdrawalAddress,
        uint16 unregistrationDelay
    ) internal view returns (IRegistry.Registration memory) {
        BLS.G1Point memory pubkey = BLS.toPublicKey(secretKey);
        BLS.G2Point memory signature = _registrationSignature(
            secretKey,
            withdrawalAddress,
            unregistrationDelay
        );

        return IRegistry.Registration({pubkey: pubkey, signature: signature});
    }

    /// @dev Helper to verify operator data matches expected values
    function _assertRegistration(
        bytes32 registrationRoot,
        address expectedWithdrawalAddress,
        uint56 expectedCollateral,
        uint32 expectedRegisteredAt,
        uint32 expectedUnregisteredAt,
        uint16 expectedUnregistrationDelay
    ) internal view {
        (
            address withdrawalAddress,
            uint56 collateral,
            uint32 registeredAt,
            uint32 unregisteredAt,
            uint16 unregistrationDelay
        ) = registry.registrations(registrationRoot);

        assertEq(
            withdrawalAddress,
            expectedWithdrawalAddress,
            "Wrong withdrawal address"
        );
        assertEq(collateral, expectedCollateral, "Wrong collateral amount");
        assertEq(
            registeredAt,
            expectedRegisteredAt,
            "Wrong registration block"
        );
        assertEq(
            unregisteredAt,
            expectedUnregisteredAt,
            "Wrong unregistration block"
        );
        assertEq(
            unregistrationDelay,
            expectedUnregistrationDelay,
            "Wrong unregistration delay"
        );
    }

    function test_register() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay
        );

        bytes32 registrationRoot = registry.register{
            value: registry.MIN_COLLATERAL()
        }(registrations, alice, unregistrationDelay, treeHight);

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(registry.MIN_COLLATERAL() / 1 gwei),
            uint32(block.number),
            0,
            unregistrationDelay
        );
    }

    function test_register_insufficientCollateral() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay
        );

        uint256 collateral = registry.MIN_COLLATERAL() - 1 wei;

        // vm.expectRevert(IRegistry.InsufficientCollateral.selector);
        vm.expectRevert(
            IRegistry.InsufficientCollateral.selector,
            address(registry)
        );
        registry.register{value: collateral}(
            registrations,
            alice,
            unregistrationDelay,
            treeHight
        );
    }

    function testFails_register_unregistrationDelayTooShort() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS() - 1);
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay
        );

        // vm.expectRevert(IRegistry.UnregistrationDelayTooShort.selector, address(registry)); //todo this custom error is not being detected
        registry.register{value: registry.MIN_COLLATERAL()}(
            registrations,
            alice,
            unregistrationDelay,
            treeHight
        );
    }

    function testFails_register_treeHeightTooSmall() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](2);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay
        );

        registrations[1] = _createRegistration(
            SECRET_KEY_2,
            bob,
            unregistrationDelay
        );

        // vm.expectRevert(IRegistry.TreeHeightTooSmall.selector); //todo this custom error is not being detected
        registry.register{value: registry.MIN_COLLATERAL()}(
            registrations,
            alice,
            unregistrationDelay,
            treeHight
        );
    }

    function testFails_register_OperatorAlreadyRegistered() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay
        );

        bytes32 registrationRoot = registry.register{
            value: registry.MIN_COLLATERAL()
        }(registrations, alice, unregistrationDelay, treeHight);

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(registry.MIN_COLLATERAL() / 1 gwei),
            uint32(block.number),
            0,
            unregistrationDelay
        );

        // Attempt duplicate registration
        // vm.expectRevert(IRegistry.OperatorAlreadyRegistered.selector); //todo this custom error is not being detected
        registry.register{value: registry.MIN_COLLATERAL()}(
            registrations,
            alice,
            unregistrationDelay,
            treeHight
        );
    }

    function test_verifyMerkleProofHeight1() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 collateral = registry.MIN_COLLATERAL();
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay
        );

        bytes32 registrationRoot = registry.register{value: collateral}(
            registrations,
            alice,
            unregistrationDelay,
            treeHight
        );

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            0,
            unregistrationDelay
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = registrationRoot;
        uint256 gotCollateral = registry.verifyMerkleProof(
            registrationRoot,
            registrations[0],
            proof,
            0 // leafIndex
        );
        assertEq(
            gotCollateral,
            uint56(collateral / 1 gwei),
            "Wrong collateral amount"
        );
    }

    function test_slashRegistrationHeight1_DifferentUnregDelay() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 collateral = registry.MIN_COLLATERAL();
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice,
            unregistrationDelay // delay that is signed by validator key
        );

        bytes32 registrationRoot = registry.register{value: collateral}(
            registrations,
            alice,
            unregistrationDelay + 1, // submit a different delay to URC
            treeHight
        );

        _assertRegistration(
            registrationRoot,
            alice,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            0,
            unregistrationDelay + 1 // confirm what was submitted is saved
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = registrationRoot;

        uint256 bobBalanceBefore = bob.balance;
        uint256 aliceBalanceBefore = alice.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // bob is the challenger
        vm.prank(bob);
        uint256 slashedCollateralWei = registry.slashRegistration(
            registrationRoot,
            registrations[0],
            proof,
            0 // leafIndex
        );
        assertEq(
            slashedCollateralWei,
            collateral,
            "Wrong slashedCollateralWei amount"
        );

        assertEq(
            bob.balance,
            bobBalanceBefore + slashedCollateralWei,
            "challenger didn't receive reward"
        );

        assertEq(
            alice.balance,
            aliceBalanceBefore + collateral - slashedCollateralWei,
            "operator didn't receive remaining funds"
        );

        assertEq(
            address(registry).balance,
            urcBalanceBefore - collateral,
            "urc balance incorrect"
        );

        // ensure operator was deleted
        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);
    }

    function test_slashRegistrationHeight1_DifferentWithdrawalAddress() public {
        uint16 unregistrationDelay = uint16(registry.TWO_EPOCHS());
        uint256 collateral = registry.MIN_COLLATERAL();
        uint256 treeHight = 1;

        IRegistry.Registration[]
            memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            alice, // withdrawal that is signed by validator key
            unregistrationDelay
        );

        bytes32 registrationRoot = registry.register{value: collateral}(
            registrations,
            bob, // Bob tries to frontrun alice
            unregistrationDelay,
            treeHight
        );

        _assertRegistration(
            registrationRoot,
            bob, // confirm bob's address is what was registered
            uint56(collateral / 1 gwei),
            uint32(block.number),
            0,
            unregistrationDelay
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = registrationRoot;

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

        assertEq(
            slashedCollateralWei,
            collateral,
            "Wrong slashedCollateralWei amount"
        );

        assertEq(
            alice.balance,
            aliceBalanceBefore + slashedCollateralWei,
            "challenger didn't receive reward"
        );

        assertEq(
            bob.balance,
            bobBalanceBefore + collateral - slashedCollateralWei,
            "operator didn't receive remaining funds"
        );

        assertEq(
            address(registry).balance,
            urcBalanceBefore - collateral,
            "urc balance incorrect"
        );

        // ensure operator was deleted
        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);
    }
}
