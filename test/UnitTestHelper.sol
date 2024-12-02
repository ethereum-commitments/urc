// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import "../src/ISlasher.sol";
import { BLS } from "../src/lib/BLS.sol";

contract UnitTestHelper is Test {
    using BLS for *;

    Registry registry;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    // Preset secret keys for deterministic testing
    uint256 constant SECRET_KEY_1 = 12345;
    uint256 constant SECRET_KEY_2 = 67890;

    /// @dev Helper to create a BLS signature for a registration
    function _registrationSignature(uint256 secretKey, address withdrawalAddress, uint16 unregistrationDelay)
        internal
        view
        returns (BLS.G2Point memory)
    {
        bytes memory message = abi.encodePacked(withdrawalAddress, unregistrationDelay);
        return BLS.sign(message, secretKey, registry.DOMAIN_SEPARATOR());
    }

    /// @dev Creates a Registration struct with a real BLS keypair
    function _createRegistration(uint256 secretKey, address withdrawalAddress, uint16 unregistrationDelay)
        internal
        view
        returns (IRegistry.Registration memory)
    {
        BLS.G1Point memory pubkey = BLS.toPublicKey(secretKey);
        BLS.G2Point memory signature = _registrationSignature(secretKey, withdrawalAddress, unregistrationDelay);

        return IRegistry.Registration({ pubkey: pubkey, signature: signature });
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

        assertEq(withdrawalAddress, expectedWithdrawalAddress, "Wrong withdrawal address");
        assertEq(collateral, expectedCollateral, "Wrong collateral amount");
        assertEq(registeredAt, expectedRegisteredAt, "Wrong registration block");
        assertEq(unregisteredAt, expectedUnregisteredAt, "Wrong unregistration block");
        assertEq(unregistrationDelay, expectedUnregistrationDelay, "Wrong unregistration delay");
    }

    function _hashToLeaves(IRegistry.Registration[] memory registrations) internal pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](registrations.length);
        for (uint256 i = 0; i < registrations.length; i++) {
            leaves[i] = keccak256(abi.encode(registrations[i]));
        }
        return leaves;
    }

    // New helper functions
    function _setupBasicRegistrationParams() internal view returns (uint16 unregistrationDelay, uint256 collateral) {
        unregistrationDelay = uint16(registry.MIN_UNREGISTRATION_DELAY());
        collateral = registry.MIN_COLLATERAL();
    }

    function _setupSingleRegistration(uint256 secretKey, address withdrawalAddr, uint16 unregistrationDelay)
        internal
        view
        returns (IRegistry.Registration[] memory)
    {
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);
        registrations[0] = _createRegistration(secretKey, withdrawalAddr, unregistrationDelay);
        return registrations;
    }

    function _verifySlashingBalances(
        address challenger,
        address operator,
        uint256 slashedAmount,
        uint256 totalCollateral,
        uint256 challengerBalanceBefore,
        uint256 operatorBalanceBefore,
        uint256 urcBalanceBefore
    ) internal view {
        assertEq(challenger.balance, challengerBalanceBefore + slashedAmount, "challenger didn't receive reward");
        assertEq(
            operator.balance,
            operatorBalanceBefore + totalCollateral - slashedAmount,
            "operator didn't receive remaining funds"
        );
        assertEq(address(registry).balance, urcBalanceBefore - totalCollateral, "urc balance incorrect");
    }

    function basicRegistration(uint256 secretKey, uint256 collateral, address withdrawalAddress)
        public
        returns (bytes32 registrationRoot, IRegistry.Registration[] memory registrations)
    {
        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();

        registrations = _setupSingleRegistration(secretKey, withdrawalAddress, unregistrationDelay);

        registrationRoot = registry.register{ value: collateral }(registrations, withdrawalAddress, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            withdrawalAddress,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            0,
            unregistrationDelay
        );
    }

    function signDelegation(uint256 secretKey, ISlasher.Delegation memory delegation, bytes memory domainSeparator)
        internal
        view
        returns (ISlasher.SignedDelegation memory)
    {
        BLS.G2Point memory signature = BLS.sign(abi.encode(delegation), secretKey, domainSeparator);
        return ISlasher.SignedDelegation({ delegation: delegation, signature: signature });
    }

    struct RegisterAndDelegateParams {
        uint256 validatorSecretKey;
        uint256 collateral;
        address withdrawalAddress;
        uint256 delegateSecretKey;
        address slasher;
        bytes domainSeparator;
        bytes metadata;
    }

    struct RegisterAndDelegateResult {
        bytes32 registrationRoot;
        IRegistry.Registration[] registrations;
        ISlasher.SignedDelegation signedDelegation;
    }

    function registerAndDelegate(RegisterAndDelegateParams memory params)
        public
        returns (RegisterAndDelegateResult memory result)
    {
        // Single registration
        (result.registrationRoot, result.registrations) =
            basicRegistration(params.validatorSecretKey, params.collateral, params.withdrawalAddress);

        // Sign delegation
        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            validatorPubKey: BLS.toPublicKey(params.validatorSecretKey),
            delegatePubKey: BLS.toPublicKey(params.delegateSecretKey),
            slasher: params.slasher,
            metadata: params.metadata
        });

        result.signedDelegation = signDelegation(params.validatorSecretKey, delegation, params.domainSeparator);
    }
}
