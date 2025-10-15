// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/lib/ECDSAUtils.sol";
import "../src/ISlasher.sol";

/// @title ECDSAUtilsTest
/// @notice Comprehensive unit tests for ECDSAUtils
contract ECDSAUtilsTest is Test {
    using ECDSAUtils for *;

    // Test parameters
    bytes32 constant SIGNING_DOMAIN = bytes32(0x6d6d6f43719103511efa4f1362ff2a50996cccf329cc84cb410c5e5c7d351d03);
    bytes32 constant SIGNING_ID = bytes32(0xcb005700fab121c00ccbc94db58c04675b7847c38f9583815139d1d98bea0cb0);
    uint64 constant NONCE = type(uint64).max - 1;
    bytes32 constant CHAIN_ID = bytes32(0xb08b080000000000000000000000000000000000000000000000000000000000);

    // decrypted + decoded from https://github.com/Commit-Boost/commit-boost-client/blob/main/tests/data/keystores/secrets/0xb3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9
    uint256 constant PRIVATE_KEY = 0x0501e85d5bc2e95f70efda47409710a7cf01dd02ff238e3efec679b27331d917;

    function testComputeSigningRoot() public {
        bytes32 messageHash = keccak256("test message");

        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        // Verify the signing root is deterministic
        bytes32 expectedSubTreeRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(messageHash, SIGNING_ID)),
                sha256(abi.encodePacked(ECDSAUtils._toLittleEndian(NONCE), CHAIN_ID))
            )
        );
        bytes32 expectedSigningRoot = sha256(abi.encodePacked(expectedSubTreeRoot, SIGNING_DOMAIN));

        assertEq(signingRoot, expectedSigningRoot, "Signing root computation incorrect");
    }

    function testComputeSigningRootWithDifferentNonce() public {
        bytes32 messageHash = keccak256("test message");

        bytes32 signingRoot1 = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        bytes32 signingRoot2 =
            ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE + 1, CHAIN_ID);

        assertTrue(signingRoot1 != signingRoot2, "Different nonces should produce different signing roots");
    }

    function testComputeSigningRootWithDifferentSigningId() public {
        bytes32 messageHash = keccak256("test message");

        bytes32 signingRoot1 = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        bytes32 signingRoot2 = ECDSAUtils.computeSigningRoot(
            messageHash, SIGNING_DOMAIN, keccak256("different-signing-id"), NONCE, CHAIN_ID
        );

        assertTrue(signingRoot1 != signingRoot2, "Different signing IDs should produce different signing roots");
    }

    function testComputeSigningRootWithDifferentChainId() public {
        bytes32 messageHash = keccak256("test message");

        bytes32 signingRoot1 = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        bytes32 signingRoot2 = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, "0x02");

        assertTrue(signingRoot1 != signingRoot2, "Different chain IDs should produce different signing roots");
    }

    function testSignAndRecover() public {
        bytes32 messageHash = keccak256("test message");

        // Compute signing root
        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        // Sign the message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, signingRoot);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Recover the signer
        address recovered = ECDSAUtils.recover(messageHash, signature, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        assertEq(recovered, vm.addr(PRIVATE_KEY), "Recovered address should match expected address");
    }

    function testRecoverWithInvalidSignature() public {
        bytes32 messageHash = keccak256("test message");

        // Create an invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));

        // This should return a different address or potentially revert
        address recovered =
            ECDSAUtils.recover(messageHash, invalidSignature, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        assertTrue(recovered != vm.addr(PRIVATE_KEY), "Invalid signature should not recover expected address");
    }

    function testRecoverWithWrongNonce() public {
        bytes32 messageHash = keccak256("test message");

        // Sign with one nonce
        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, signingRoot);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Try to recover with different nonce
        address recovered = ECDSAUtils.recover(messageHash, signature, SIGNING_DOMAIN, SIGNING_ID, NONCE + 1, CHAIN_ID);

        assertTrue(recovered != vm.addr(PRIVATE_KEY), "Wrong nonce should not recover expected address");
    }

    function testRecoverWithWrongSigningId() public {
        bytes32 messageHash = keccak256("test message");

        // Sign with one signing ID
        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, signingRoot);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Try to recover with different signing ID
        address recovered =
            ECDSAUtils.recover(messageHash, signature, SIGNING_DOMAIN, keccak256("wrong-signing-id"), NONCE, CHAIN_ID);

        assertTrue(recovered != vm.addr(PRIVATE_KEY), "Wrong signing ID should not recover expected address");
    }

    function testRecoverWithWrongChainId() public {
        bytes32 messageHash = keccak256("test message");

        // Sign with one chain ID
        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, signingRoot);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Try to recover with different chain ID
        address recovered = ECDSAUtils.recover(messageHash, signature, SIGNING_DOMAIN, SIGNING_ID, NONCE, "0x02");

        assertTrue(recovered != vm.addr(PRIVATE_KEY), "Wrong chain ID should not recover expected address");
    }

    function testIntegrationWithCommitment() public {
        // Create a commitment request
        ISlasher.CommitmentRequest memory request =
            ISlasher.CommitmentRequest({ commitmentType: 1, payload: "test payload", slasher: address(0x123) });

        // Compute request hash
        bytes32 requestHash = keccak256(abi.encode(request));

        // Create commitment
        ISlasher.Commitment memory commitment = ISlasher.Commitment({
            commitmentType: 1, payload: "test payload", requestHash: requestHash, slasher: address(0x123)
        });

        // Compute message hash
        bytes32 messageHash = keccak256(abi.encode(commitment));

        // Sign the commitment
        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, signingRoot);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create signed commitment
        ISlasher.SignedCommitment memory signedCommitment = ISlasher.SignedCommitment({
            commitment: commitment, nonce: NONCE, signingId: SIGNING_ID, signature: signature
        });

        // Verify the signature
        address recovered = ECDSAUtils.recover(messageHash, signature, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        assertEq(recovered, vm.addr(PRIVATE_KEY), "Full commitment flow should work correctly");
    }

    function testToLittleEndian() public {
        uint64 testValue = 0x123456789ABCDEF0;
        bytes32 result = ECDSAUtils._toLittleEndian(testValue);

        // Verify little-endian conversion
        bytes memory expected = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            expected[i] = bytes1(uint8(testValue >> (8 * i)));
        }

        assertEq(result, bytes32(expected), "Little-endian conversion incorrect");
    }

    function testToLittleEndianZero() public {
        bytes32 result = ECDSAUtils._toLittleEndian(0);
        assertEq(result, bytes32(0), "Zero should convert to zero");
    }

    function testToLittleEndianMax() public {
        bytes32 result = ECDSAUtils._toLittleEndian(type(uint64).max);
        assertTrue(result != bytes32(0), "Max value should not be zero");
    }

    function testValidateRustCommitment() public {
        ISlasher.CommitmentRequest memory commitmentRequest = ISlasher.CommitmentRequest({
            commitmentType: 1, payload: "", slasher: address(0x1111111111111111111111111111111111111111)
        });

        ISlasher.Commitment memory commitment = ISlasher.Commitment({
            commitmentType: 1,
            payload: commitmentRequest.payload,
            requestHash: keccak256(abi.encode(commitmentRequest)),
            slasher: commitmentRequest.slasher
        });

        // 0xded4394f844c5beaa81ce97f66016bb248871966d82bb8379d95ca78184dd650
        bytes32 messageHash = keccak256(abi.encode(commitment));

        // 0x80575c16b5bcddf841dd3f51b93cc175554e03555479ee4b6e3363a8fff432b9
        bytes32 signingRoot = ECDSAUtils.computeSigningRoot(messageHash, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, signingRoot);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Generated from Rust
        bytes memory expected =
            hex"22cd56d133231753fc522d2dbc7bf32357230c07cd791632536945b566dd58e442e73a48e7c7a896229b027d3833e455a20d452bd204ead62a09bfd270cae9ee1c";

        assert(keccak256(signature) == keccak256(expected));

        assert(
            ECDSAUtils.recover(messageHash, signature, SIGNING_DOMAIN, SIGNING_ID, NONCE, CHAIN_ID)
                == vm.addr(PRIVATE_KEY)
        );
    }
}
