// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

import { Test, console } from "forge-std/Test.sol";
import { BLSUtils } from "../src/lib/BLSUtils.sol";
import { BLS } from "solady/utils/ext/ithaca/BLS.sol";
import { ISlasher } from "../src/ISlasher.sol";

/// @notice A simple test demonstrating BLS signature verification.
contract BLSTest is Test {
    /// @dev Demonstrates the signing and verification of a message.
    function testSignAndVerify(
        uint256 privateKey,
        bytes32 messageHash,
        bytes32 signingDomain,
        bytes32 signingId,
        bytes32 nonce,
        bytes32 chainId
    ) public view {
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(privateKey);
        BLS.G2Point memory signature = BLSUtils.sign(privateKey, messageHash, signingDomain, signingId, nonce, chainId);
        assert(BLSUtils.verify(messageHash, signature, publicKey, signingDomain, signingId, nonce, chainId));
    }

    /// @dev Demonstrates the aggregation and verification of two signatures.
    function testAggregation(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes32 messageHash,
        bytes32 signingDomain,
        bytes32 signingId,
        bytes32 nonce,
        bytes32 chainId
    ) public view {
        // public keys
        BLS.G1Point memory pk1 = BLSUtils.toPublicKey(privateKey1);
        BLS.G1Point memory pk2 = BLSUtils.toPublicKey(privateKey2);

        // signatures
        BLS.G2Point memory sig1 = BLSUtils.sign(privateKey1, messageHash, signingDomain, signingId, nonce, chainId);
        BLS.G2Point memory sig2 = BLSUtils.sign(privateKey2, messageHash, signingDomain, signingId, nonce, chainId);

        // aggregated signature
        BLS.G2Point memory sig = BLS.add(sig1, sig2);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](3);
        g1Points[0] = BLSUtils.NEGATED_G1_GENERATOR();
        g1Points[1] = pk1;
        g1Points[2] = pk2;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](3);
        g2Points[0] = sig;
        g2Points[1] = BLSUtils.computeSigningRoot(messageHash, signingDomain, signingId, nonce, chainId);
        g2Points[2] = BLSUtils.computeSigningRoot(messageHash, signingDomain, signingId, nonce, chainId);

        assert(BLS.pairing(g1Points, g2Points));
    }

    function testComputeSigningRoot(
        bytes32 messageHash,
        bytes32 signingDomain,
        bytes32 signingId,
        bytes32 nonce,
        bytes32 chainId
    ) public view {
        BLS.G2Point memory signingRoot =
            BLSUtils.computeSigningRoot(messageHash, signingDomain, signingId, nonce, chainId);

        // Compute expected signing root manually
        bytes32 subTreeRoot = sha256(
            abi.encodePacked(sha256(abi.encodePacked(messageHash, signingId)), sha256(abi.encodePacked(nonce, chainId)))
        );
        bytes32 expectedSigningRoot = sha256(abi.encodePacked(subTreeRoot, signingDomain));
        BLS.G2Point memory expected = BLS.hashToG2(abi.encodePacked(expectedSigningRoot));

        assert(
            signingRoot.x_c0_a == expected.x_c0_a && signingRoot.x_c0_b == expected.x_c0_b
                && signingRoot.x_c1_a == expected.x_c1_a && signingRoot.x_c1_b == expected.x_c1_b
                && signingRoot.y_c0_a == expected.y_c0_a && signingRoot.y_c0_b == expected.y_c0_b
                && signingRoot.y_c1_a == expected.y_c1_a && signingRoot.y_c1_b == expected.y_c1_b
        );
    }

    function testToPublicKey() public view {
        uint256 privateKey = 12356;

        // uncompressed public key
        BLS.G1Point memory expected = BLS.G1Point(
            BLSUtils._u(12115118667309283734868789696201968385),
            BLSUtils._u(102796267992108309135721548586500937750960769774310798537421982072779087272819),
            BLSUtils._u(15699442850880472822588013448545136667),
            BLSUtils._u(697141831937854224682724016220779412457574525815594559914325383387627997986)
        );

        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(privateKey);
        assert(
            publicKey.x_a == expected.x_a && publicKey.x_b == expected.x_b && publicKey.y_a == expected.y_a
                && publicKey.y_b == expected.y_b
        );
    }

    function testG1PointCompress_1() public {
        BLS.G1Point memory point = BLSUtils.toPublicKey(123456);
        BLS.Fp memory result = BLSUtils.compress(point);

        // Expected result: 0xaf6e96c0eccd8d4ae868be9299af737855a1b08d57bccb565ea7e69311a30baeebe08d493c3fea97077e8337e95ac5a6
        assert(result.a == BLSUtils._u(233189109563333818632959426218981028728));
        assert(result.b == BLSUtils._u(38732273024956312936195524807674957651409788979825024437260187772136397129126));
    }

    function testG1PointCompress_2() public {
        BLS.G1Point memory point = BLSUtils.toPublicKey(69420);
        BLS.Fp memory result = BLSUtils.compress(point);

        // Expected result: 0xb9e16ee4c0c0f6fd65b48c8dc759038bd2eebd979e489d08d69825bed32a37c3cc69e9e05f577445ee27319791832961
        assert(result.a == BLSUtils._u(247077695202111629659213208963742499723));
        assert(result.b == BLSUtils._u(95407516321583900695556749922087294361570042875752728076201341488189472450913));
    }

    enum MessageType {
        Reserved,
        Registration,
        Delegation
    }

    function testValidG2Point() public {
        // 0x1e240
        uint256 privateKey = 123456;

        // 0xaf6e96c0eccd8d4ae868be9299af737855a1b08d57bccb565ea7e69311a30baeebe08d493c3fea97077e8337e95ac5a6
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(privateKey);

        // Owner account of the proposer (used in SignedRegistration)
        address owner = address(0x1111111111111111111111111111111111111111);

        // Commit-Boost signing domain
        bytes32 signingDomain = bytes32(0x00000000000000000000000000000000000000000000000000000000436f6d6d);

        // Commit-Boost signing ID
        bytes32 signingId = bytes32(0x2222222222222222222222222222222222222222222222222222222222222222);

        // Commit-Boost nonce
        bytes32 nonce = bytes32(0x0000000000000000000000000000000000000000000000000000000000000420);

        // Commit-Boost chain ID
        bytes32 chainId = bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);

        // 0xe0c7a9983a810c24cb2fe92669f4f7e99cdccb534b2d47678b3ca9b9c903bb11
        bytes32 messageHash = keccak256(abi.encode(MessageType.Registration, owner));

        // 0x33f917d4c13213a7a68d6dfb920604632ea146ab4f0cde2720caadcfc0315f22
        bytes32 signingRoot = sha256(
            abi.encodePacked(
                sha256(
                    abi.encodePacked(
                        sha256(abi.encodePacked(messageHash, signingId)), sha256(abi.encodePacked(nonce, chainId))
                    )
                ),
                signingDomain
            )
        );

        // 0xa5955ed2dc4cfeffcb7a1203e60f115de2fb84e9323d3f6d7654485dcb6ccef1775295ce63f3dc69ecb1e1f5bbdbcb31196a0b74cb16950dc8aafabcf182573a4d2f146b53d6960a5a27e037c44f5f2a2181bd98641f33b8c0387e53e7eadad0
        BLS.G2Point memory signature = BLSUtils.sign(privateKey, messageHash, signingDomain, signingId, nonce, chainId);

        console.logBytes32(signature.x_c0_a);
        console.logBytes32(signature.x_c0_b);
        console.logBytes32(signature.x_c1_a);
        console.logBytes32(signature.x_c1_b);
        console.logBytes32(signature.y_c0_a);
        console.logBytes32(signature.y_c0_b);
        console.logBytes32(signature.y_c1_a);
        console.logBytes32(signature.y_c1_b);

        // 0x00000000000000000000000000000000196a0b74cb16950dc8aafabcf182573a
        // 0x4d2f146b53d6960a5a27e037c44f5f2a2181bd98641f33b8c0387e53e7eadad0
        // 0x0000000000000000000000000000000005955ed2dc4cfeffcb7a1203e60f115d
        // 0xe2fb84e9323d3f6d7654485dcb6ccef1775295ce63f3dc69ecb1e1f5bbdbcb31
        // 0x00000000000000000000000000000000078009cdfda2becc35184e03b1d0eb89
        // 0xd25a89324552cd9e317e4baffd2606df7ac1f3297d7faffb44f53aa2456440bd
        // 0x000000000000000000000000000000000d246a98735f7aaf9dcc7894768f8016
        // 0x22bd89742861ab1e98de83b64ba009b7243b77e9ee10c9a29a11c9366a8082c6

        assert(BLSUtils.verify(messageHash, signature, publicKey, signingDomain, signingId, nonce, chainId));
    }

    function testValidG2PointDelegation() public {
        // 0x1e240
        uint256 proposerPrivateKey = 123456;

        // 0xaf6e96c0eccd8d4ae868be9299af737855a1b08d57bccb565ea7e69311a30baeebe08d493c3fea97077e8337e95ac5a6
        BLS.G1Point memory proposerPubKey = BLSUtils.toPublicKey(proposerPrivateKey);

        // 0x1343e
        uint256 delegatePrivateKey = 78910;

        // 0xaf53b192a82ec1229e8fce4f99cb60287ce33896192b6063ac332b36fbe87ba1b2936bbc849ec68a0132362ab11a7754
        BLS.G1Point memory delegatePubKey = BLSUtils.toPublicKey(delegatePrivateKey);

        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposer: proposerPubKey,
            delegate: delegatePubKey,
            committer: address(0x1111111111111111111111111111111111111111),
            slot: 5,
            metadata: "some-metadata-here"
        });

        console.logBytes32(keccak256(abi.encode(uint256(2), delegation)));

        // Commit-Boost signing domain
        bytes32 signingDomain = bytes32(0x00000000000000000000000000000000000000000000000000000000436f6d6d);

        // Commit-Boost signing ID
        bytes32 signingId = bytes32(0x2222222222222222222222222222222222222222222222222222222222222222);

        // Commit-Boost nonce
        bytes32 nonce = bytes32(0x0000000000000000000000000000000000000000000000000000000000000420);

        // Commit-Boost chain ID
        bytes32 chainId = bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);

        // 0xcd9aca062121f6f50df1bfd7e74e2b023a5a0d9e1387447568a2119db5022e1b
        bytes32 messageHash = keccak256(abi.encode(MessageType.Delegation, delegation));

        // 0xad9ba7af707d987c147f0379b5e68bc2da1e1b94fcaa6dc72897bb4d23b22075
        bytes32 signingRoot = sha256(
            abi.encodePacked(
                sha256(
                    abi.encodePacked(
                        sha256(abi.encodePacked(messageHash, signingId)), sha256(abi.encodePacked(nonce, chainId))
                    )
                ),
                signingDomain
            )
        );

        // 0xa4a7b68288c7e131151ddc020ebf437180f45d0440e74b45d35ae3f757aba7a1051cff0db6bf2ae8049bd864a77263c20b044bf27bf506e1f79717e36c025587bc645a28458447a2db573c8a62d0968c1f2413c449c9e2fa3e7589b6fc438bb2
        BLS.G2Point memory signature =
            BLSUtils.sign(proposerPrivateKey, messageHash, signingDomain, signingId, nonce, chainId);

        console.logBytes32(signature.x_c0_a);
        console.logBytes32(signature.x_c0_b);
        console.logBytes32(signature.x_c1_a);
        console.logBytes32(signature.x_c1_b);
        console.logBytes32(signature.y_c0_a);
        console.logBytes32(signature.y_c0_b);
        console.logBytes32(signature.y_c1_a);
        console.logBytes32(signature.y_c1_b);

        //   0x000000000000000000000000000000000b044bf27bf506e1f79717e36c025587
        //   0xbc645a28458447a2db573c8a62d0968c1f2413c449c9e2fa3e7589b6fc438bb2
        //   0x0000000000000000000000000000000004a7b68288c7e131151ddc020ebf4371
        //   0x80f45d0440e74b45d35ae3f757aba7a1051cff0db6bf2ae8049bd864a77263c2
        //   0x000000000000000000000000000000000ab58d8c14bab9130b1a7b261d2c7c9b
        //   0x4503018948819890030239b32f259755fa30302c51f1f1b4fb0c18a0efd7224c
        //   0x00000000000000000000000000000000110cc5b23f6b491ab0a4eb521b83acab
        //   0xfa2af587c82f0d3039d576e1cd54eb12b37b03a6e9c1c053c40f7fb9534a4f9e

        assert(BLSUtils.verify(messageHash, signature, proposerPubKey, signingDomain, signingId, nonce, chainId));
    }

    function testValidateRustDelegation() public {
        // decrypted + decoded from https://github.com/Commit-Boost/commit-boost-client/blob/main/tests/data/keystores/secrets/0xb3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9
        uint256 proposerPrivateKey = 0x0501e85d5bc2e95f70efda47409710a7cf01dd02ff238e3efec679b27331d917;

        // 0xb3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9
        BLS.G1Point memory proposerPubKey = BLSUtils.toPublicKey(proposerPrivateKey);

        // 0x1e240
        uint256 delegatePrivateKey = 123456;

        // 0xaf6e96c0eccd8d4ae868be9299af737855a1b08d57bccb565ea7e69311a30baeebe08d493c3fea97077e8337e95ac5a6
        BLS.G1Point memory delegatePubKey = BLSUtils.toPublicKey(delegatePrivateKey);

        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposer: proposerPubKey,
            delegate: delegatePubKey,
            committer: address(0x1111111111111111111111111111111111111111),
            slot: 0,
            metadata: ""
        });

        // Commit-Boost signing domain
        bytes32 signingDomain = bytes32(0x6d6d6f43719103511efa4f1362ff2a50996cccf329cc84cb410c5e5c7d351d03);

        // Commit-Boost signing ID
        bytes32 signingId = bytes32(0xcb005700fab121c00ccbc94db58c04675b7847c38f9583815139d1d98bea0cb0);

        // u64::MAX - 1 as little endian
        bytes32 nonce = bytes32(0xfeffffffffffffff000000000000000000000000000000000000000000000000);

        // Hoodi is 560048, as little endian
        bytes32 chainId = bytes32(0xb08b080000000000000000000000000000000000000000000000000000000000);

        // 0x9acaabc32311cf88c56b810bf9f6c789f84bca6cd7172c2056d4c7a639ffe79e
        bytes32 messageHash = keccak256(abi.encode(MessageType.Delegation, delegation));

        // 0x2df11c9d631fbe4be80eedd5caf00adb886ab9e10b1a277ec22d392c7a91d16e
        bytes32 signingRoot = sha256(
            abi.encodePacked(
                sha256(
                    abi.encodePacked(
                        sha256(abi.encodePacked(messageHash, signingId)), sha256(abi.encodePacked(nonce, chainId))
                    )
                ),
                signingDomain
            )
        );

        // 0x8c6f28dfec8a79c881146d6734e84b3b784c2649cb0c3fcec292491513abffd142eb7dde6b34e36427c42ccad19c42f20ae562237453f4c2c6ce0467a17afa55c7084b5a713e113b1d44a65dd7a08e36fd4ef91aee59c03de61b3c84fab4ae43
        BLS.G2Point memory signature =
            BLSUtils.sign(proposerPrivateKey, messageHash, signingDomain, signingId, nonce, chainId);

        console.logBytes32(signature.x_c0_a);
        console.logBytes32(signature.x_c0_b);
        console.logBytes32(signature.x_c1_a);
        console.logBytes32(signature.x_c1_b);
        console.logBytes32(signature.y_c0_a);
        console.logBytes32(signature.y_c0_b);
        console.logBytes32(signature.y_c1_a);
        console.logBytes32(signature.y_c1_b);

        // 0x000000000000000000000000000000000ae562237453f4c2c6ce0467a17afa55
        // 0xc7084b5a713e113b1d44a65dd7a08e36fd4ef91aee59c03de61b3c84fab4ae43
        // 0x000000000000000000000000000000000c6f28dfec8a79c881146d6734e84b3b
        // 0x784c2649cb0c3fcec292491513abffd142eb7dde6b34e36427c42ccad19c42f2
        // 0x000000000000000000000000000000000656654e89e944387f4b528f92471e3b
        // 0xd511bf5c2651fbc783deb339fa4cab28bd4c8cd49e311acbdc2bb3556027c986
        // 0x0000000000000000000000000000000006148f9185fdeea718d761cde3dc10ef
        // 0x9134f6df779be74d88a26aef051122b58d88288b86b4ecf8a256fcd2b0a7e715

        assert(BLSUtils.verify(messageHash, signature, proposerPubKey, signingDomain, signingId, nonce, chainId));
    }

    function testValidateRustRegistration() public {
        // decrypted + decoded from https://github.com/Commit-Boost/commit-boost-client/blob/main/tests/data/keystores/secrets/0xb3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9
        uint256 proposerPrivateKey = 0x0501e85d5bc2e95f70efda47409710a7cf01dd02ff238e3efec679b27331d917;

        // 0xb3a22e4a673ac7a153ab5b3c17a4dbef55f7e47210b20c0cbb0e66df5b36bb49ef808577610b034172e955d2312a61b9
        BLS.G1Point memory proposerPubKey = BLSUtils.toPublicKey(proposerPrivateKey);

        address owner = address(0x1111111111111111111111111111111111111111);

        // Commit-Boost signing domain
        bytes32 signingDomain = bytes32(0x6d6d6f43719103511efa4f1362ff2a50996cccf329cc84cb410c5e5c7d351d03);

        // Commit-Boost signing ID
        bytes32 signingId = bytes32(0xcb005700fab121c00ccbc94db58c04675b7847c38f9583815139d1d98bea0cb0);

        // u64::MAX - 1 as little endian
        bytes32 nonce = bytes32(0xfeffffffffffffff000000000000000000000000000000000000000000000000);

        // Hoodi is 560048, as little endian
        bytes32 chainId = bytes32(0xb08b080000000000000000000000000000000000000000000000000000000000);

        // 0xe0c7a9983a810c24cb2fe92669f4f7e99cdccb534b2d47678b3ca9b9c903bb11
        bytes32 messageHash = keccak256(abi.encode(MessageType.Registration, owner));

        // 0x8f3238365553e8df2f2f439bd2ac43b4ccc02c15eed16cccd96f60d08aeae385c18d035d306d559eee0026c5560f16a11829d7181e75bb8ac3a1db28ebb2a34998486e4d7beb3ce4aa760f06e883c018bbff612271024378bb0369ed3296475c
        BLS.G2Point memory signature =
            BLSUtils.sign(proposerPrivateKey, messageHash, signingDomain, signingId, nonce, chainId);

        console.logBytes32(signature.x_c0_a);
        console.logBytes32(signature.x_c0_b);
        console.logBytes32(signature.x_c1_a);
        console.logBytes32(signature.x_c1_b);
        console.logBytes32(signature.y_c0_a);
        console.logBytes32(signature.y_c0_b);
        console.logBytes32(signature.y_c1_a);
        console.logBytes32(signature.y_c1_b);

        // 0x000000000000000000000000000000001829d7181e75bb8ac3a1db28ebb2a349
        // 0x98486e4d7beb3ce4aa760f06e883c018bbff612271024378bb0369ed3296475c
        // 0x000000000000000000000000000000000f3238365553e8df2f2f439bd2ac43b4
        // 0xccc02c15eed16cccd96f60d08aeae385c18d035d306d559eee0026c5560f16a1
        // 0x00000000000000000000000000000000190e7b912eb3df921e6fb627998dfba3
        // 0xe8dff7e32680cade76ac9e4b499b9b3eb7ac7b2862117e29f9beb7ef2b85d634
        // 0x00000000000000000000000000000000013e29e6f8bb23da666bc35f4d828a72
        // 0x95bac57fd2fcb56db57b114674fd72c64a4caf1fc6afaef5276b5bf03bb4f722

        assert(BLSUtils.verify(messageHash, signature, proposerPubKey, signingDomain, signingId, nonce, chainId));
    }
}

contract BLSGasTest is Test {
    function testG1AddGas() public {
        BLS.G1Point memory a = BLSUtils.toPublicKey(1234);
        BLS.G1Point memory b = BLSUtils.toPublicKey(5678);
        vm.resetGasMetering();
        BLS.add(a, b);
    }

    function testG1MulGas() public {
        BLS.G1Point memory a = BLSUtils.toPublicKey(1234);
        vm.resetGasMetering();
        BLSUtils.mul(a, BLSUtils._u(1234));
    }

    function testG1MSMGas() public {
        BLS.G1Point[] memory points = new BLS.G1Point[](2);
        points[0] = BLSUtils.toPublicKey(1234);
        points[1] = BLSUtils.toPublicKey(5678);
        bytes32[] memory scalars = new bytes32[](2);
        scalars[0] = BLSUtils._u(1234);
        scalars[1] = BLSUtils._u(5678);
        vm.resetGasMetering();
        BLS.msm(points, scalars);
    }

    function testG2AddGas() public {
        BLS.G2Point memory g2A =
            BLSUtils.sign(1234, keccak256("hello"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));

        BLS.G2Point memory g2B =
            BLSUtils.sign(5678, keccak256("world"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));
        vm.resetGasMetering();
        BLS.add(g2A, g2B);
    }

    function testG2MulGas() public {
        BLS.G2Point memory g2A =
            BLSUtils.sign(1234, keccak256("hello"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));
        vm.resetGasMetering();
        BLSUtils.mul(g2A, BLSUtils._u(1234));
    }

    function testG2MSMGas() public {
        BLS.G2Point[] memory points = new BLS.G2Point[](2);
        points[0] = BLSUtils.sign(1234, keccak256("hello"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));
        points[1] = BLSUtils.sign(5678, keccak256("world"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));
        bytes32[] memory scalars = new bytes32[](2);
        scalars[0] = BLSUtils._u(1234);
        scalars[1] = BLSUtils._u(5678);
        vm.resetGasMetering();
        BLS.msm(points, scalars);
    }

    function testSinglePairingGas() public {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = BLSUtils.toPublicKey(1234);
        g1Points[1] = BLSUtils.toPublicKey(5678);
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = BLSUtils.sign(1234, keccak256("hello"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));
        g2Points[1] = BLSUtils.sign(5678, keccak256("world"), bytes32(0), bytes32(0), bytes32(0), bytes32(uint256(1)));
        vm.resetGasMetering();
        BLS.pairing(g1Points, g2Points);
    }

    function testMapFpToG1Gas() public {
        BLS.Fp memory fp = BLS.Fp(BLSUtils._u(1234), BLSUtils._u(5678));
        vm.resetGasMetering();
        BLS.toG1(fp);
    }

    function testMapFp2ToG2Gas() public {
        BLS.Fp2 memory fp2 = BLS.Fp2(BLSUtils._u(1234), BLSUtils._u(5678), BLSUtils._u(91011), BLSUtils._u(121314));
        vm.resetGasMetering();
        BLS.toG2(fp2);
    }

    function testSigningGas() public {
        BLS.G2Point memory signingRoot = BLSUtils.computeSigningRoot(
            keccak256("hello"), bytes32(uint256(keccak256("domain"))), bytes32(0), bytes32(0), bytes32(uint256(1))
        );
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(1234);
        vm.resetGasMetering();
        BLSUtils.sign(
            1234, keccak256("hello"), bytes32(uint256(keccak256("domain"))), bytes32(0), bytes32(0), bytes32(uint256(1))
        );
    }

    function testVerifyingSingleSignatureGas() public {
        BLS.G2Point memory signingRoot = BLSUtils.computeSigningRoot(
            keccak256("hello"), bytes32(uint256(keccak256("domain"))), bytes32(0), bytes32(0), bytes32(uint256(1))
        );
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(1234);
        BLS.G2Point memory signature = BLSUtils.sign(
            1234, keccak256("hello"), bytes32(uint256(keccak256("domain"))), bytes32(0), bytes32(0), bytes32(uint256(1))
        );

        vm.resetGasMetering();
        BLSUtils.verify(
            keccak256("hello"),
            signature,
            publicKey,
            bytes32(uint256(keccak256("domain"))),
            bytes32(0),
            bytes32(0),
            bytes32(uint256(1))
        );
    }

    function testG1PointCompressGas() public {
        BLS.G1Point memory point = BLSUtils.toPublicKey(123456);
        vm.resetGasMetering();
        BLSUtils.compress(point);
    }
}
