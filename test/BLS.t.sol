// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

import {Test, console} from "forge-std/Test.sol";
import {BLS} from "../src/lib/BLS.sol";

/// @notice A simple test demonstrating BLS signature verification.
contract BLSTest is Test {
    /// @dev Demonstrates the signing and verification of a message.
    function test() public {
        // Obtain the private key as a random scalar.
        uint256 privateKey = vm.randomUint();

        // Public key is the generator point multiplied by the private key.
        BLS.G1Point memory publicKey = BLS.G1Mul(BLS.G1_GENERATOR(), privateKey);

        // Compute the message point by mapping message's keccak256 hash to a point in G2.
        bytes memory message = "hello world";
        BLS.G2Point memory messagePoint = BLS.MapFp2ToG2(BLS.Fp2(BLS.Fp(0, 0), BLS.Fp(0, uint256(keccak256(message)))));

        // Obtain the signature by multiplying the message point by the private key.
        BLS.G2Point memory signature = BLS.G2Mul(messagePoint, privateKey);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = BLS.NEGATED_G1_GENERATOR();
        g1Points[1] = publicKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = messagePoint;

        assertTrue(BLS.Pairing(g1Points, g2Points));
    }

    /// @dev Demonstrates the aggregation and verification of two signatures.
    function testAggregated() public {
        // private keys
        uint256 sk1 = vm.randomUint();
        uint256 sk2 = vm.randomUint();

        // public keys
        BLS.G1Point memory pk1 = BLS.G1Mul(BLS.G1_GENERATOR(), sk1);
        BLS.G1Point memory pk2 = BLS.G1Mul(BLS.G1_GENERATOR(), sk2);

        // Compute the message point by mapping message's keccak256 hash to a point in G2.
        bytes memory message = "hello world";
        BLS.G2Point memory messagePoint = BLS.MapFp2ToG2(BLS.Fp2(BLS.Fp(0, 0), BLS.Fp(0, uint256(keccak256(message)))));

        // signatures
        BLS.G2Point memory sig1 = BLS.G2Mul(messagePoint, sk1);
        BLS.G2Point memory sig2 = BLS.G2Mul(messagePoint, sk2);

        // aggregated signature
        BLS.G2Point memory sig = BLS.G2Add(sig1, sig2);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](3);
        g1Points[0] = BLS.NEGATED_G1_GENERATOR();
        g1Points[1] = pk1;
        g1Points[2] = pk2;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](3);
        g2Points[0] = sig;
        g2Points[1] = messagePoint;
        g2Points[2] = messagePoint;

        assertTrue(BLS.Pairing(g1Points, g2Points));
    }
}