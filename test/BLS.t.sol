// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

import { Test, console } from "forge-std/Test.sol";
import { BLS } from "../src/lib/BLS.sol";

/// @notice A simple test demonstrating BLS signature verification.
contract BLSTest is Test {
    /// @dev Demonstrates the signing and verification of a message.
    function testSignAndVerify(uint256 privateKey, bytes memory message, bytes memory domainSeparator) public view {
        BLS.G1Point memory publicKey = BLS.toPublicKey(privateKey);
        BLS.G2Point memory signature = BLS.sign(message, privateKey, domainSeparator);
        assert(BLS.verify(message, signature, publicKey, domainSeparator));
    }

    /// @dev Demonstrates the aggregation and verification of two signatures.
    function testAggregation(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes memory message,
        bytes memory domainSeparator
    ) public view {
        // public keys
        BLS.G1Point memory pk1 = BLS.toPublicKey(privateKey1);
        BLS.G1Point memory pk2 = BLS.toPublicKey(privateKey2);

        // signatures
        BLS.G2Point memory sig1 = BLS.sign(message, privateKey1, domainSeparator);
        BLS.G2Point memory sig2 = BLS.sign(message, privateKey2, domainSeparator);

        // aggregated signature
        BLS.G2Point memory sig = BLS.G2Add(sig1, sig2);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](3);
        g1Points[0] = BLS.NEGATED_G1_GENERATOR();
        g1Points[1] = pk1;
        g1Points[2] = pk2;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](3);
        g2Points[0] = sig;
        g2Points[1] = BLS.toMessagePoint(message, domainSeparator);
        g2Points[2] = BLS.toMessagePoint(message, domainSeparator);

        assert(BLS.Pairing(g1Points, g2Points));
    }

    function testToMessagePoint(bytes memory message, bytes memory domainSeparator) public view {
        BLS.G2Point memory messagePoint = BLS.toMessagePoint(message, domainSeparator);
        BLS.G2Point memory messagePointExpected = BLS.MapFp2ToG2(
            BLS.Fp2(BLS.Fp(0, 0), BLS.Fp(0, uint256(keccak256(abi.encodePacked(domainSeparator, message)))))
        );

        assert(
            messagePoint.x.c0.a == messagePointExpected.x.c0.a && messagePoint.x.c0.b == messagePointExpected.x.c0.b
                && messagePoint.x.c1.a == messagePointExpected.x.c1.a && messagePoint.x.c1.b == messagePointExpected.x.c1.b
                && messagePoint.y.c0.a == messagePointExpected.y.c0.a && messagePoint.y.c0.b == messagePointExpected.y.c0.b
                && messagePoint.y.c1.a == messagePointExpected.y.c1.a && messagePoint.y.c1.b == messagePointExpected.y.c1.b
        );
    }

    function testToPublicKey() public view {
        uint256 privateKey = 12356;

        // uncompressed public key
        BLS.G1Point memory expected = BLS.G1Point(
            BLS.Fp(
                12115118667309283734868789696201968385,
                102796267992108309135721548586500937750960769774310798537421982072779087272819
            ),
            BLS.Fp(
                15699442850880472822588013448545136667,
                697141831937854224682724016220779412457574525815594559914325383387627997986
            )
        );

        BLS.G1Point memory publicKey = BLS.toPublicKey(privateKey);
        assert(
            publicKey.x.a == expected.x.a && publicKey.x.b == expected.x.b && publicKey.y.a == expected.y.a
                && publicKey.y.b == expected.y.b
        );
    }
}
