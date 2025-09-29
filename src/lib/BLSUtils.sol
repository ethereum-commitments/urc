// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "solady/utils/ext/ithaca/BLS.sol";
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

/// @title BLS
/// @notice Utility functions to built on top of the Solady BLS library.
library BLSUtils {
    using BLS for *;

    /// @dev For addition of two points on the BLS12-381 G1 curve,
    address internal constant BLS12_G1ADD = 0x000000000000000000000000000000000000000b;

    /// @dev For multi-scalar multiplication (MSM) on the BLS12-381 G1 curve.
    address internal constant BLS12_G1MSM = 0x000000000000000000000000000000000000000C;

    /// @dev For addition of two points on the BLS12-381 G2 curve.
    address internal constant BLS12_G2ADD = 0x000000000000000000000000000000000000000d;

    /// @dev For multi-scalar multiplication (MSM) on the BLS12-381 G2 curve.
    address internal constant BLS12_G2MSM = 0x000000000000000000000000000000000000000E;

    /// @dev For performing a pairing check on the BLS12-381 curve.
    address internal constant BLS12_PAIRING_CHECK = 0x000000000000000000000000000000000000000F;

    /// @dev For mapping a Fp to a point on the BLS12-381 G1 curve.
    address internal constant BLS12_MAP_FP_TO_G1 = 0x0000000000000000000000000000000000000010;

    /// @dev For mapping a Fp2 to a point on the BLS12-381 G2 curve.
    address internal constant BLS12_MAP_FP2_TO_G2 = 0x0000000000000000000000000000000000000011;

    /// @notice G1MUL operation
    /// @param point G1 point
    /// @param scalar Scalar to multiply the point by
    /// @return result Resulted G1 point
    function mul(BLS.G1Point memory point, bytes32 scalar) internal view returns (BLS.G1Point memory result) {
        BLS.G1Point[] memory points = new BLS.G1Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        points[0] = point;
        scalars[0] = scalar;

        return BLS.msm(points, scalars);
    }

    /// @notice G2MUL operation
    /// @param point G2 point
    /// @param scalar Scalar to multiply the point by
    /// @return result Resulted G2 point
    function mul(BLS.G2Point memory point, bytes32 scalar) internal view returns (BLS.G2Point memory result) {
        BLS.G2Point[] memory points = new BLS.G2Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        points[0] = point;
        scalars[0] = scalar;

        return BLS.msm(points, scalars);
    }

    function G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            _u(31827880280837800241567138048534752271),
            _u(88385725958748408079899006800036250932223001591707578097800747617502997169851),
            _u(11568204302792691131076548377920244452),
            _u(114417265404584670498511149331300188430316142484413708742216858159411894806497)
        );
    }

    function NEGATED_G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            _u(31827880280837800241567138048534752271),
            _u(88385725958748408079899006800036250932223001591707578097800747617502997169851),
            _u(22997279242622214937712647648895181298),
            _u(46816884707101390882112958134453447585552332943769894357249934112654335001290)
        );
    }

    function _u(uint256 x) internal pure returns (bytes32) {
        return bytes32(x);
    }

    /// @dev Referenced from https://eips.ethereum.org/EIPS/eip-2537#curve-parameters
    function baseFieldModulus() internal pure returns (uint256[2] memory) {
        return [
            0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7,
            0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
        ];
    }

    /**
     * @notice Negates a G1 point, by reflecting it over the x-axis
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev Assumes that the Y coordinate is always less than the field modulus
     * @param point The G1 point to negate
     */
    function negate(BLS.G1Point memory point) internal pure returns (BLS.G1Point memory) {
        uint256[2] memory fieldModulus = baseFieldModulus();
        uint256[2] memory yNeg;

        // Perform word-wise elementary subtraction
        if (fieldModulus[1] < uint256(point.y_b)) {
            yNeg[1] = type(uint256).max - (uint256(point.y_b) - fieldModulus[1]) + 1;
            fieldModulus[0] -= 1; // borrow
        } else {
            yNeg[1] = fieldModulus[1] - uint256(point.y_b);
        }
        yNeg[0] = fieldModulus[0] - uint256(point.y_a);

        return BLS.G1Point({ x_a: point.x_a, x_b: point.x_b, y_a: _u(yNeg[0]), y_b: _u(yNeg[1]) });
    }

    /**
     * @notice Returns true if `a` is lexicographically greater than `b`
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev It makes the comparison bit-wise.
     * This functions also assumes that the passed values are 48-byte long BLS pub keys that have
     * 16 functional bytes in the first word, and 32 bytes in the second.
     */
    // function _greaterThan(uint256[2] memory a, uint256[2] memory b) internal pure returns (bool) {
    function _greaterThan(BLS.Fp memory a, BLS.Fp memory b) internal pure returns (bool) {
        uint256 wordA;
        uint256 wordB;
        uint256 mask;

        // Only compare the unequal words
        if (a.a == b.a) {
            wordA = uint256(a.b);
            wordB = uint256(b.b);
            mask = 1 << 255;
        } else {
            wordA = uint256(a.a);
            wordB = uint256(b.a);
            mask = 1 << 127; // Only check for lower 16 bytes in the first word
        }

        // We may safely set the control value to be less than 256 since it is guaranteed that the
        // the loop returns if the first words are different.
        for (uint256 i; i < 256; ++i) {
            uint256 x = wordA & mask;
            uint256 y = wordB & mask;

            if (x == 0 && y != 0) return false;
            if (x != 0 && y == 0) return true;

            mask = mask >> 1;
        }

        return false;
    }

    /// @dev Computes a point in G2 from a message.
    /// @dev Copied from Solady but changed the DST from "SWU_RO_NUL_\x2b" to "SWU_RO_POP_\x2b"
    function _hashToG2(bytes memory message) internal view returns (BLS.G2Point memory result) {
        assembly ("memory-safe") {
            function dstPrime(o_, i_) -> _o {
                mstore8(o_, i_) // 1.
                mstore(add(o_, 0x01), "BLS_SIG_BLS12381G2_XMD:SHA-256_S") // 32.
                mstore(add(o_, 0x21), "SWU_RO_POP_\x2b") // 12.
                _o := add(0x2d, o_)
            }

            function sha2(data_, n_) -> _h {
                if iszero(and(eq(returndatasize(), 0x20), staticcall(gas(), 2, data_, n_, 0x00, 0x20))) {
                    revert(calldatasize(), 0x00)
                }
                _h := mload(0x00)
            }

            function modfield(s_, b_) {
                mcopy(add(s_, 0x60), b_, 0x40)
                if iszero(and(eq(returndatasize(), 0x40), staticcall(gas(), 5, s_, 0x100, b_, 0x40))) {
                    revert(calldatasize(), 0x00)
                }
            }

            function mapToG2(s_, r_) {
                if iszero(and(eq(returndatasize(), 0x100), staticcall(gas(), BLS12_MAP_FP2_TO_G2, s_, 0x80, r_, 0x100)))
                {
                    mstore(0x00, 0x89083b91) // `MapFp2ToG2Failed()`.
                    revert(0x1c, 0x04)
                }
            }

            let b := mload(0x40)
            let s := add(b, 0x100)
            calldatacopy(s, calldatasize(), 0x40)
            mcopy(add(0x40, s), add(0x20, message), mload(message))
            let o := add(add(0x40, s), mload(message))
            mstore(o, shl(240, 256))
            let b0 := sha2(s, sub(dstPrime(add(0x02, o), 0), s))
            mstore(0x20, b0)
            mstore(s, b0)
            mstore(b, sha2(s, sub(dstPrime(add(0x20, s), 1), s)))
            let j := b
            for { let i := 2 } 1 { } {
                mstore(s, xor(b0, mload(j)))
                j := add(j, 0x20)
                mstore(j, sha2(s, sub(dstPrime(add(0x20, s), i), s)))
                i := add(i, 1)
                if eq(i, 9) { break }
            }

            mstore(add(s, 0x00), 0x40)
            mstore(add(s, 0x20), 0x20)
            mstore(add(s, 0x40), 0x40)
            mstore(add(s, 0xa0), 1)
            mstore(add(s, 0xc0), 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
            mstore(add(s, 0xe0), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
            modfield(s, add(b, 0x00))
            modfield(s, add(b, 0x40))
            modfield(s, add(b, 0x80))
            modfield(s, add(b, 0xc0))

            mapToG2(b, result)
            mapToG2(add(0x80, b), add(0x100, result))

            if iszero(and(eq(returndatasize(), 0x100), staticcall(gas(), BLS12_G2ADD, result, 0x200, result, 0x100))) {
                mstore(0x00, 0xc55e5e33) // `G2AddFailed()`.
                revert(0x1c, 0x04)
            }
        }
    }

    /// @notice Converts a private key to a public key by multiplying the generator point with the private key
    /// @param privateKey The private key to convert
    /// @return The public key
    function toPublicKey(uint256 privateKey) internal view returns (BLS.G1Point memory) {
        return mul(G1_GENERATOR(), _u(privateKey));
    }

    /// @notice Computes the signingRoot
    ///
    ///                      signingRoot
    ///                       /         \
    ///                  subTreeRoot   signingDomain
    ///                 /           \
    ///                *             *
    ///             /    \         /   \
    ///    messageHash signingId  nonce chainId
    ///
    /// @param messageHash The hash of the message to sign
    /// @param signingDomain The domain mixin for the signer (Commit-Boost)
    /// @param signingId The signing ID for the module (Commit-Boost)
    /// @param nonce The nonce for the module (Commit-Boost)
    /// @param chainId The chain ID
    /// @return The signing root
    function computeSigningRoot(
        bytes32 messageHash,
        bytes32 signingDomain,
        bytes32 signingId,
        uint64 nonce,
        bytes32 chainId
    ) internal view returns (BLS.G2Point memory) {
        bytes32 subTreeRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(messageHash, signingId)),
                sha256(abi.encodePacked(_toLittleEndian(nonce), chainId))
            )
        );
        bytes32 signingRoot = sha256(abi.encodePacked(subTreeRoot, signingDomain));

        // Convert the signing root hash to a G2 point
        return _hashToG2(abi.encodePacked(signingRoot));
    }

    /// @notice Signs a message
    /// @param privateKey The private key to sign with
    /// @param messageHash The hash of the message to sign
    /// @param signingDomain The domain mixin for the signer (Commit-Boost)
    /// @param signingId The signing ID for the module (Commit-Boost)
    /// @param nonce The nonce for the module (Commit-Boost)
    /// @param chainId The chain ID
    /// @return A signature in G2
    function sign(
        uint256 privateKey,
        bytes32 messageHash,
        bytes32 signingDomain,
        bytes32 signingId,
        uint64 nonce,
        bytes32 chainId
    ) internal view returns (BLS.G2Point memory) {
        return mul(computeSigningRoot(messageHash, signingDomain, signingId, nonce, chainId), _u(privateKey));
    }

    /// @notice Verifies a signature
    /// @param messageHash The hash of the message to verify
    /// @param signature The signature to verify
    /// @param publicKey The public key to verify against
    /// @param signingDomain The domain mixin for the signer (Commit-Boost)
    /// @param signingId The signing ID for the module (Commit-Boost)
    /// @param nonce The nonce for the module (Commit-Boost)
    /// @param chainId The chain ID
    /// @return True if the signature is valid, false otherwise
    function verify(
        bytes32 messageHash,
        BLS.G2Point memory signature,
        BLS.G1Point memory publicKey,
        bytes32 signingDomain,
        bytes32 signingId,
        uint64 nonce,
        bytes32 chainId
    ) public view returns (bool) {
        // Hash the message bytes into a G2 point
        BLS.G2Point memory signingRoot = computeSigningRoot(messageHash, signingDomain, signingId, nonce, chainId);

        // Invoke the BLS.pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = NEGATED_G1_GENERATOR();
        g1Points[1] = publicKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = signingRoot;

        return BLS.pairing(g1Points, g2Points);
    }

    /**
     * @notice Returns a BLS.G1Point in the compressed form
     * @dev Adapted from https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/004d407105578a83c4815e7ec2c55ec467b9ed3f/SmartContracts/src/libraries/BLS12381.sol#L124
     * @dev Originally based on https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/BLS.pairing/src/bls12_381/README.md#serialization
     * @param point The G1 point to compress
     */
    function compress(BLS.G1Point memory point) internal pure returns (BLS.Fp memory) {
        BLS.Fp memory r = BLS.Fp({ a: point.x_a, b: point.x_b });

        // Set the first MSB
        r.a = bytes32(uint256(r.a) | (1 << 127));

        // Second MSB is left to be 0 since we are assuming that no infinity points are involved

        // Set the third MSB if point.y is lexicographically larger than the y in negated point
        BLS.G1Point memory negatedPoint = negate(point);
        if (_greaterThan(BLS.Fp({ a: point.y_a, b: point.y_b }), BLS.Fp({ a: negatedPoint.y_a, b: negatedPoint.y_b })))
        {
            r.a = bytes32(uint256(r.a) | (1 << 125));
        }

        return r;
    }

    /// @notice Helper to convert a u64 to a little-endian bytes
    /// @param x The u64 to convert
    /// @return b The little-endian bytes
    function _toLittleEndian(uint64 x) public pure returns (bytes32) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return bytes32(b);
    }
}
