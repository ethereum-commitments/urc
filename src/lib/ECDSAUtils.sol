// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { ECDSA } from "solady/utils/ECDSA.sol";

/// @title ECDSAUtils
/// @notice Utility functions for structured ECDSA signature handling
library ECDSAUtils {
    /// @notice Computes the signing root using the same Merkle tree structure as BLSUtils
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
    ) internal pure returns (bytes32) {
        bytes32 subTreeRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(messageHash, signingId)),
                sha256(abi.encodePacked(_toLittleEndian(nonce), chainId))
            )
        );
        bytes32 signingRoot = sha256(abi.encodePacked(subTreeRoot, signingDomain));
        return signingRoot;
    }

    /// @notice Recovers the signer address from a signature
    /// @param messageHash The hash of the message to verify
    /// @param signature The signature to verify
    /// @param signingDomain The domain mixin for the signer (Commit-Boost)
    /// @param signingId The signing ID for the module (Commit-Boost)
    /// @param nonce The nonce for the module (Commit-Boost)
    /// @param chainId The chain ID
    /// @return The recovered signer address
    function recover(
        bytes32 messageHash,
        bytes memory signature,
        bytes32 signingDomain,
        bytes32 signingId,
        uint64 nonce,
        bytes32 chainId
    ) public view returns (address) {
        bytes32 signingRoot = computeSigningRoot(messageHash, signingDomain, signingId, nonce, chainId);
        return ECDSA.recover(signingRoot, signature);
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
