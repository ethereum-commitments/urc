// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract IExclusionPreconfSlasher {
    struct SignedCommitment {
        uint64 slot;
        bytes signature;
        bytes signedTx;
    }

    struct TransactionData {
        bytes32 txHash;
        uint256 nonce;
        uint256 gasLimit;
    }

    struct BlockHeaderData {
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 txRoot;
        uint256 blockNumber;
        uint256 timestamp;
        uint256 baseFee;
    }

    struct AccountData {
        uint256 nonce;
        uint256 balance;
    }

    struct Proof {
        // block number where the transactions were submitted
        uint256 targetBlockNumber;
        // RLP-encoded block header of the previous block of the target block
        // (for clarity: `previousBlockHeader.number == targetBlockNumber - 1`)
        bytes previousBlockHeaderRLP;
        // RLP-encoded block header where the committed transactions are included
        bytes targetBlockHeaderRLP;
        // merkle proof of the account in the state trie of the previous block
        // (checked against the previousBlockHeader.stateRoot)
        bytes accountMerkleProof;
        // merkle proof of the transactions in the transaction trie of the target block
        // (checked against the targetBlockHeader.txRoot). The order of the proofs should match
        // the order of the committed transactions in the challenge: `Challenge.committedTxs`.
        bytes[] txMerkleProofs;
        // indexes of the committed transactions in the block. The order of the indexes should match
        // the order of the committed transactions in the challenge: `Challenge.committedTxs`.
        uint256[] txIndexesInBlock;
    }
}
