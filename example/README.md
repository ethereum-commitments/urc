# Example Slasher Implementations

## InclusionPreconfSlasher

## ExclusionPreconfSlasher
1. Operator calls URC's [register()](../src/Registry.sol#L44) function to register a proposer BLS key
2. Operator signs an off-chain [`Delegation`](../src/ISlasher.sol#L8) message, delegating to a delegate's BLS key and committing to the slashing rules of the [`ExclusionPreconfSlasher`](./ExclusionPreconfSlasher.sol) contract. Included in the `Delegation.metadata` is an address that is the ECDSA signer of the [`SignedCommitment`](./PreconfStructs.sol) message. 
    > Note, embedding the ECDSA signer address in the `Delegation.metadata` field is optional, but simplified this example.
3. Operator signs an off-chain [`SignedCommitment`](./PreconfStructs.sol) message, committing to the exclusion of a specific transaction.
4. L1 block is published with the transaction included, breaking the preconf promise.
5. Challenger builds evidence for slashing:
    - produces an off-chain [`InclusionProof`](./PreconfStructs.sol) message, proving the preconfed transaction was included in the L1 block. The `SignedCommitment` and `InclusionProof` structs are abi-encoded and supplied as the `evidence` argument to the [`slashCommitment()`](../src/Registry.sol) function.
    - produces a Merkle proof that the operator's BLS key is registered in the URC (`proof` argument)
6. Challenger calls [`slashCommitment()`](../src/Registry.sol) with the evidence. The URC will verify that the `Delegation` message was signed by the registered proposer BLS key and then call the [`slash()`](../src/ISlasher.sol) function at the `Delegation.slasher` address. This will execute the [`ExclusionPreconfSlasher.slash()`](./ExclusionPreconfSlasher.sol) function.
7. The ExclusionPreconfSlasher will decode the `evidence` argument, verify the SignedCommitment was signed by the ECDSA signer in the `Delegation.metadata` field, then verify the inclusion proof against the L1 block. If the proof is valid, it means the preconfed transaction was included in the L1 block, and the slashing logic will execute and the operator will be slashed. Specifically, the slashing logic will return the `slashAmountGwei` and `rewardAmountGwei` values, which are the amount of GWEI to be burned and the amount of GWEI to be returned to the challenger, respectively, where the accounting is handled by the URC.
