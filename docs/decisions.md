
## Don't save validator public keys on-chain

**Pros**:
- Significantly reduces storage costs and barriers to entry
- Keys can be stored in an extension contract

**Cons**:
- Harder to verify directly on-chain (requires submitting merkle proof)

**Current Implementation**:

Instead of saving validator public keys on-chain, the `register()` function merkleizes the `Registrations` and saves the root hash to the `commitments` mapping. This allows anyone verify whether a validator is opted-in and their collateral without storing the public key on-chain. This optimization reduces storage costs from `48 bytes` per validator to a constant `32 bytes` per batch of validators.


## Batching Operators
**Pros**:
- Reduces gas costs
- Collateral is shared across all validators in the batch (efficient for big 🐋)

**Cons**:
- Collateral is shared across all validators in the batch (inefficient for small 🐟)

**Current Implementation**:

The current implementation batches `N` validators per operator into a single `register()` call. This reduces gas costs by minimizing function calls and storage. The implication is that the Ether collateral is shared across all validators in the batch. However, since block proposals must happen sequentially, the collateral only needs to apply to a single validator at a time.


## Don't verify BLS signatures at registration time

**Pros**:
- Reduces gas costs

**Cons**:
- Valid registrations must wait for the fraud proof window to pass
- Introduces a minimum collateral requirement

**Current Implementation**:

Even post-Pectra upgrade, BLS precompiles are still expensive and would need to be called per validator. To avoid this, the current implementation optimistically accepts BLS signatures at registration time. Before the `FRAUD_PROOF_WINDOW` elapses, anyone can pay the gas to run the BLS signature verification on-chain and claim `MIN_COLLATERAL` from the operator as an incentive. 

## Don't use bytecode to slash
To opt-in to preconfs, operators will commit to slashing conditions by signing off-chain `DelegationMessages`. To support general slashing logic, the initial idea was to have operators commit to a bytecode hash. Upon slashing, the URC would deploy and execute the corresponding bytecode. The return value of the function call is the amount of GWEI to be slashed from the operator's collateral. 

**Pros of bytecode**:
- Elegant design
- Universal

**Cons of bytecode**:
- Executing bytecode requires first deploying it which eats into the gas limit or using lower-level languages like [Huff](https://docs.huff.sh/get-started/overview/)
- The approach cannot be used for stateful slashing logic, e.g., fraud proofs
- Bytecode is not easily verified/readable

**Current Implementation**:

Over several discussions, we decided replace bytecode commitments with slashing contract commitments. The bytecode approach supports universal slashing logic by encoding it directly as EVM logic or by deploying ZK-verification logic. However, the main motivator against using bytecode is that it does not allow for stateful slashing logic. For example, any protocol wishing to implement fraud proofs for their slashing logic would be incompatible with the bytecode approach. This is because the fraud proof game would need to be played over multiple rounds, implying it saves intermediate state.

In the current implementation, proposers commit to an arbitrary contract address which is expected to support a general purpose interface: `slash(bytes inputs)`. Similarly to the bytecode approach, the return value of the `slash(bytes inputs)` function is the amount of GWEI to be slashed.

This approach has the following benefits:
- Each `Slasher` contract only needs to be deployed once and can be verified on-chain.
- Arbitrary stateful logic can be executed on the `Slasher`. (e.g., a fraud proof game is played ahead of time and then calling `slash(bytes inputs)` returns the slashing outcome)
- Supports arbitrarily complex slashing logic, even existing restaking protocols
- Can support the execution of arbitrary bytecode by deploying a dedicated `Slasher` contract 