# URC Overview

## Milestones
- [X] Batch register an operator (cheaply)
- [X] Unregister/Claim collateral
- [X] Slash with bytecode
- [X] Slash with arbitrary `Slasher` contracts
- [X] Social consensus on design
- [X] Audit 1
- [X] Audit 2
- [ ] Audit 3

## Overview
Readers are recommended to refer to the [Constraints API documentation](https://github.com/eth-fabric/constraints-specs/blob/main/specs/proposer.md) for details on how to interact with the URC.

## Signing
The URC will verify two types of BLS signatures: 
- `IRegistry.SignedRegistration.signature`
- `ISlasher.SignedDelegation.signature`

The messages are expected to be formatted as follows:
- `bytes32 messageHash = keccak256(abi.encode(IRegistry.MessageType.Registration, owner));` where `owner` is an `address`
- `bytes32 messageHash = keccak256(abi.encode(IRegistry.MessageType.Delegation, delegation));` where `delegation` is a `ISlasher.Delegation`

The URC complies with the [Signing API defined in Commit-Boost](https://github.com/Commit-Boost/commit-boost-client/blob/2dfe96b8d45d9c2bb37f71d56130a066dec16ec8/crates/common/src/types.rs#L296). 
```
/// Structure for signatures used in Beacon chain operations
#[derive(Default, Debug, TreeHash)]
pub struct SigningData {
    pub object_root: B256,
    pub signing_domain: B256,
}

/// Structure for signatures used for proposer commitments in Commit Boost.
/// The signing root of this struct must be used as the object_root of a
/// SigningData for signatures.
#[derive(Default, Debug, TreeHash)]
pub struct PropCommitSigningInfo {
    pub data: B256,
    pub module_signing_id: B256,
    pub nonce: u64, // As per https://eips.ethereum.org/EIPS/eip-2681
    pub chain_id: U256,
}
```

The final signature is over the `signingRoot` which is the hash tree root of the `SigningData` struct, containing the `PropCommitSigningInfo` and `signing_domain`. 

This can be visualized as the following, where each intermediate hash uses SHA256. Specifically, `subTreeRoot` is the hash tree root of `PropCommitSigningInfo`:
```
                      signingRoot
                       /         \
                  subTreeRoot   signingDomain
                 /           \
                *             *
             /    \         /   \
    messageHash signingId  nonce chainId
```
- Note `messageHash` is equivalent to `PropCommitSigningInfo.data`
- Note that the `nonce` and `chain_id` are encoded as little-endian `bytes32`.
