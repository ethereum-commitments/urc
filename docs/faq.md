# Edge Cases / FAQ

### What if the `operator` doesn’t own the validator keys?
- → valid signatures (e.g., they copied calldata from another operator)
    1. attacker will not control `withdrawalAddress` → forfeits collateral
    2. attacker cannot sign any valid off-chain commitments
- → invalid signatures
    - fraud proof will get them slashed

### What if the `operator` submits duplicate keys?
- → in the same `operatorCommitment`:
    - they waste of gas
- → in different `operatorCommitments`:
    - they introduce extra collateral

### What is the purpose of the proxy key?
todo

### What happens to slashed ETH during registration?
todo

### What happens to slashed ETH when a commitment is broken?
todo

### (Parameter) MIN_COLLATERAL
- 0.1 ETH

### (Parameter) FRAUD_PROOF_WINDOW
- 7200 blocks (24 hours)

### (Parameter) DOMAIN_SEPERATOR
- "Universal-Registry-Contract"