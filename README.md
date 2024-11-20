# Universal Registry Contract

The URC is a universal contract for… 
- Ethereum validators to register for proposer commitments
- anyone to slash validators that break commitments

it should…
- be governance-free and immutable
- be simple and maximally expressive
- use ETH as collateral
- not rely on any external contracts
- minimize switching costs
- be gas-efficient
- be open-source


### Usage
The URC is written using Foundry. To install:
```
curl -L https://foundry.paradigm.xyz | bash
```

To run the tests:
```
forge build
forge test
```