// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";
import "../src/ISlasher.sol";
import { BLSUtils } from "../src/lib/BLSUtils.sol";
import { ECDSAUtils } from "../src/lib/ECDSAUtils.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

import { DummySlasher } from "../test/Slasher.t.sol";

contract SlashingScript is BaseScript {
    // forge script script/Slashing.s.sol:SlashingScript --sig "registerBadRegistration(address,address,bytes32,string)" $REGISTRY_ADDRESS $OWNER $SIGNING_ID $SIGNED_REGISTRATIONS_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function registerBadRegistration(address _registry, address owner, bytes32 signingId, string memory outfile)
        external
        returns (bytes32 registrationRoot)
    {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Generate an invalid BLS registration using a deterministic private key
        uint256 privateKey = 12345;

        // Read the signing domain and chain ID from the config file
        (bytes32 signingDomain, bytes32 chainId) = _defaultSigningParams();

        // different owner address for invalid registration
        IRegistry.SignedRegistration[] memory registrations =
            _nRegistrations(1, privateKey, address(1337), signingDomain, signingId, chainId);

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Use the minimum collateral amount
        uint256 collateralWei = registry.getConfig().minCollateralWei;

        // Print for the user
        _prettyPrintPubKey(registrations[0]);

        // Register the invalid registration
        registrationRoot = registry.register{ value: collateralWei }(registrations, owner, signingId);

        console.log("Registered bad registration with root:", vm.toString(registrationRoot));

        // Write the invalid registration to file
        _writeSignedRegistrations(owner, registrations, outfile);

        vm.stopBroadcast();
    }

    // forge script script/Slashing.s.sol:SlashingScript --sig "slashRegistration(address,string)" $REGISTRY_ADDRESS $REGISTRATION_PROOF_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function slashRegistration(address _registry, string memory registrationProofFile) external {
        // Read the registration proof from file
        IRegistry.RegistrationProof memory proof = _readRegistrationProof(registrationProofFile);

        // Start broadcasting transactions
        vm.startBroadcast();

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call slashRegistration
        uint256 slashedCollateralWei = registry.slashRegistration(proof);

        console.log("Slashed collateral:", slashedCollateralWei);

        vm.stopBroadcast();
    }

    // forge script script/Slashing.s.sol:SlashingScript --sig "generateEquivocatingDelegations(address,address,uint256,string,string)" $OWNER $COMMITTER $SLOT $DELEGATION_ONE_FILE $DELEGATION_TWO_FILE
    function generateEquivocatingDelegations(
        address owner,
        address committer,
        uint256 slot,
        string memory delegationOneFile,
        string memory delegationTwoFile
    ) external {
        // For testing we assume the proposer private key is generated from their owner address
        // uint256 proposerPrivateKey = uint256(keccak256(abi.encode(owner)));
        uint256 proposerPrivateKey = uint256(keccak256(abi.encode(owner)));

        // Read the signing domain and chain ID from the config file
        (bytes32 signingDomain, bytes32 chainId) = _defaultSigningParams();
        bytes32 signingId = keccak256("test-signing-id");

        // Generate two delegations with the same proposer and slot but different delegates
        ISlasher.SignedDelegation[] memory delegations =
            _nDelegations(2, proposerPrivateKey, 1, committer, slot, signingDomain, signingId, chainId);

        // Write the delegations to files
        _writeDelegation(delegations[0], delegationOneFile);
        _writeDelegation(delegations[1], delegationTwoFile);

        console.log("Equivocating delegations written to files");
        console.log("Delegation one file:", delegationOneFile);
        console.log("Delegation two file:", delegationTwoFile);
    }

    // forge script script/Slashing.s.sol:SlashingScript --sig "slashEquivocation(address,string,string,string)" $REGISTRY_ADDRESS $REGISTRATION_PROOF_FILE $DELEGATION_ONE_FILE $DELEGATION_TWO_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function slashEquivocation(
        address _registry,
        string memory registrationProofFile,
        string memory delegationOneFile,
        string memory delegationTwoFile
    ) external returns (uint256 slashAmountWei) {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Read the registration proof from file
        IRegistry.RegistrationProof memory proof = _readRegistrationProof(registrationProofFile);

        // Read the delegations from files
        ISlasher.SignedDelegation memory delegationOne = _readDelegation(delegationOneFile);
        ISlasher.SignedDelegation memory delegationTwo = _readDelegation(delegationTwoFile);

        // Print for the user
        _prettyPrintPubKey(proof.registration);

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call slashEquivocation
        slashAmountWei = registry.slashEquivocation(proof, delegationOne, delegationTwo);

        console.log("Slashed collateral:", slashAmountWei);

        vm.stopBroadcast();
    }

    // forge script script/Slashing.s.sol:SlashingScript --sig "slashCommitment(address,string,string,string,bytes)" $REGISTRY_ADDRESS $REGISTRATION_PROOF_FILE $DELEGATION_ONE_FILE $COMMITMENT_FILE $EVIDENCE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function slashCommitment(
        address _registry,
        string memory registrationProofFile,
        string memory delegationFile,
        string memory commitmentFile,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei) {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Read the registration proof from file
        IRegistry.RegistrationProof memory proof = _readRegistrationProof(registrationProofFile);

        // Print for the user
        console.log("Slashing user with registration root: ", vm.toString(proof.registrationRoot));
        _prettyPrintPubKey(proof.registration);

        // Read the commitment from file
        ISlasher.SignedCommitment memory commitment = _readCommitment(commitmentFile);

        // Read the delegation from file
        ISlasher.SignedDelegation memory delegation = _readDelegation(delegationFile);

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call slashCommitment
        slashAmountWei = registry.slashCommitment(proof, delegation, commitment, evidence);

        console.log("Slashed collateral:", slashAmountWei);

        vm.stopBroadcast();
    }

    // forge script script/Slashing.s.sol:SlashingScript --sig "slashCommitmentFromOptIn(address,bytes32,string,bytes)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $COMMITMENT_FILE $EVIDENCE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function slashCommitmentFromOptIn(
        address _registry,
        bytes32 registrationRoot,
        string memory commitmentFile,
        bytes calldata evidence
    ) external returns (uint256 slashAmountWei) {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Print for the user
        console.log("Registration root:", vm.toString(registrationRoot));

        // Read the commitment from file
        ISlasher.SignedCommitment memory commitment = _readCommitment(commitmentFile);

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call slashCommitment
        slashAmountWei = registry.slashCommitment(registrationRoot, commitment, evidence);

        console.log("Slashed collateral:", slashAmountWei);

        vm.stopBroadcast();
    }

    function _testDelegation(address owner, address committer, uint256 committerPrivateKey)
        internal
        returns (ISlasher.SignedDelegation memory signedDelegation)
    {
        // Read the signing domain and chain ID from the config file
        (bytes32 signingDomain, bytes32 chainId) = _defaultSigningParams();

        // hardcoded committer
        (address _committer, uint256 _committerPrivateKey) = makeAddrAndKey("committer");

        // sign the delegation
        uint256 proposerPrivateKey = uint256(keccak256(abi.encode(owner)));
        signedDelegation = _signTestDelegation(
            proposerPrivateKey,
            ISlasher.Delegation({
                proposer: BLSUtils.toPublicKey(proposerPrivateKey),
                delegate: BLSUtils.toPublicKey(0), // unused
                committer: _committer,
                slot: 5,
                metadata: ""
            }),
            signingDomain,
            keccak256("test-signing-id"),
            uint64(0), // nonce
            chainId
        );
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    /// forge script script/Slashing.s.sol:SlashingScript --sig "prepareSlashing(address,address,bytes32,string,string,bytes)" $REGISTRY_ADDRESS $OWNER $REGISTRATION_ROOT $DELEGATION_ONE_FILE $COMMITMENT_FILE $EVIDENCE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function prepareSlashing(
        address _registry,
        address owner,
        bytes32 registrationRoot,
        string memory delegationFile,
        string memory commitmentFile,
        bytes calldata evidence
    ) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Deploy a dummy slasher contract
        address dummySlasher = address(new DummySlasher());

        // hardcoded committer
        (address _committer, uint256 _committerPrivateKey) = makeAddrAndKey("committer");

        // sign the delegation
        ISlasher.SignedDelegation memory signedDelegation = _testDelegation(owner, _committer, _committerPrivateKey);

        // Get signing parameters
        (bytes32 signingDomain, bytes32 chainId) = _defaultSigningParams();
        bytes32 signingId = keccak256("test-signing-id");
        uint64 nonce = 1;

        // sign the commitment
        ISlasher.SignedCommitment memory signedCommitment =
            _signTestCommitment(_committerPrivateKey, dummySlasher, 0, "", signingId, nonce, chainId, signingDomain);

        // sanity check verify signature as the URC would
        bytes32 messageHash = keccak256(abi.encode(signedCommitment.commitment));
        address committerRecovered = ECDSAUtils.recover(
            messageHash,
            signedCommitment.signature,
            signingDomain,
            signedCommitment.signingId,
            signedCommitment.nonce,
            chainId
        );
        if (committerRecovered != _committer) {
            revert("Recovered committer does not match");
        }

        // write the signed delegation to file
        _writeDelegation(signedDelegation, delegationFile);
        console.log("wrote delegation to file:", delegationFile);

        // write signed commitment to file
        _writeCommitment(signedCommitment, commitmentFile);
        console.log("wrote commitment to file:", commitmentFile);

        // sanity check read commitment from file
        ISlasher.SignedCommitment memory s = _readCommitment(commitmentFile);
        messageHash = keccak256(abi.encode(s.commitment));
        committerRecovered = ECDSAUtils.recover(messageHash, s.signature, signingDomain, s.signingId, s.nonce, chainId);
        if (committerRecovered != _committer) {
            revert("Recovered committer does not match");
        }

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call optInToSlasher
        registry.optInToSlasher(registrationRoot, dummySlasher, _committer);

        console.log("Opted in to dummy slasher:", vm.toString(dummySlasher));

        vm.stopBroadcast();
    }
}
