// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/IRegistry.sol";
import "./BaseScript.s.sol";

contract RegisterScript is BaseScript {
    // forge script script/Register.s.sol:RegisterScript --sig "register(address,uint256,bytes32,string)" $REGISTRY_ADDRESS $COLLATERAL $SIGNING_ID $SIGNED_REGISTRATIONS_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function register(
        address _registry,
        uint256 collateralWei,
        bytes32 signingId,
        string memory signedRegistrationsFile
    ) external returns (bytes32 registrationRoot) {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Read user's pre-signed registrations
        (address owner, IRegistry.SignedRegistration[] memory registrations) =
            _readSignedRegistrations(signedRegistrationsFile);

        // Confirm with user
        string memory prompt = string(abi.encodePacked(vm.toString(owner), " is the correct owner? 1=yes, 0=no"));
        uint256 answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect owner address");

        prompt = string(abi.encodePacked(vm.toString(collateralWei), " is the correct collateral? 1=yes, 0=no"));
        answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect collateral amounts");

        prompt = string(abi.encodePacked(_buildPubkeyStrings(registrations), "are the correct pubkeys? 1=yes, 0=no"));
        answer = vm.promptUint(prompt);
        if (answer != 1) revert("incorrect pubkeys");

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call register
        registrationRoot = registry.register{ value: collateralWei }(registrations, owner, signingId);

        console.log("Success! got registrationRoot:", vm.toString(registrationRoot));

        vm.stopBroadcast();
    }

    // forge script script/Register.s.sol:RegisterScript --sig "unregister(address,bytes32)" $REGISTRY_ADDRESS $REGISTRATION_ROOT --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
    function unregister(address _registry, bytes32 registrationRoot) external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Confirm with user
        string memory prompt = string("Are you sure you want to unregister? 1=yes, 0=no");
        uint256 answer = vm.promptUint(prompt);
        if (answer != 1) revert("aborting");

        // Get reference to the registry
        IRegistry registry = IRegistry(_registry);

        // Call register
        registry.unregister(registrationRoot);

        // Logs
        console.log("Success! started unregistration process");
        console.log(
            string(
                abi.encodePacked(
                    "Can complete registration in ",
                    vm.toString(IRegistry(_registry).getConfig().unregistrationDelay),
                    " blocks"
                )
            )
        );

        vm.stopBroadcast();
    }

    /// @dev NOT MEANT FOR PRODUCTION USE
    /// @dev Signs N registration messages and writes them to `outfile`
    /// @dev Derives N dummy BLS private keys from the `owner` address
    /// @dev Reads the signing domain and chain ID from the default "config/registry.json" file
    // forge script script/Register.s.sol:RegisterScript --sig "nDummyRegistrations(uint256,address,string,bytes32)" $N $OWNER $SIGNED_REGISTRATIONS_FILE $SIGNING_ID
    function nDummyRegistrations(uint256 n, address owner, bytes32 signingId, string memory outfile) public {
        console.log("Running nDummyRegistrations()... WARNING do not use the output in production!!!");

        (bytes32 signingDomain, bytes32 chainId) = _defaultSigningParams();

        // The n'th private key will = startPrivateKey + n
        uint256 startPrivateKey = uint256(keccak256(abi.encode(owner)));

        // Sign the registration messages
        IRegistry.SignedRegistration[] memory registrations =
            _nRegistrations(n, startPrivateKey, owner, signingDomain, signingId, chainId);

        // Write them to a JSON file
        _writeSignedRegistrations(owner, registrations, outfile);

        // Read them back to the User
        // _readSignedRegistrations(outfile);
    }
}
