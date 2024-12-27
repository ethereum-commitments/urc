// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {MapWithTimeData} from "../lib/MapWithTimeData.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";
import {IBoltMiddlewareV1} from "../interfaces/IBoltMiddlewareV1.sol";
import {IBoltManagerV1} from "../interfaces/IBoltManagerV1.sol";
import {IKarakCore} from "../interfaces/IKarakCore.sol";

import {BaseDSS} from "karak-onchain-sdk/BaseDSS.sol";
import {IKarakBaseVault} from "../lib/karak-onchain-sdk/interfaces/IKarakBaseVault.sol";

/// @title Bolt Karak Middleware contract.
/// @notice This contract is responsible for interfacing with the Karak restaking protocol.
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltKarakMiddlewareV1 is BaseDSS, IBoltMiddlewareV1, OwnableUpgradeable, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    // ========= STORAGE =========

    /// @notice Start timestamp of the first epoch.
    uint48 public START_TIMESTAMP;

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltManagerV1 public manager;

    /// @notice Set of vault's assets that are used in Bolt Protocol.
    EnumerableMap.AddressToUintMap private assets;

    /// @notice Name hash of the restaking protocol for identifying the instance of `IBoltMiddleware`.
    bytes32 public NAME_HASH;

    // --> Storage layout marker: 9 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[44] private __gap;

    // ========= ERRORS =========

    error AssetNotAllowed();

    constructor() {
        _disableInitializers();
    }
    // ========= INITIALIZER & PROXY FUNCTIONALITY ========= //

    /// @notice Constructor for the BoltKarakMiddleware contract.
    /// @param _parameters The address of the Bolt Parameters contract.
    /// @param _manager The address of the Bolt Manager contract.
    /// @param _core The address of the karak core contract.
    /// @param _maxSlashablePercentageWad The maximum percentageWad that can be slashed by DSS.
    function initialize(
        address _owner,
        address _parameters,
        address _manager,
        address _core,
        uint256 _maxSlashablePercentageWad
    ) public initializer {
        __Ownable_init(_owner);
        _init(_core, _maxSlashablePercentageWad);
        parameters = IBoltParametersV1(_parameters);
        manager = IBoltManagerV1(_manager);
        START_TIMESTAMP = Time.timestamp();

        NAME_HASH = keccak256("KARAK");
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the start timestamp of an epoch.
    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return START_TIMESTAMP + epoch * parameters.EPOCH_DURATION();
    }

    /// @notice Get the epoch at a given timestamp.
    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        return (timestamp - START_TIMESTAMP) / parameters.EPOCH_DURATION();
    }

    /// @notice Get the current epoch.
    function getCurrentEpoch() public view returns (uint48 epoch) {
        return getEpochAtTs(Time.timestamp());
    }

    function getWhitelistedAssets() public view returns (address[] memory) {
        return assets.keys();
    }

    // ========= ADMIN FUNCTIONS =========
    /// @notice Register a asset to work in Bolt Protocol.
    /// @param asset The asset's address
    function registerAsset(
        address asset
    ) public onlyOwner {
        if (assets.contains(asset)) {
            revert AlreadyRegistered();
        }

        if (!IKarakCore(core()).isAssetAllowlisted(asset)) {
            revert AssetNotAllowed();
        }

        assets.add(asset);
        assets.enable(asset);
    }

    /// @notice Deregister a asset to work from Bolt Protocol.
    /// @param asset The asset's address
    function deregisterAsset(
        address asset
    ) public onlyOwner {
        if (!assets.contains(asset)) {
            revert NotRegistered();
        }

        assets.remove(asset);
    }

    // ========= KARAK MIDDLEWARE LOGIC =========

    /// @notice Check if a asset is currently enabled to work in Bolt Protocol.
    /// @param asset The asset address to check the enabled status for.
    /// @return True if the asset is enabled, false otherwise.
    function isAssetEnabled(
        address asset
    ) public view returns (bool) {
        (uint48 enabledTime, uint48 disabledTime) = assets.getTimes(asset);
        return enabledTime != 0 && disabledTime == 0;
    }

    /// @notice Get the collaterals and amounts staked by an operator across the supported assets.
    ///
    /// @param operator The operator address to get the collaterals and amounts staked for.
    /// @return collaterals The collaterals staked by the operator.
    /// @dev Assumes that the operator is registered and enabled.
    /// @dev When multiple vaults with same collateral exists, the total amount staked for that collateral is the sum of each amount.
    function getOperatorCollaterals(
        address operator
    ) public view returns (address[] memory, uint256[] memory) {
        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));

        address[] memory stakedVaults = getActiveVaults(operator);
        address[] memory collateralTokens = new address[](stakedVaults.length);
        uint256[] memory amounts = new uint256[](stakedVaults.length);

        for (uint256 i = 0; i < stakedVaults.length; ++i) {
            address asset = IKarakBaseVault(stakedVaults[i]).asset();
            (uint48 enabledTime, uint48 disabledTime) = assets.getTimes(asset);

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }
            collateralTokens[i] = asset;
            amounts[i] = _getVaultActiveBalance(stakedVaults[i]);
        }

        return (collateralTokens, amounts);
    }

    /// @notice Get the amount of tokens delegated to an operator across the allowed assets.
    /// @param operator The operator address to get the stake for.
    /// @param collateral The collateral address to get the stake for.
    /// @return amount The amount of tokens delegated to the operator of the specified collateral.
    function getOperatorStake(address operator, address collateral) public view returns (uint256 amount) {
        uint48 timestamp = Time.timestamp();
        return getOperatorStakeAt(operator, collateral, timestamp);
    }

    /// @notice Get the stake of an operator in Karak protocol at a given timestamp.
    /// @param operator The operator address to check the stake for.
    /// @param collateral The collateral address to check the stake for.
    /// @param timestamp The timestamp to check the stake at.
    /// @return amount The stake of the operator at the given timestamp, in collateral token.
    function getOperatorStakeAt(
        address operator,
        address collateral,
        uint48 timestamp
    ) public view returns (uint256 amount) {
        if (timestamp > Time.timestamp() || timestamp < START_TIMESTAMP) {
            revert InvalidQuery();
        }

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(timestamp));

        address[] memory stakedVaults = getActiveVaults(operator);

        for (uint256 i = 0; i < stakedVaults.length; ++i) {
            address asset = IKarakBaseVault(stakedVaults[i]).asset();
            (uint48 enabledTime, uint48 disabledTime) = assets.getTimes(asset);

            if (asset != collateral) {
                continue;
            }

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }
            amount += _getVaultActiveBalance(stakedVaults[i]);
        }

        return amount;
    }

    // ========= HELPER FUNCTIONS =========

    /// @notice Check if a map entry was active at a given timestamp.
    /// @param enabledTime The enabled time of the map entry.
    /// @param disabledTime The disabled time of the map entry.
    /// @param timestamp The timestamp to check the map entry status at.
    /// @return True if the map entry was active at the given timestamp, false otherwise.
    function _wasEnabledAt(uint48 enabledTime, uint48 disabledTime, uint48 timestamp) private pure returns (bool) {
        return enabledTime != 0 && enabledTime <= timestamp && (disabledTime == 0 || disabledTime >= timestamp);
    }

    /// @notice Returns the amount of assets that aren't queued for withdrawals.
    /// @param vault Address of the vault.
    function _getVaultActiveBalance(
        address vault
    ) internal view returns (uint256) {
        uint256 sharesNotQueuedForWithdrawal =
            IERC20Metadata(vault).totalSupply() - IERC20Metadata(vault).balanceOf(vault);
        uint256 assetBalance = IERC4626(vault).convertToAssets(sharesNotQueuedForWithdrawal);
        return assetBalance;
    }
}
