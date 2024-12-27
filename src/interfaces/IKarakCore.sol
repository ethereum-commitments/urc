// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.25;

interface IKarakCore {
    /// Checks whether the given asset is allowlisted.
    /// @param asset address of the asset.
    function isAssetAllowlisted(address asset) external returns (bool);
}
