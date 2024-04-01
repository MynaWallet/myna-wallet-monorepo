// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "@libraries/AccountStorage.sol";
import "@libraries/Errors.sol";
import "@auth/Auth.sol";

/// @title RecoveryManager contract
/// @author a42x
/// @notice You can use this contract for recovery manager
abstract contract RecoveryManager is Auth {
    /// @notice Length of the RSA public key modulus
    uint256 private constant _MODULUS_LENGTH = 256;
    /// @notice Exponent of the RSA public key
    bytes internal constant _EXPONENT =
        hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";

    modifier onlyRecoveryManager() {
        require(msg.sender == AccountStorage.layout().recoveryManager, "RecoveryManager: only recovery manager");
        _;
    }

    /// @notice Set new recovery manager
    /// @param newRecoveryManager new recovery manager address
    function setRecoveryManager(address newRecoveryManager) external onlySelf {
        _setRecoveryManager(newRecoveryManager);
    }

    /// @notice Recover owner modulus
    function executeRecovery(bytes memory newOwner, bytes memory cert) external onlyRecoveryManager {
        /// todo validate cert from trusted party that proves the registered recovery manager is the MynaWallet contract
        ///      and the new owner modulus is the valid RSA modulus on the new Myna Card issed by the government.
        (cert);

        AccountStorage.layout().owner = newOwner;
    }

    /// @notice Get Recovery Manager address
    /// @return recoveryManager Recovery Manager address
    function getRecoveryManager() public view returns (address recoveryManager) {
        return AccountStorage.layout().recoveryManager;
    }

    /// @notice Set new recovery manager
    /// @param newRecoveryManager new recovery manager address
    function _setRecoveryManager(address newRecoveryManager) internal {
        AccountStorage.layout().recoveryManager = newRecoveryManager;
    }
}
