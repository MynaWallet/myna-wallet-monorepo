// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "@libraries/AccountStorage.sol";
import "@libraries/Errors.sol";
import "@auth/Auth.sol";
import "@external/webauthn-sol/WebAuthn.sol";

/// @title OwnerManager contract
/// @author a42x
/// @notice You can use this contract for owner manager
abstract contract PasskeyManager is Auth {
    /// @notice Set new passkey
    /// @param newPasskey new passkey
    function setPasskey(bytes32[2] calldata newPasskey) external onlySelf {
        _setPasskey(newPasskey);
    }

    /// @notice Recover owner modulus
    function executeRecoveryByPasskey(
        bytes memory newOwner,
        bytes memory cert,
        bytes32 challenge,
        bytes memory signature
    ) external {
        /// todo validate cert from trusted party that proves the new owner modulus is the valid RSA modulus on the new Myna Card issed by the government.
        (cert);

        // validate R1 signature
        (bytes32 x, bytes32 y) = getPasskey();
        bool isValid = WebAuthn.verify({
            challenge: abi.encode(challenge),
            requireUV: true,
            webAuthnAuth: abi.decode(signature, (WebAuthn.WebAuthnAuth)),
            x: uint256(x),
            y: uint256(y)
        });
        if (!isValid) {
            revert Errors.INVALID_SIGNATURE();
        }

        AccountStorage.layout().owner = newOwner;
    }

    /// @notice Get passkey
    /// @return passkey passkey
    function getPasskey() public view returns (bytes32[2] memory passkey) {
        return AccountStorage.layout().passkey;
    }

    /// @notice Set new passkey
    /// @param newPasskey new passkey
    function _setPasskey(bytes32[2] calldata newPasskey) internal {
        AccountStorage.layout().passkey = newPasskey;
    }
}
