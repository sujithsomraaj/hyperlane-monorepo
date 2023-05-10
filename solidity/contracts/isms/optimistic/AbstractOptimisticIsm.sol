// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.6.11;

import {Message} from "../../libs/Message.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";

abstract contract AbstractOptimisticIsm is IOptimisticIsm, Ownable {
    using Message for bytes;

    /// @dev allows owner to config their fraudWindow in seconds
    uint256 public immutable fraudWindow; /// @notice: should this be configurable??

    /// @dev allows owner to configure their ism; cannot be flagged ism
    IInterchainSecurityModule public defaultIsm;
    /// @dev time at which the ism (submodule) is flagged
    mapping(address => uint256) public ismFlaggedTime;
    ///@dev maps message id to pre-verified ism.
    mapping(bytes32 => address) public verifiedIsm;
    /// @dev maps message id to pre-verified time.
    mapping(bytes32 => uint256) public verifiedTime;
    /// @dev maps the address to watcher role (@notice: can use RBAC)
    mapping(address => bool) public watcher;

    modifier onlyWatcher() {
        require(watcher[msg.sender], "!watcher");
        _;
    }

    constructor(uint256 _fraudWindow, IInterchainSecurityModule _defaultIsm) {
        fraudWindow = _fraudWindow;
        defaultIsm = _defaultIsm;
    }

    /// @dev allows verification of message
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external override returns (bool verified) {
        bool verified = defaultIsm.verify(_metadata, _message);
        require(verified, "!verify");

        bytes32 messageId = _message.id();

        /// @dev allows preverify if the old ism is flagged, and a new ism
        /// is added to the contract by admin to attempt redelivery of message
        require(
            verifiedTime[messageId] == 0 &&
                verifiedIsm[messageId] == address(defaultIsm),
            "proposed"
        );

        verifiedTime[messageId] = block.timestamp;
        verifiedIsm[messageId] = address(defaultIsm);
    }

    /// @dev allows owner to add watcher
    function enrollWatcher(address _watcher) external override onlyOwner {
        require(_watcher != address(0), "zero address");

        watcher[_watcher] = true;
    }

    /// @dev allows owner to remove watcher
    function unenrollWatcher(address _watcher) external override onlyOwner {
        require(_watcher != address(0), "zero address");

        watcher[_watcher] = false;
    }

    /// @dev allows watcher to flag an ISM
    function markFradulent(address _ism) external override onlyWatcher {
        require(_ism != address(0), "zero address");

        /// @note 1 of n is considered valid here
        ismFlaggedTime[_ism] = block.timestamp;
    }

    /// @dev allows owner to switch the default ism (if blacklisted)
    function switchIsm(address _ism) external onlyOwner {
        address prevIsm = address(defaultIsm);
        require(ismFlag[prevIsm], "!flagged");

        defaultIsm = IInterchainSecurityModule(_ism);
    }

    /// @dev returns true is the message & metadata is valid
    /// and passed the cooldown period.
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool verified) {
        bytes32 messageId = _message.id();
        address ism = verifiedIsm[messageId];
        uint256 timeOfVerification = verifiedTime[messageId];

        if (ism == address(0)) return false; // if message not verified
        if (
            ismFlaggedTime[ism] > timeOfVerification &&
            ismFlaggedTime[ism] + fraudWindow < timeOfVerification
        ) return false; // if ism is flagged within the fraud window

        if (block.timestamp - timeOfVerification < fraudWindow) return false; /// if fraudWindow elapsed

        /// do validations once again (can be removed if not needed)
        verified = defaultIsm.verify(_metadata, _message);
        return false;
    }
}
