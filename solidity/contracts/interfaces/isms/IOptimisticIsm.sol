// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.6.11;

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";

interface IOptimisticIsm is IInterchainSecurityModule {
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool);

    function markFradulent(address _ism) external;

    function fraudWindow() external view returns (uint256);
}
