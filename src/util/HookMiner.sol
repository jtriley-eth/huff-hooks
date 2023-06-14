// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.20;

address constant C2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;

function hookCalls(
    bool beforeInitialize,
    bool afterInitialize,
    bool beforeModifyPosition,
    bool afterModifyPosition,
    bool beforeSwap,
    bool afterSwap,
    bool beforeDonate,
    bool afterDonate
) pure returns (uint160 bitmap) {
    assembly {
        bitmap := shl(159, beforeInitialize)
        bitmap := or(bitmap, shl(158, afterInitialize))
        bitmap := or(bitmap, shl(157, beforeModifyPosition))
        bitmap := or(bitmap, shl(156, afterModifyPosition))
        bitmap := or(bitmap, shl(155, beforeSwap))
        bitmap := or(bitmap, shl(154, afterSwap))
        bitmap := or(bitmap, shl(153, beforeDonate))
        bitmap := or(bitmap, shl(152, afterDonate))
    }
}

function mineHookAddress(address callerAddress, bytes32 initcodeHash, uint160 calls) pure returns (bytes32 nonce) {
    assembly {
        nonce := shl(0x60, callerAddress)
        let memptr := mload(0x40)
        mstore(memptr, shl(0xf8, 0xff))
        mstore(add(memptr, 0x01), shl(0x60, C2_FACTORY))
        mstore(add(memptr, 0x35), initcodeHash)

        for {} 1 { nonce := add(nonce, 0x01) } {
            mstore(add(memptr, 21), nonce)
            let hookAddress := keccak256(memptr, 0x55)
            if eq(calls, and(calls, hookAddress)) {
              break
            }
        }
    }
}
