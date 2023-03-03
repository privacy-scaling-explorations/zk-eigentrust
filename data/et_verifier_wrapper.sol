// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

contract EtVerifierWrapper {
    struct Proof {
        uint256[] pub_ins;
        bytes proof;
    }
    
    address verifier_address;
    
    constructor(address vaddr) {
      verifier_address = vaddr;   
   }

    function verify(Proof calldata proof) public {
        assembly {
             // function Error(string)
             function revertWith (msg) {
                mstore(0, shl(224, 0x08c379a0))
                mstore(4, 32)
                mstore(68, msg)
                let msgLen
                for {} msg {} {
                    msg := shl(8, msg)
                    msgLen := add(msgLen, 1)
                }
                mstore(36, msgLen)
                revert(0, 100)
            }

            let addr := sload(verifier_address.slot)
            switch extcodesize(addr)
            case 0 {
                // no code at `verifier_address`
                revertWith("verifier-missing")
            }
            
            let proof_pos := mload(0x40)
            let proof_size := calldatasize()
            calldatacopy(proof_pos, 0, proof_size)

            let success := staticcall(gas(), addr, proof_pos, proof_size, 0, 0)
            switch success
            case 0 {
                // plonk verification failed
                revertWith("verification-failed")
            }
        }
    }
}