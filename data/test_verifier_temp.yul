object "plonk_verifier" {
    code {
        function allocate(size) -> ptr {
            ptr := mload(0x40)
            if eq(ptr, 0) { ptr := 0x60 }
            mstore(0x40, add(ptr, size))
        }
        let size := datasize("Runtime")
        let offset := allocate(size)
        datacopy(offset, dataoffset("Runtime"), size)
        return(offset, size)
    }
    object "Runtime" {
        code {
            let success:bool := true

            if not(success) { revert(0, 0) }
            return(0, 0)
        }
    }
}