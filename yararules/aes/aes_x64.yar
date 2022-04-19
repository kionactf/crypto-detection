rule AES_bytecode_openssl_x64 {
    meta:
        description = "Look for opcodes for AES x64"
        date = "2022-04"
    strings:
        $c0 = {45 33 ?4 ?? 03}//xor    0x3(%r?,%r?,8),%r?
        $c1 = {45 33 ?4 ?? 02}//xor    0x2(%r?,%r?,8),%r?
        $c2 = {45 33 ?4 ?? 01}//xor    0x1(%r?,%r?,8),%r?
    condition:
        $c0 and $c1 and $c2
}

//TODO: AES_bytecode_openssl_x64_compact

rule AES_bytecode_AESNI_x64 {
    meta:
        description = "Look for opcodes for AES NI x64"
        date = "2022-04"
    strings:
        $c0 = {66 0f 38 dc ??}//aesenc %xmm?,%xmm?
        $c1 = {66 0f 38 de ??}//aesdec %xmm?,%xmm?
        $c2 = {c4 ?2 ?? dc ??}//vaesenc %xmm?,%xmm?,%xmm?
        $c3 = {c4 ?2 ?? de ??}//vaesdec %xmm?,%xmm?,%xmm?
    condition:
        $c0 or $c1 or $c2 or $c3
}

rule AES_openssl_vpaes_x64 {
    meta:
        description = "Look for constants for AES implementation on openssl vpaes x64"
        date = "2022-04"
    strings:
        $c0 = {80 01 08 0d 0f 06 05 0e 02 0c 0b 0a 09 03 07 04}//inv
    condition:
        $c0
}
