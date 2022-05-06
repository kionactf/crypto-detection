rule SHA1_bytecode_x64 {
    meta:
        description = "Look for opcodes for SHA1 x64"
        date = "2022-04"
    strings:
        $c3_0 = {c1 c? 05}//rol 0x5,??
        $c3_1 = {c1 c? 1b}//ror 0x1b,??
        $c4_0 = {c1 c? 02}//ror 0x2,??
        $c4_1 = {c1 c? 1e}//rol 0x1e,??
    condition:
        ($c3_0 or $c3_1) and ($c4_0 or $c4_1)
}

rule SHA1_bytecode_x64_intelsha1 {
    meta:
        description = "Look for opcodes for SHA1 instruction on x64/intel"
        date = "2022-04"
    strings:
        $c0 = {0f 38 c9 ??}//sha1msg xmm?,xmm?
    condition:
        $c0
}

rule SHA1_bytecode_x64_openssl_ssse3 {
    meta:
        description = "Look for opcodes for SHA1 on openssl sse3"
        date = "2022-04"
    strings:
        $c0 = {66 41 0f 73 d? 04}//psrldq $0x4,%xmm?
        $c1 = {66 41 0f 73 f? 0c}//pslldq $0xc,%xmm?
        $c2 = {66 41 0f 72 d? 1f}//psrld  $0x1f,%xmm?
        $c3 = {66 41 0f 72 d? 1e}//psrld  $0x1e,%xmm?
        $c4 = {66 41 0f 72 f? 02}//pslld  $0x2,%xmm?
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4
}

rule SHA1_bytecode_x64_openssl_avx {
    meta:
        description = "Look for opcodes for SHA1 on openssl avx"
        date = "2022-04"
    strings:
        $c0 = {0f a4 ?? 05}//shld 0x5,??,??
        $c1 = {0f ac ?? 07}//shrd 0x7,??,??
    condition:
        $c0 and $c1
}

rule SHA1_bytecode_x64_openssl_avx2 {
    meta:
        description = "Look for opcodes for SHA1 on openssl avx2"
        date = "2022-04"
    strings:
        $c0 = {c4 63 7b f0 ?? 1b}// rorx 0x1b,e??,r??
        $c1 = {c4 e3 7b f0 ?? 02}// rorx 0x2,e??,r??
        $c2 = {c5 ?d 72 d? 1e}//vpsrld 0x1e,ymm?,ymm?
        $c3 = {c5 ?5 72 f? 02}//vpslld 0x2,ymm?,%ymm?
    condition:
        $c0 and $c1 and $c2 and $c3
}
