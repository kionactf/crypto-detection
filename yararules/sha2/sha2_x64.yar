rule SHA256_bytecode_x64 {
    meta:
        description = "Look for bytecode SHA256 on x64"
        date = "2022-04"
    strings:
        $c0_0 = {c1 c? 06}//ror 0x6,??
        $c0_1 = {c1 c? 1a}//rol 0x1a,??
        $c1_0 = {c1 c? 0b}//ror 0xb,??
        $c1_1 = {c1 c? 15}//rol 0x15,??
        $c2_0 = {c1 c? 07}//rol 0x7,??
        $c2_1 = {c1 c? 19}//ror 0x19,??
        $c3_0 = {c1 c? 02}//ror 0x2,??
        $c3_1 = {c1 c? 1e}//rol 0x1e,??
        $c4_0 = {c1 c? 0d}//ror 0xd,??
        $c4_1 = {c1 c? 13}//rol 0x13,??
        $c5_0 = {c1 c? 0a}//rol 0xa,??
        $c5_1 = {c1 c? 16}//ror 0x16,??
    condition:
        ($c0_0 or $c0_1) and ($c1_0 or $c1_1) and ($c2_0 or $c2_1) and ($c3_0 or $c3_1) and ($c4_0 or $c4_1) and ($c5_0 or $c5_1)
}

rule SHA256_bytecode_x64_openssl {
    meta:
        description = "Look for SHA256 bytecode for x64 on openssl"
        date = "2022-04"
    strings:
        $c0 = {c1 c? 0b}//ror 0xb
        $c1 = {c1 c? 02}//ror 0x2
        $c2 = {c1 c? 07}//ror 0x7
        $c3 = {c1 c? 11}//ror 0x11
        $c4 = {c1 c? 0e}//ror 0xe
        $c5 = {c1 c? 09}//ror 0x9
        $c6 = {c1 c? 05}//ror 0x5
        $c7 = {c1 c? 0b}//ror 0xb
        $c8 = {c1 c? 06}//ror 0x6
        $c9 = {c1 c? 02}//ror 0x2
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5 and $c6 and $c7 and $c8 and $c9
}

rule SHA256_bytecode_x64_intelsha256 {
    meta:
        description = "Look for SHA256 bytecode for x64 intel instruction"
        date = "2022-04"
    strings:
        $c0 = {45 0f 38 cc ??}//sha256msg1 xmm?,xmm?
    condition:
        $c0
}

rule SHA256_bytecode_x64_openssl_ssse3 {
    meta:
        description = "Look for SHA256 bytecode for x64 sse3 openssl"
        date = "2022-04"
    strings:
        $c0 = {66 0f 72 d? 03}//psrld 0x3,xmm?
        $c1 = {66 0f 72 d? 07}//psrld 0x7,xmm?
        $c2 = {66 0f 72 f? 0e}//pslld 0xe,xmm?
        $c3 = {66 0f 72 d? 0b}//psrld 0xb,xmm?
        $c4 = {66 0f 72 f? 0b}//pslld 0xb,xmm?
        $c5 = {66 0f 72 d? 0a}//psrld 0xa,xmm?
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

rule SHA256_bytecode_x64_openssl_avx {
    meta:
        description = "Look for SHA256 bytecode for x64 avx openssl"
        date = "2022-04"
    strings:
        $c0 = {c5 ?9 72 d? 07}//vpsrld 0x7,xmm?,xmm?
        $c1 = {c5 ?1 72 d? 03}//vpsrld 0x3,xmm?,xmm?
        $c2 = {c5 ?1 72 f? 0e}//vpslld 0xe,xmm?,xmm?
        $c3 = {c5 ?9 72 d? 0b}//vpsrld 0xb,xmm?,xmm?
        $c4 = {c5 ?1 72 f? 0b}//vpslld 0xb,xmm?,xmm?
        $c5 = {c5 ?9 72 d? 0a}//vpsrld 0xa,xmm?,xmm?
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

rule SHA256_bytecode_x64_openssl_avx2 {
    meta:
        description = "Look for SHA256 bytecode for x64 avx2 openssl"
        date = "2022-04"
    strings:
        $c0 = {c4 ?? 7b f0 ?? 06}//rorx 0x6,??,??
        $c1 = {c4 ?? 7b f0 ?? 0b}//rorx 0xb,??,??
        $c2 = {c4 ?? 7b f0 ?? 19}//rorx 0x19,??,??
        $c3 = {c4 ?? 7b f0 ?? 02}//rorx 0x2,??,??
        $c4 = {c4 ?? 7b f0 ?? 0d}//rorx 0xd,??,??
        $c5 = {c4 ?? 7b f0 ?? 16}//rorx 0x16,??,??
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

rule SHA512_bytecode_x64 {
    meta:
        description = "Look for bytecode SHA512 on x64"
        date = "2022-04"
    strings:
        $c0_0 = {c1 c? 0e}//ror 0xe,??
        $c0_1 = {c1 c? 32}//rol 0x32,??
        $c1_0 = {c1 c? 12}//ror 0x12,??
        $c1_1 = {c1 c? 2e}//rol 0x2e,??
        $c2_0 = {c1 c? 17}//rol 0x17,??
        $c2_1 = {c1 c? 29}//ror 0x29,??
        $c3_0 = {c1 c? 1c}//ror 0x1c,??
        $c3_1 = {c1 c? 24}//rol 0x24,??
        $c4_0 = {c1 c? 22}//ror 0x22,??
        $c4_1 = {c1 c? 1e}//rol 0x1e,??
        $c5_0 = {c1 c? 19}//rol 0x19,??
        $c5_1 = {c1 c? 27}//ror 0x27,??
    condition:
        ($c0_0 or $c0_1) and ($c1_0 or $c1_1) and ($c2_0 or $c2_1) and ($c3_0 or $c3_1) and ($c4_0 or $c4_1) and ($c5_0 or $c5_1)
}

rule SHA512_bytecode_x64_openssl {
    meta:
        description = "Look for SHA512 bytecode for x64 on openssl"
        date = "2022-04"
    strings:
        $c0 = {c1 c? 07}//ror 0x7
        $c1 = {c1 c? 2a}//ror 0x2a
        $c2 = {d1 c?}//ror
        $c3 = {c1 c? 13}//ror 0x13
        $c4 = {c1 c? 17}//ror 0x17
        $c5 = {c1 c? 05}//ror 0x5
        $c6 = {c1 c? 04}//ror 0x4
        $c7 = {c1 c? 06}//ror 0x6
        $c8 = {c1 c? 0e}//ror 0xe
        $c9 = {c1 c? 1c}//ror 0x1c
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5 and $c6 and $c7 and $c8 and $c9
}


rule SHA512_bytecode_x64_openssl_xop {
    meta:
        description = "Look for SHA512 bytecode for x64 xop openssl"
        date = "2022-04"
    strings:
        $c0 = {8f 48 ?? c3 ?? 38}//vprotq 0x38,xmm?,xmm?
        $c1 = {c4 c1 ?9 73 d? 07}//vpsrlq 0x7,xmm?,xmm?
        $c2 = {8f 48 ?? c3 ?? 07}//vprotq 0x7,xmm?,xmm?
        $c3 = {8f 68 ?? c3 ?? 03}//vprotq 0x3,xmm?,xmm?
        $c4 = {c5 ?9 73 d? 06}//vpsrlq 0x6,xmm?,xmm?
        $c5 = {8f 48 ?? c3 ?? 2a}//vprotq 0x2a,xmm?,xmm?
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

rule SHA512_bytecode_x64_openssl_avx {
    meta:
        description = "Look for SHA512 bytecode for x64 avx openssl"
        date = "2022-04"
    strings:
        $c0 = {c4 c1 2? 73 d? 01}//vpsrlq 0x1,xmm?,%xmm?
        $c1 = {c4 c1 2? 73 d? 07}//vpsrlq 0x7,xmm?,xmm?
        $c2 = {c4 c1 3? 73 f? 38}//vpsllq 0x38,xmm?,xmm?
        $c3 = {c4 c1 2? 73 d? 07}//vpsrlq 0x7,xmm?,xmm?
        $c4 = {c4 c1 3? 73 f? 07}//vpsllq 0x7,xmm?,xmm?
        $c5 = {c5 ?1 73 d? 06}// vpsrlq 0x6,xmm?,xmm?
        $c6 = {c5 ?9 73 f? 03}// vpsllq 0x3,xmm?,xmm?
        $c7 = {c5 ?1 73 d? 13}//vpsrlq 0x13,xmm?,xmm?
        $c8 = {c4 c1 2? 73 f? 2a}//vpsllq 0x2a,xmm?,xmm?
        $c9 = {c4 c1 3? 73 d? 2a}//vpsrlq 0x2a,xmm?,xmm?
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5 and $c6 and $c7 and $c8 and $c9
}

rule SHA512_bytecode_x64_openssl_avx2 {
    meta:
        description = "Look for SHA512 bytecode for x64 avx2 openssl"
        date = "2022-04"
    strings:
        $c0 = {c4 ?? fb f0 ?? 29}//rorx 0x29,??,??
        $c1 = {c4 ?? fb f0 ?? 12}//rorx 0x12,??,??
        $c2 = {c4 ?? fb f0 ?? 0e}//rorx 0xe,??,??
        $c3 = {c4 ?? fb f0 ?? 27}//rorx 0x27,??,??
        $c4 = {c4 ?? fb f0 ?? 22}//rorx 0x22,??,??
        $c5 = {c4 ?? fb f0 ?? 1c}//rorx 0x1c,??,??
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

