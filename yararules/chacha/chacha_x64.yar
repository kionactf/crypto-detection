
rule Chacha_rol_x64 {
    meta:
        description = "Look for rol opcodes on quarterround of Chacha stream cipher"
        date = "2022-04"
    strings:
        $c0 = {c1 c? 10}// rol 0x10,(reg)
        $c1 = {c1 c? 0c}// rol 0xc,(reg)
        $c2 = {c1 c? 08}// rol 0x8,(reg)
        $c3 = {c1 c? 07}// rol 0x7,(reg)
    condition:
        $c0 and $c1 and $c2 and $c3
}

rule ChaCha_rol_x64_openssl_SSE3 {
    meta:
        description = "Look for ROTATION code for SSE3 openssl on quarterround of Chacha stream cipher"
        date = "2022-04"
    strings:
        $c0 = {66 0f 72 d? 14} // psrld xmm? 0x14
        $c1 = {66 0f 72 f? 0c} // pslld xmm? 0x0c
        $c2 = {66 0f 72 d? 19} // psrld xmm? 0x19
        $c3 = {66 0f 72 f? 07} // pslld xmm? 0x07
        $c4 = {02 03 00 01 06 07 04 05 0a 0b 08 09 0e 0f 0c 0d} // rot16 for pshufb
        $c5 = {03 00 01 02 07 04 05 06 0b 08 09 0a 0f 0c 0d 0e} // rot25 for pshufb
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

rule ChaCha_rol_x64_openssl_8x {
    meta:
        description = "Look for ROTATION code for AVX2 openssl on quarterround of Chacha stream cipher"
        date = "2022-04"
    strings:
        $c0 = {c5 8? 72 f? 0c} // vpslld $0xc,%ymm?,%ymm?
        $c1 = {c5 f? 72 d? 14} // vpsrld $0x14,%ymm?,%ymm?
        $c2 = {c5 8? 72 f? 07} // vpslld $0x7,%ymm?,%ymm?
        $c3 = {c5 f? 72 d? 19} // vpsrld $0x19,%ymm?,%ymm?
        $c4 = {02 03 00 01 06 07 04 05 0a 0b 08 09 0e 0f 0c 0d} // rot16 for vpshufb
        $c5 = {03 00 01 02 07 04 05 06 0b 08 09 0a 0f 0c 0d 0e} // rot25 for vpshufb
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5
}

rule ChaCha_rol_x64_openssl_AVX512 {
    meta:
        description = "Look for ROTATION code for AVX512 openssl on quarterround of Chacha stream cipher"
        date = "2022-04"
    strings:
        $c0 = {62 f1 65 4? 72 c? 10} // vprold 0x10,zmm?,zmm?
        $c1 = {62 f1 75 4? 72 c? 0c} // vprold 0xc,zmm?,zmm?
        $c2 = {62 f1 65 4? 72 c? 08} // vprold 0x8,zmm?,zmm?
        $c3 = {62 f1 75 4? 72 c? 07} // vprold 0x7,zmm?zmm?
    condition:
        $c0 and $c1 and $c2 and $c3
}
