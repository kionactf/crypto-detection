rule MD5_bytecode_x64 {
    meta:
        description = "Look for opcodes for MD5 x64"
        date = "2022-04"
    strings:
        $c0 = {48 23}//and
        $c1 = {48 09}//or
        $c2 = {48 f7 d?}//not
        $c3 = {48 c1 e? 07}//shl 0x7
        $c4 = {48 c1 e? 19}//shr 0x19
        $c5 = {48 c1 e? 0c}//shl 0xc
        $c6 = {48 c1 e? 14}//shr 0x14
        $c7 = {48 c1 e? 11}//shl 0x11
        $c8 = {48 c1 e? 0f}//shr 0xf
        $c9 = {48 c1 e? 16}//shl 0x16
        $c10 = {48 c1 e? 0a}//shr 0xa
        $c11 = {48 c1 e? 05}//shl 0x5
        $c12 = {48 c1 e? 1b}//shr 0x1b
        $c13 = {48 c1 e? 09}//shl 0x9
        $c14 = {48 c1 e? 17}//shr 0x17
        $c15 = {48 c1 e? 0e}//shl 0xe
        $c16 = {48 c1 e? 12}//shr 0x12
        $c17 = {48 c1 e? 14}//shl 0x14
        $c18 = {48 c1 e? 0c}//shr 0xc
        $c19 = {48 c1 e? 04}//shl 0x4
        $c20 = {48 c1 e? 1c}//shr 0x1c
        $c21 = {48 c1 e? 0b}//shl 0xb
        $c22 = {48 c1 e? 15}//shr 0x15
        $c23 = {48 c1 e? 10}//shl 0x10
        $c24 = {48 c1 e? 10}//shr 0x10
        $c25 = {48 c1 e? 17}//shl 0x17
        $c26 = {48 c1 e? 09}//shr 0x9
        $c27 = {48 c1 e? 06}//shl 0x6
        $c28 = {48 c1 e? 1a}//shr 0x1a
        $c29 = {48 c1 e? 0a}//shl 0xa
        $c30 = {48 c1 e? 16}//shr 0x16
        $c31 = {48 c1 e? 0f}//shl 0xf
        $c32 = {48 c1 e? 11}//shr 0x11
        $c33 = {48 c1 e? 15}//shl 0x15
        $c34 = {48 c1 e? 0b}//shr 0xb
    condition:
        all of them
}

rule MD5_bytecode_x64_openssl {
    meta:
        description = "Look for opcodes for MD5 x64 openssl"
        date = "2022-04"
    strings:
        $c0 = {41 21 ??}//and ??,r11d
        $c1 = {45 09 dc}//or r11d,r12d
        $c2 = {41 f7 d3}//not r11d
        $c3 = {c1 c? 07}//rol 0x7,??
        $c4 = {c1 c? 0c}//rol 0xc,??
        $c5 = {c1 c? 11}//rol 0x11,??
        $c6 = {c1 c? 16}//rol 0x16,??
        $c7 = {c1 c? 05}//rol 0x5,??
        $c8 = {c1 c? 09}//rol 0x9,??
        $c9 = {c1 c? 0e}//rol 0xe,??
        $c10 = {c1 c? 14}//rol 0x14,??
        $c11 = {c1 c? 04}//rol 0x4,??
        $c12 = {c1 c? 0b}//rol 0xb,??
        $c13 = {c1 c? 10}//rol 0x10,??
        $c14 = {c1 c? 17}//rol 0x17,??
        $c15 = {c1 c? 06}//rol 0x6,??
        $c16 = {c1 c? 0a}//rol 0xa,??
        $c17 = {c1 c? 0f}//rol 0xf,??
        $c18 = {c1 c? 15}//rol 0x15,??
    condition:
        all of them
}
