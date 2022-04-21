rule SHA3_bytecode_x64 {
    meta:
        description = "Look for bytecode for SHA3 on x64"
        date = "2022-04"
    strings:
        $c0 = {b? cd cc cc cc}//mov 0xcccccccd,?? (for %5)
        $c1 = {49 0f af ??}//imul ??,??
        $c2 = {83 f? 05}//cmp 0x5,??
    condition:
        $c0 and $c1 and $c2
}

rule SHA3_bytecode_x64_openssl {
    meta:
        description = "Look for bytecode for SHA3 on x64 openssl"
        date = "2022-04"
    strings:
        $c0 = {c1 c? 2c}//rol 0x2c,??
        $c1 = {c1 c? 2b}//rol 0x2b,??
        $c2 = {c1 c? 15}//rol 0x15,??
        $c3 = {c1 c? 0e}//rol 0xe,??
        $c4 = {c1 c? 1c}//rol 0x1c,??
        $c5 = {c1 c? 3d}//rol 0x3d,??
        $c6 = {c1 c? 2d}//rol 0x2d,??
        $c7 = {c1 c? 14}//rol 0x14,??
        $c8 = {c1 c? 03}//rol 0x3,??
        $c9 = {c1 c? 19}//rol 0x19,??
        $c10 = {c1 c? 08}//rol 0x8,??
        $c11 = {c1 c? 06}//rol 0x6,??
        $c12 = {c1 c? 12}//rol 0x12,??
        $c13 = {c1 c? 0a}//rol 0xa,??
        $c14 = {c1 c? 0f}//rol 0xf,??
        $c15 = {c1 c? 24}//rol 0x24,??
        $c16 = {c1 c? 38}//rol 0x38,??
        $c17 = {c1 c? 1b}//rol 0x1b,??
        $c18 = {c1 c? 3e}//rol 0x3e,??
        $c19 = {c1 c? 37}//rol 0x37,??
        $c20 = {c1 c? 02}//rol 0x2,??
        $c21 = {c1 c? 27}//rol 0x27,??
        $c22 = {c1 c? 29}//rol 0x29,??
    condition:
        all of them
}


