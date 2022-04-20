rule DES_bytecode_openssl_x64 {
    meta:
        description = "Look for opcodes for DES x64"
        date = "2022-04"
    strings:
        $c0 = {c1 e? 04}//shr 0x4,??
        $c1 = {c1 e? 10}//shr 0x10,??
        $c2 = {c1 e? 02}//shr 0x2,??
        $c3 = {c1 e? 08}//shr 0x8,??
        $c4 = {81 e? 0f 0f 0f 0f}//and $0xf0f0f0f,??
        $c5 = {81 e? 33 33 33 33}//and $0x33333333,??
        $c6 = {81 e? ff 00 ff 00}//and $0xff00ff00,??
        $c7 = {81 e? 55 55 55 55}//and $0x55555555,??
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5 and $c6 and $c7
}

rule DES_bytecode_openssl_x64_2 {
    meta:
        description = "Look for opcodes for DES x64 in D_ENCRYPT"
        date = "2022-04"
    strings:
        $c0 = {41 c1 e? 02}//shr 0x02,??
        $c1 = {41 c1 e? 0a}//shr 0x0a,??
        $c2 = {41 c1 e? 12}//shr 0x12,??
        $c3 = {41 c1 e? 1a}//shr 0x1a,??
        $c4 = {42 33 8c ?? 00 01 00 00}//xor 0x100(??,??,4),??
        $c5 = {42 33 8c ?? 00 02 00 00}//xor 0x200(??,??,4),??
        $c6 = {42 33 8c ?? 00 03 00 00}//xor 0x300(??,??,4),??
        $c7 = {42 33 8c ?? 00 04 00 00}//xor 0x400(??,??,4),??
        $c8 = {42 33 8c ?? 00 05 00 00}//xor 0x500(??,??,4),??
        $c9 = {42 33 8c ?? 00 06 00 00}//xor 0x600(??,??,4),??
        $c10 = {42 33 8c ?? 00 07 00 00}//xor 0x700(??,??,4),??
    condition:
        $c0 and $c1 and $c2 and $c3 and $c4 and $c5 and $c6 and $c7 and $c8 and $c9 and $c10
}
