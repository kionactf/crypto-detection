rule BASE64_bytecode_encode_x64 {
    meta:
        description = "Look for instructions for BASE64 x64"
        date = "2022-05"
    strings:
        $c0 = { c0 e? 06 } // shr ?? 0x06
        $c1_0 = { 83 4? ?? 03 } //add [$??-??] 0x03
        $c1_1 = { 83 c? 03 } // add $?? 0x03
        $c1_2 = { 83 4? ?? 04 } //add [$??-??] 0x04
        $c1_3 = { 83 c? 04 } // add $?? 0x04
    condition:
        $c0 and ($c1_0 or $c1_1 or $c1_2 or $c1_3)
}

rule BASE64_bytecode_decode_x64 {
    meta:
        description = "Look for instructions for BASE64 x64"
        date = "2022-05"
    strings:
        $c0 = { c1 e? 06 } // shl ?? 0x06
        $c1_0 = { 83 4? ?? 03 } //add [$??-??] 0x03
        $c1_1 = { 83 c? 03 } // add $?? 0x03
        $c1_2 = { 83 4? ?? 04 } //add [$??-??] 0x04
        $c1_3 = { 83 c? 04 } // add $?? 0x04
    condition:
        $c0 and ($c1_0 or $c1_1 or $c1_2 or $c1_3)
}
