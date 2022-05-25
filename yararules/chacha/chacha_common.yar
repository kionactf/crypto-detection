// from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar
rule Chacha_128_constant {
    meta:
        author = "spelissier"
        description = "Look for 128-bit key Chacha stream cipher constant"
        date = "2019-12"
        reference = "https://www.ecrypt.eu.org/stream/salsa20pf.html"
    strings:
        $c0 = "expand 16-byte k"
    condition:
        $c0
}

// from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar
rule Chacha_256_constant {
    meta:
        author = "spelissier"
        description = "Look for 256-bit key Chacha stream cipher constant"
        date = "2019-12"
        reference = "https://tools.ietf.org/html/rfc8439#page-8"
    strings:
        $c0 = "expand 32-byte k"
        $split1 = "expand 3"
        $split2 = "2-byte k"
    condition:
        $c0 or ( $split1 and $split2 )
}

rule Chacha_128_constant_32bit {
    meta:
        description = "Look for 128-bit key Chacha stream cipher constant(32bit)"
        date = "2022-05"
    strings:
        $c0_1 = "expa"
        $c0_2 = "nd 1"
        $c0_3 = "6-by"
        $c0_4 = "te k"
    condition:
        $c0_1 and $c0_2 and $c0_3 and $c0_4
}

rule Chacha_256_constant_32bit {
    meta:
        description = "Look for 256-bit key Chacha stream cipher constant(32bit)"
        date = "2022-05"
    strings:
        $split1_1 = "expa"
        $split1_2 = "nd 3"
        $split2_1 = "2-by"
        $split2_2 = "te k"
    condition:
        $split1_1 and $split1_2 and $split2_1 and $split2_2
}
