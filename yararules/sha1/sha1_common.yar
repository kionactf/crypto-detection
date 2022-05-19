// from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar
rule SHA1_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for SHA1 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 67452301 }
        $c1 = { EFCDAB89 }
        $c2 = { 98BADCFE }
        $c3 = { 10325476 }
        $c4 = { C3D2E1F0 }
        $c5 = { 01234567 }
        $c6 = { 89ABCDEF }
        $c7 = { FEDCBA98 }
        $c8 = { 76543210 }
        $c9 = { F0E1D2C3 }
        //added by _pusher_ 2016-07 - last round
        $c10 = { D6C162CA }
    condition:
        5 of them
}

