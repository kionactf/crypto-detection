// from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar
rule SHA512_Constants {
    meta:
        author = "phoul (@phoul)"
        description = "Look for SHA384/SHA512 constants"
        date = "2014-01"
        version = "0.1"
    strings:
        $c0 = { 428a2f98 }
        $c1 = { 982F8A42 }
        $c2 = { 71374491 }
        $c3 = { 91443771 }
        $c4 = { B5C0FBCF }
        $c5 = { CFFBC0B5 }
        $c6 = { E9B5DBA5 }
        $c7 = { A5DBB5E9 }
        $c8 = { D728AE22 }
        $c9 = { 22AE28D7 }
    condition:
        5 of them
}

// from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar
rule SHA2_BLAKE2_IVs {
    meta:
        author = "spelissier"
        description = "Look for SHA2/BLAKE2/Argon2 IVs"
        date = "2019-12"
        version = "0.1"
    strings:
        $c0 = { 67 E6 09 6A }
        $c1 = { 85 AE 67 BB }
        $c2 = { 72 F3 6E 3C }
        $c3 = { 3A F5 4F A5 }
        $c4 = { 7F 52 0E 51 }
        $c5 = { 8C 68 05 9B }
        $c6 = { AB D9 83 1F }
        $c7 = { 19 CD E0 5B }

    condition:
        all of them
}
