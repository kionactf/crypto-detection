//from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar (part of the table for Mixcolumn)
rule RijnDael_AES
{
    meta:
        author = "_pusher_"
        description = "RijnDael AES"
        date = "2016-06"
    strings:
        $c0 = { A5 63 63 C6 84 7C 7C F8 }
    condition:
        $c0
}

//from https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar (part of the table for Sbox)
rule RijnDael_AES_CHAR
{
    meta:
        author = "_pusher_"
        description = "RijnDael AES (check2) [char]"
        date = "2016-06"
    strings:
        $c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
    condition:
        $c0
}

rule RijnDeal_AES_rev_mixcolumn
{
    meta:
        description = "RijnDeal AES reverse table for mixcolumn"
        date = "2022-04"
    strings:
        $c0 = {50 A7 F4 51 53 65 41 7E}
    condition:
        $c0
}

rule RijnDeal_AES_rev_sbox
{
    meta:
        description = "RijnDeal AES reverse sbox"
        date = "2022-04"
    strings:
        $c0 = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb }
    condition:
        $c0
}

rule RijnDeal_AES_rcon
{
    meta:
        description = "RijnDeal AES rcon"
        date = "2022-04"
    strings:
        $c0 = {8d 01 02 04 08 10 20 40 80 1b 36}
    condition:
        $c0
}

rule RijnDeal_AES_rcon_32bit
{
    meta:
        description = "RijnDeal AES rcon(32bit)"
        date = "2022-04"
    strings:
        $c0 = {00 00 00 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 10 00 00 00 20 00 00 00 40 00 00 00 80 00 00 00 1b 00 00 00 36}
    condition:
        $c0
}

/*
rule RijnDeal_AES_TE0
{
    meta:
        description = "RijnDeal AES TE0"
        date = "2022-04"
    strings:
        $c0 = {a5 63 63 c6 84 7c 7c f8 99 77 77 ee 8d 7b 7b f6}
    condition:
        $c0
}
*/

rule RijnDeal_AES_TE1
{
    meta:
        description = "RijnDeal AES TE1"
        date = "2022-04"
    strings:
        $c0 = {63 63 c6 a5 7c 7c f8 84 77 77 ee 99 7b 7b f6 8d}
    condition:
        $c0
}

rule RijnDeal_AES_TE2
{
    meta:
        description = "RijnDeal AES TE2"
        date = "2022-04"
    strings:
        $c0 = {63 c6 a5 63 7c f8 84 7c 77 ee 99 77 7b f6 8d 7b}
    condition:
        $c0
}

rule RijnDeal_AES_TE3
{
    meta:
        description = "RijnDeal AES T3"
        date = "2022-04"
    strings:
        $c0 = {c6 a5 63 63 f8 84 7c 7c ee 99 77 77 f6 8d 7b 7b}
    condition:
        $c0
}

rule RijnDeal_AES_TE4
{
    meta:
        description = "RijnDeal AES TE4"
        date = "2022-04"
    strings:
        $c0 = {63 63 63 63 7c 7c 7c 7c 77 77 77 77 7b 7b 7b 7b}
    condition:
        $c0
}

/*
rule RijnDeal_AES_TD0
{
    meta:
        description = "RijnDeal AES TD0"
        date = "2022-04"
    strings:
        $c0 = {50 a7 f4 51 53 65 41 7e c3 a4 17 1a 96 5e 27 3a}
    condition:
        $c0
}
*/

rule RijnDeal_AES_TD1
{
    meta:
        description = "RijnDeal AES TD1"
        date = "2022-04"
    strings:
        $c0 = {a7 f4 51 50 65 41 7e 53 a4 17 1a c3 5e 27 3a 96}
    condition:
        $c0
}

rule RijnDeal_AES_TD2
{
    meta:
        description = "RijnDeal AES TD2"
        date = "2022-04"
    strings:
        $c0 = {f4 51 50 a7 41 7e 53 65 17 1a c3 a4 27 3a 96 5e}
    condition:
        $c0
}

rule RijnDeal_AES_TD3
{
    meta:
        description = "RijnDeal AES TD3"
        date = "2022-04"
    strings:
        $c0 = {51 50 a7 f4 7e 53 65 41 1a c3 a4 17 3a 96 5e 27}
    condition:
        $c0
}

rule RijnDeal_AES_TD4
{
    meta:
        description = "RijnDeal AES TD4"
        date = "2022-04"
    strings:
        $c0 = {52 52 52 52 09 09 09 09 6a 6a 6a 6a d5 d5 d5 d5}
    condition:
        $c0
}

// from signsrch.sig(http://aluigi.altervista.org/mytoolz.htm)
rule RijnDeal_AES_logtable
{
    meta:
        description = "RijnDeal AES logtable"
        date = "2022-04"
    strings:
        $c0 = {00 00 19 01 32 02 1a c6 4b c7 1b 68 33 ee df 03 64 04 e0 0e 34 8d 81 ef 4c 71 08 c8 f8 69 1c c1 7d c2 1d b5 f9 b9 27 6a}
    condition:
        $c0
}

// from signsrchsig(http://aluigi.altervista.org/mytoolz.htm)
rule RijnDeal_AES_antilogtable
{
    meta:
        description = "RijnDeal AES anti-logtable"
        date = "2022-04"
    strings:
        $c0 = {01 03 05 0f 11 33 55 ff 1a 2e 72 96 a1 f8 13 35 5f e1 38 48 d8 73 95 a4 f7 02 06 0a 1e 22 66 aa e5 34 5c e4 37 59 eb 26}
    condition:
        $c0
}
