# Ware (0x41414141 CTF (2021))

This binary is packed by UPX. We analyze the unpacked binary.

| item                 | value |
| -------------------- | ----- |
| file type            | Elf32|
| arch                 | i386 (32bit)|
| language             | Go |
| compiler             | Go  1.6.2|
| crypto library       | Go builtin crypto package |
| crypto functionality | AES|

The binary is not stripped. We can detect crypto functions easily, but we try to apply yara rules for Go binary.

## detect AES
yara rules `RijnDael_AES`, `RijnDael_AES_CHAR`, `RijnDeal_AES_rev_mixcolumn`, `RijnDeal_AES_rev_sbox`, `RijnDeal_AES_TE1`, `RijnDeal_AES_TE2`, `RijnDeal_AES_TE3`, `RijnDeal_AES_TD1`, `RijnDeal_AES_TD2`, `RijnDeal_AES_TD3` from aes_common.yar detect AES functionality.
These constants read from the function Go crypto/aes.encryptBlockGo.

Note that yara rule `AES_bytecode_AESNI_x64` from aes_x64.yar detect AES functionality.
This detect aesenc instruction for the function Go runtime.aeshash*.

## false positive
yara rules `RC4_optimized` and `rc4_ksa` from rc4_x64.yar detect RC4 functionality.
This alert is false positive.

It seems that The constants for the rule `RC4_optimized` detect garbage data.

The instruction cmp 0x100 from the rule `rc4_ksa` has some Go builtins functions.
For example, the function runtime/proc.schedinit includes the if branch with the condition ```n > _MaxGomaxprocs``` (_MaxGomaxprocs is defined as (1\<\<8))) on Go 1.6.2. (see [source](https://github.com/golang/go/blob/go1.6.2/src/runtime/proc.go#L450)) 

RC4 yara rules may generate a few false positive because those rules are too simple. We cannot create another rules in the current status. (Almost all of RC4 operations are not quite characteristic.)

## known writeup
- [KZA](https://klefz.se/2021/02/01/0x41414141-ctf-2021-write-up/)
- [WastefulNick](https://github.com/WastefulNick/CTF-Writeups/tree/master/0x41414141/reversing/ware) WastefulNich provides elf file.
- [LuftensHjaltar](https://luftenshjaltar.info/writeups/0x41414141ctf/rev/ware/#ware)

