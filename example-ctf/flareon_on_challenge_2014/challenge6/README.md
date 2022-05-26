# Challenge 6 (The FLARE On Challenge 2014)

| item                 | value |
| -------------------- | ----- |
| file type            | Elf64|
| arch                 | x86-64 (64bit)|
| language             | C |
| compiler             | gcc 4.6.3 |
| crypto library       | proprietary?|
| crypto functionality | BASE64(proprietary?)|

## Detect BASE64
yara rules `BASE64_decoding_table` from base64_common.yar and `BASE64_bytecode_decode_x64` from base64_x64.yar detect BASE64 functionality.
Indeed, the function 0x401164 reads values from the address 0x4f4000, at which the memory stored BASE64 decoding table. (not-used values on BASE64 decoding are filled with 0x42.)
Also, the function 0x401164 includes a shr instruction and an add instruction which matches the BASE64_bytecode_decode_x64 rule.

## False Positive
Some false positive alerts are reported: BASE64_bytecode_encode_x64 from base64_x64.yar, RC4_optimized from rc4_common.yar, rc4_ksa from rc4_x64.yar, SHA3_bytecode_x64 from sha3_x64.yar.
This is because the binary is applied to obfuscating technique and incledes so many functions.
We have to analyze more such as investigating scope of functions.

## Known Writeup
- [Fireeye(public)](https://www.fireeye.com/blog/threat-research/2014/11/flare_on_challengep.html)
- [Parsia](https://parsiya.net/blog/2014-09-23-my-adventure-with-fireeye-flare-challenge/#ch6)

## Public Source
- [FLARE-On Challenge](https://flare-on.com/)
