# Crypto-Detection

This is collection of yara rules related crypto/encoding/compression functions.
And add detection program for the crypto with these yara rules.

yara rules are powerful. We can support proprietary binaries or stripped static linking binaries, not supported by the established tools such as [crypto-detector](https://github.com/Wind-River/crypto-detector).

Note: We do not suppport obfuscated binaries in the current status. If you want to detect crypto for an obfuscated binary, search other projects with using dynamic analysis such as [CryptHunt](https://github.com/s3team/CryptoHunt). If you know any great projects for detecting crypto, we appreciate to be informed of us. 

For reversing crypto-related binary, it is useful for us to know detailed information about what does yara rule detect an crypto for the binary.
For example, if we do not detect the constant "0x61707865" (chacha20 constant) but detect an instruction for chacha20, the binary might use chacha20 variant with changed constants.
(Of course, it can be another possible: encrypted/obfuscated constants for evading detection.)

Our method is signature-based detection.
However, not only well-known constants for crypto libraries are included in the signatures, we add signatures based on _assembly codes_.
yara rules are flexible so that we can support various crypto patterns.
As already indicated by [A.Adamov](https://www.virusbulletin.com/uploads/pdf/conference_slides/2018/Adamov-VB2018-AIAssistWithRansomware.pdf), some binary might evade detection by some crypto patterns (simple bytecode signature matching or call graph analysis).

For example,
- use registers different from original one
- swap instructions if the order does not matter
- move instructions to new functions and call the function
- insert no meaning instructions

We can handle those patterns by crafting yara rules.
We create yara rules by extracting distinctive instructions and applying wild-cards for not relying specific registers.
This enables us to identify crypto more robust comparing with the approach such as [FLIRT](https://hex-rays.com/products/ida/tech/flirt/in_depth/).

## Supported Crypto
- Chacha20
  - constants
  - x86-64 instructions
  - x86-64 instructions from [OpenSSL](https://github.com/openssl/openssl) (including codes for SSE3/AVX)
- RC4
  - constants
  - x86-64 instructions
  - x86-64 instructions from OpenSSL
- AES
  - constants
  - x86-64 instructions from OpenSSL (including codes for AES-NI/SSE3/AVX)
- DES
  - constants
  - x86-64 instructions from OpenSSL
- MD5
  - constants
  - x86-64 instructions
  - x86-64 instructions from OpenSSL
- SHA1
  - constants
  - x86-64 instructions
  - x86-64 instructions from OpenSSL (including codes for Intel SHA1 opcode/SSE3/AVX)
- SHA2(SHA256/SHA512)
  - constants
  - x86-64 instructions
  - x86-64 instructions from OpenSSL (including codes for Intel SHA2 opcode/SSE3/AVX)
- SHA3
  - constants
  - x86-64 instructions
  - x86-64 instructions from OpenSSL
- BASE64
  - constants
  - x86-64 instructions

## Tool for Supporting Yara Rule Analysis
- print\_vaddr\_from\_yara\_result.py

  simple yara rule matching tool with displaying virtual addresses for matched strings.
- yara\_match\_on\_function\_scope\_radare2.py

  yara rule matching tool within functions/data referenced from given function address supported by radare2 function/data analysis

See [Tools](doc/tools.md) for requirements and usage examples.

## Related Project
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
- [FindCrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt)
- [Manalyze](https://github.com/JusticeRage/Manalyze)
- [crypto-detector](https://github.com/Wind-River/crypto-detector)
- [CryptoHunt](https://github.com/s3team/CryptoHunt)
- [CAPA](https://github.com/mandiant/capa)
- [findcrypt-yara](https://github.com/polymorf/findcrypt-yara)
- [ghidraninja/ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts)
- [stelftools](https://github.com/shuakabane/stelftools)

  This is an identification tool for standard C libraries by yara rules.
- [grap](https://github.com/QuoSecGmbH/grap)

  yara-like tool for detect graph patterns within binaries

## Apply Yara Rules for Decompiler
Some plugins have been developed.

IDA:
- [findyara-ida](https://github.com/OALabs/findyara-ida)

Ghidra:
- [RunYARAFromGhidra.py (NSA/ghidra)](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/RunYARAFromGhidra.py)

Radare2
- [Yara Plugin](https://github.com/radareorg/radare2/blob/master/doc/yara.md)

BinaryNinja:
- [binaryninja-yara](https://github.com/starfleetcadet75/binaryninja-yara)
- [BinaryNinjaYaraPlugin](https://github.com/GitMirar/BinaryNinjaYaraPlugin)

## ToDo
If needed, we might go forward. (The following list is just memorandum.)
- another crypto
  - TEA, Browfish,...
  - asymmetric crypto (including post-quantum crypto)
  - lightweight crypto
  - encoding(Base64 etc.)
  - compressing
- another architecture such as aarch64
- another crypto libraries such as [Crypto++](https://github.com/weidai11/cryptopp)
- reverse engineering stuff support
  - show function addresses for found crypto 
- automated generating yara rules for arbitrary libraries
