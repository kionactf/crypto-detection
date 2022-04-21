# crypto-detection

This is collection of yara rules related crypto/encoding/compression functions.
And add detection program for the crypto with these yara rules.

yara rules are powerful. We can support proprietary binaries or stripped static linking binaries, not supported by the established tool such as [crypto-detector](https://github.com/Wind-River/crypto-detector).

Note: We do not suppport obfuscated binaries in the current status. If you want to detect crypt for an obfuscated binary, search other projects with using dynamic analysis such as [CryptHunt](https://github.com/s3team/CryptoHunt). If you know any great projects for detecting crypto, we appreciate to be informed of us. 

For reversing crypto-related binary, it is useful for us to know detailed information about what does yara rule detect an crypt for the binary.
For example, if we do not detect the constant "0x61707865" (chacha20 constant) but detect an opcodes for chacha20, the binary might use chacha20 variant with changed constants.
(Of course, it can be another possible: encrypted/obfuscated constants for evading detection.)

Our method is signature-based detection.
However, not only well-known constants for crypto libraries are included in the signatures, we add signatures based on _assembly codes_.
yara rules are flexible so that we can support various crypto patterns.
As already indicated by [A.Adamov](https://www.virusbulletin.com/uploads/pdf/conference_slides/2018/Adamov-VB2018-AIAssistWithRansomware.pdf), some binary might evade detection by some crypto patterns.
We can handle those patterns by crafting yara rules.

## Supported crypto
- Chacha20
  - constants
  - x86-64 opcodes
  - x86-64 opcodes from [OpenSSL](https://github.com/openssl/openssl) (including codes for SSE3/AVX)
- RC4
  - constants
  - x86-64 opcodes
  - x86-64 opcodes from OpenSSL
- AES
  - constants
  - x86-64 opcodes from OpenSSL (including codes for AES-NI/SSE3/AVX)
- DES
  - constants
  - x86-64 opcodes from OpenSSL
- MD5
  - constants
  - x86-64 opcodes
  - x86-64 opcodes from OpenSSL
- SHA1
  - constants
  - x86-64 opcodes
  - x86-64 opcodes from OpenSSL (including codes for Intel SHA1 opcode/SSE3/AVX)
- SHA2(SHA256/SHA512)
  - constants
  - x86-64 opcodes
  - x86-64 opcodes from OpenSSL (including codes for Intel SHA2 opcode/SSE3/AVX)
- SHA3
  - constants
  - x86-64 opcodes
  - x86-64 opcodes from OpenSSL

## related project
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
- [FindCrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt)
- [Manalyze](https://github.com/JusticeRage/Manalyze)
- [crypto-detector](https://github.com/Wind-River/crypto-detector)
- [CryptoHunt](https://github.com/s3team/CryptoHunt)
- [CAPA](https://github.com/mandiant/capa)

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
