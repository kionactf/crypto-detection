# crypto-detection

This is collection of yara rules related crypto/encoding/compression functions.
And add detection program for the crypto with these yara rules.

Note: We do not suppport obfuscated binaries in the current status. If you want to detect crypt for an obfuscated binary, search other projects with using dynamic analysis such as [CryptHunt](https://github.com/s3team/CryptoHunt). If you know any great projects for detecting crypto, we appreciate to be informed of us. 

For reversing crypto-related binary, it is useful for us to know detailed information about what does yara rule detect an crypt for the binary.
For example, if we do not detect the constant "0x61707865" (chacha20 constant) but detect an opcodes for chacha20, the binary might use chacha20 variant with changed constants.

