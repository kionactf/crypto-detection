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
