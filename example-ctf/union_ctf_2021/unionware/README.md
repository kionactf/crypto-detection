# unionware (Union CTF 2021)

This challenge is to reverse files at three stages.
We focus on last stage, since crypto functions include in the stage's binary.

| item                 | value |
| -------------------- | ----- |
| file type            | Win32 EXE (PE32)|
| arch                 | i386 (32bit)|
| language             | C++|
| compiler             | Microsoft Visual C++|
| crypto library       | Crypto++(statically linked), proprietary |
| crypto functionality | RSA OAEP with SHA-1(Crypto++), RC4(proprietary)|

## detect RC4
yara rule `rc4_ksa_x64_2` from rc4/rc4_x64.yar detects RC4 functionality.
Indeed, the function at 0x405e50 includes the instruction: "81 7d f8 00 01 00 00" at 0x405e7b.

## detect other functionality
AES, DES, SHA-1, SHA-2 are detected by yara rules.
This indicates that some crypto library may be linked.

## known writeup
- [ret2school](https://ret2school.github.io/post/unionware/)
- [cxiao](https://cxiao.net/posts/2021-10-10-unionware-writeup-part-a/)
  cxiao provides ps1/exe files at [github](https://github.com/cxiao/unionware-writeup).

