# locker (Crew CTF 2022)

| item                 | value |
| -------------------- | ----- |
| file type            | Elf64|
| arch                 | x86-64 (64bit)|
| crypto library       | proprietary, published |
| crypto functionality | ChaCha20(proprietary), SHA-256(published code)|

## detect ChaCha20
yara rules `Chacha_256_constant` from chacha/chacha_common.yar and `Chacha_rol_x64` from chacha/chacha_x64.yar detect ChaCha20 functionality.
Indeed, the function 0x18e0 includes the constant "65 78 70 61 6e 64 20 33"("expand 3") at 0x1921 and the constant "32 2d 62 79 74 65 20 6b"("2-byte k") at 0x1930.
Also, the function 0x1890 (which is called from 0x18e0) includes 4 rol instructions which matches the Chacha_rol_x64 rule.

## detect SHA-256
yara rules `SHA2_BLAKE2_IVs` from sha2/sha2_common.yar and `SHA256_bytecode_x64` from sha2/sha2_x64.yar detect SHA-256 functionality.
The function 0x1720 includes procedures for SHA-256 computation.
The function 0x1de0 is initialize SHA-256 constants, and the function 0x1bd0 includes SHA-256 main loop which has 4 rol/ror operations.

## false positive
yara rule `rc4_ksa` from rc4/rc4_x64.yar alerts RC4 functionality.
This alert is false positive.
The detected instruction is on the address 0x1d5c in the function 0x1de0, which is SHA-256 main loop.
This is compare a register with 0x100(256).
SHA-256 main loop is 64 iteration, and each iteration accesses 32bit values in the consective memory location.
It seems that some compilers generate add 4 instruction and cmp 0x100 instruction.

## known writeup
- [maple3142](https://blog.maple3142.net/2022/04/18/crewctf-2022-writeups/#locker)

## public source
- [CrewCTF-2022-Challenge:locker](https://github.com/Thehackerscrew/CrewCTF-2022-Challenges/tree/main/rev/locker)

