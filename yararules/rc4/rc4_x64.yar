// from https://0xc0decafe.com/detect-rc4-encryption-in-malicious-binaries/
rule rc4_ksa
 {
     meta:
         author = "Thomas Barabosch"
         description = "Searches potential setup loops of RC4's KSA"
     strings:
         $s0 = { 3d 00 01 00 00 } // cmp eax, 256
         $s1 = { 81 f? 00 01 00 00 } // cmp {ebx, ecx, edx}, 256
         $s2 = { 48 3d 00 01 00 00 } // cmp rax, 256
         $s3 = { 48 81 f? 00 01 00 00 } // cmp {rbx, rcx, …}, 256
     condition:
         any of them
 }

rule rc4_ksa_x64_2 {
    meta:
        description = "Look for opcodes for RC4 KSA x64"
        date = "2022-04"
    strings:
        $c0 = {81 7? ?? ff 00 00 00} // cmpl   $0xff,-0x?(%r??)
        $c1 = {81 7? ?? 00 01 00 00} // cmpl   $0x100,-0x?(%r??)
    condition:
        $c0 or $c1
}

rule rc4_ksa_openssl_x64 {
    meta:
        description = "Look for opcodes for RC4 KSA x64 openssl"
    strings:
        $c0 = {41 80 c? 01 73 ??}// add r?b,0x1; jae ??
    condition:
        $c0
}
