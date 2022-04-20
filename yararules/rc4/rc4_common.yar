// from https://0xc0decafe.com/detect-rc4-encryption-in-malicious-binaries/
// also refer: https://www.reddit.com/r/technology/comments/cn4gn/skypes_obfuscated_rc4_algorithm_was_leaked_so_its/
rule RC4_optimized {
    meta:
        description = "detect constants for RC4 optimized version"
        date = "2022-04"
    strings:
        $c0 = {00 01 02 03}
        $c1 = {fc fd fe ff}
        $c2 = {04 04 04 04}
    condition:
        ($c0 and $c2) or ($c1 and $c2)
}
