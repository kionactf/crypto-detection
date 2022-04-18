
rule Chacha_rol_bytecode {
    meta:
        description = "Look for rol opcodes on quarterround of Chacha stream cipher"
        date = "2022-04"
    strings:
        $c0 = {c1 c? 10}
        $c1 = {c1 c? 0c}
        $c2 = {c1 c? 08}
        $c3 = {c1 c? 07}
    condition:
        $c0 and $c1 and $c2 and $c3
}
