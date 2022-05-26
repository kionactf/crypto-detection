# print\_vaddr\_from\_yara\_result.py
simple yara rule matching tool with displaying virtual addresses for matched strings.

## Requirements
Python >= 3.6

packages:
- [yara](https://github.com/VirusTotal/yara)

Python libraries:
- [yara-python](https://github.com/VirusTotal/yara-python)
- [pyelftools](https://github.com/eliben/pyelftools)
- [pefile](https://github.com/erocarrera/pefile)

For install on Ubuntu/Debian, execute the following command.
```sh
$ sudo apt-get install yara
$ sudo pip install -r requirements.txt
```

## Example
```sh
$ python print_vaddr_from_yara_result.py -h
usage: print_vaddr_from_yara_result.py [-h] [--rulefilename RULEFILENAME] [--allrule] filename

yara matching and print virtual address for matching string

positional arguments:
  filename              filename for the binary of analyzing target

optional arguments:
  -h, --help            show this help message and exit
  --rulefilename RULEFILENAME
                        filename for the yara file which includes specific yara rules
  --allrule             flag for processing all defined yara rules one by one (slow method)

$ python print_vaddr_from_yara_result.py --rulefilename yararules/sha1/sha1_x64.yar example/sha1/sha1test.out
sha1_x64.yar:
        SHA1_bytecode_x64("Look for opcodes for SHA1 x64"):
                offset=0x19aa(vaddr=0x19aa, section=.text):$c3_0: c1 c0 05
                offset=0x1a5f(vaddr=0x1a5f, section=.text):$c3_0: c1 c0 05
                offset=0x1b07(vaddr=0x1b07, section=.text):$c3_0: c1 c0 05
                offset=0x1bc0(vaddr=0x1bc0, section=.text):$c3_0: c1 c0 05
                offset=0x1a15(vaddr=0x1a15, section=.text):$c4_0: c1 c8 02
                offset=0x1abd(vaddr=0x1abd, section=.text):$c4_0: c1 c8 02
                offset=0x1b76(vaddr=0x1b76, section=.text):$c4_0: c1 c8 02
                offset=0x1c1e(vaddr=0x1c1e, section=.text):$c4_0: c1 c8 02
```
- `offset` expresses the bytecode position on binary file for matching string.
- `vaddr` expresses the virtual address on the binary (ELF/PE) for matching string.
- `section` expresses name of the section which include the virtual address.

# yara\_match\_on\_function\_scope\_radare2.py 
(depends on parse\_yaracondition\_for\_logic\_block.py)

yara rule matching tool within functions/data referenced from given function address supported by radare2 function/data analysis

This tool structs flow graph of callrefs (only "CALL", not "CODE") and datarefs from radare2 output. 
It investigates yara rules matching within narrowed scope, which includes function or data referenced from the starting point of analysis. (search depth is given.)
This analysis can be time consuming and may miss some matching for outside of search space, but can reduce false positive.  

## Requirements
Python >= 3.6

packages:
- [yara](https://github.com/VirusTotal/yara)
- [radare2](https://github.com/radareorg/radare2)

  NOTE: Confirm that you use the latest version. Some distribution manages old packages, which cannot analyze function lists correctly. See [issue](https://github.com/radareorg/radare2/pull/17030).

Python libraries:
- [yara-python](https://github.com/VirusTotal/yara-python)
- [plyara](https://github.com/plyara/plyara)
- [ply](http://www.dabeaz.com/ply/)
- [r2pipe](https://github.com/radareorg/radare2-r2pipe)

For install on Ubuntu/Debian, execute the following command. (radare2 is installed by using [r2env](https://github.com/radareorg/r2env).)
```sh
$ sudo apt-get install yara
$ sudo pip install r2env
$ r2env init # if first use of r2env
$ r2env add radare2
$ r2env use radare2@git
$ export PATH="$HOME/.r2env/bin:$PATH"
$ sudo pip install -r requirements.txt
```

## Example
```sh
$ python yara_match_on_function_scope_radare2.py -h
usage: yara_match_on_function_scope_radare2.py [-h] [--rulefilename RULEFILENAME] [--allrule]
                                               (--funcaddr FUNCADDR | --funcmain | --allfunc) [--depth DEPTH]
                                               [--quiet]
                                               filename

yara rule matching within functions/data referenced from given function address

positional arguments:
  filename              filename for the binary of analyzing target

optional arguments:
  -h, --help            show this help message and exit
  --rulefilename RULEFILENAME
                        filename for the yara file which includes specific yara rules
  --allrule             flag for processing all defined yara rules one by one
  --funcaddr FUNCADDR   function address of starting point for analyzing the binary. The address expression should be
                        recognizable by radare2 (such as hex string, decimal string, function name, etc.)
  --funcmain            use main function (or entrypoint) for starting point for analyzing the binary
  --allfunc             flag for analyzing all function (much time for large binary)
  --depth DEPTH         depth for analyzing function call/data reference (default: 2)
  --quiet               suppress error output

$ python yara_match_on_function_scope_radare2.py --funcmain --rulefilename yararules/sha1/sha1_x64.yar example/sha1/sha1test.out --quiet
yararules/sha1/sha1_x64.yar:
        SHA1_bytecode_x64("Look for opcodes for SHA1 x64"):
                vaddr=0x19aa(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1a5f(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1b07(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1bc0(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1a15(nodeaddr=0x1790):$c4_0: c1 c8 02
                vaddr=0x1abd(nodeaddr=0x1790):$c4_0: c1 c8 02
                vaddr=0x1b76(nodeaddr=0x1790):$c4_0: c1 c8 02
                vaddr=0x1c1e(nodeaddr=0x1790):$c4_0: c1 c8 02

$ python yara_match_on_function_scope_radare2.py --funcaddr 0x1790 --rulefilename
 yararules/sha1/sha1_x64.yar example/sha1/sha1test.out --depth 0 --quiet
yararules/sha1/sha1_x64.yar:
        SHA1_bytecode_x64("Look for opcodes for SHA1 x64"):
                vaddr=0x19aa(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1a5f(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1b07(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1bc0(nodeaddr=0x1790):$c3_0: c1 c0 05
                vaddr=0x1a15(nodeaddr=0x1790):$c4_0: c1 c8 02
                vaddr=0x1abd(nodeaddr=0x1790):$c4_0: c1 c8 02
                vaddr=0x1b76(nodeaddr=0x1790):$c4_0: c1 c8 02
                vaddr=0x1c1e(nodeaddr=0x1790):$c4_0: c1 c8 02
```
- `vaddr` expresses the virtual address on the binary (ELF/PE) for matching string.
- `nodeaddr` express the virtual address of the function or referenced data whose scope includes the vaddr. nodeaddr is reachable from analysis start point within depth reference flow.

