import sys
import os
import argparse
import glob

import yara
from elftools.elf.elffile import ELFFile
from pefile import PE

class AnalyzeObject:
    def __init__(self, analyzeobj):
        self.analyzeobj = analyzeobj

    def get_sectionname_and_virtualaddress(self, offset):
        raise NotImplementedError

class PEObject(AnalyzeObject):
    def get_sectionname_and_virtualaddress(self, offset):
        for section in self.analyzeobj.sections:
            if section.contains_offset(offset):
                return (section.Name.decode().strip('\x00'), self.analyzeobj.OPTIONAL_HEADER.ImageBase + section.get_rva_from_offset(offset))
        else:
            return ('', -1)

class ELFObject(AnalyzeObject):
    def get_sectionname_and_virtualaddress(self, offset):
        for section in self.analyzeobj.iter_sections():
            secoffset = section['sh_offset']
            secsize = section['sh_size']
            if offset >= secoffset and offset < secoffset + secsize:
                return (section.name, (offset - secoffset) + section['sh_addr'])
        else:
            return ('', -1)

def detect_filetype(fd):
    try:
        pe = PEObject(PE(fd.name))
        return pe
    except:
        pass

    try:
        elf = ELFObject(ELFFile(fd))
        return elf
    except:
        pass

    return None

def get_yara_rule(rulefilename):
    try:
        result = yara.compile(rulefilename)
    except (yara.SyntaxError, yara.Error) as e:
        print(e)
        return None
    except:
        print('error occured(get_yara_rule(%s))' % rulefilename)
        return None
    return result

def check_yararule(fd, yararule):
    return yararule.match(fd.name)

def main(filename, rulefilename=None, allrule=None):
    try:
        fd = open(filename, 'rb')
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(e)
        sys.exit(0)
    except:
        print('error occured(main(%s, %s))' % (filename, rulefilename))
        sys.exit(0)

    analyzeobj = detect_filetype(fd)
    if analyzeobj == None:
        fd.close()
        return None

    rulefilenames = []
    if allrule:
        for rulefilename in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yararules', '*', '*.yar')):
            rulefilenames.append(rulefilename)
    elif rulefilename == None:
        rulefilenames.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yararules', 'rules.yar'))
    else:
        rulefilenames = [os.path.expanduser(rulefilename)]

    resultdict = {}
    # Note: one by one processing is slow (yara matching uses Aho-Corasick algorithm)
    for rulefilename in rulefilenames:
        yararule = get_yara_rule(rulefilename)
        if yararule == None:
            continue
        yararesult = check_yararule(fd, yararule)
        result_each_rule = {}
        for yararesultele in yararesult:
            result_each_rule_each_string = []
            for yararesultelestringele in yararesultele.strings:
                secname, vaddr = analyzeobj.get_sectionname_and_virtualaddress(yararesultelestringele[0])
                result_each_rule_each_string.append({"offset":yararesultelestringele[0], "string_identifier":yararesultelestringele[1], "string_data":yararesultelestringele[2], "section_name":secname, "vaddr":vaddr})
            result_each_rule[(yararesultele.rule, yararesultele.meta['description'])] = result_each_rule_each_string
        if result_each_rule != {}:
            resultdict[os.path.basename(rulefilename)] = result_each_rule

    fd.close()
    return resultdict

def view(result):
    for rulefilename, result_each_rule in result.items():
        print(f'{rulefilename}:')
        for rule, string in result_each_rule.items():
            print(f'\t{rule[0]}("{rule[1]}"):')
            for each_string in string:
                if len(each_string["string_data"]) <= 10:
                    stringhex = ' '.join([hex(c)[2:].zfill(2) for c in each_string["string_data"]])
                else:
                    stringhex = ' '.join([hex(c)[2:].zfill(2) for c in each_string["string_data"][:10]])+' ...'
                if each_string["vaddr"] > 0:
                    print(f'\t\toffset={hex(each_string["offset"])}(vaddr={hex(each_string["vaddr"])}, section={each_string["section_name"]}):{each_string["string_identifier"]}: {stringhex}')
                else:
                    print(f'\t\toffset={hex(each_string["offset"])}(no info):{each_string["string_identifier"]}: {stringhex}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="yara matching and print virtual address for matching string")

    parser.add_argument("filename", help="filename for the binary of analyzing target")
    parser.add_argument("--rulefilename", help="filename for the yara file which includes specific yara rules")
    parser.add_argument("--allrule", help="flag for processing all defined yara rules one by one (slow method)", action='store_true')

    args = parser.parse_args()

    result = main(args.filename, rulefilename=args.rulefilename, allrule=args.allrule)
    view(result)
