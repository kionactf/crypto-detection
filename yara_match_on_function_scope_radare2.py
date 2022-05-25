import sys
import os
import argparse
import glob
import base64
import tempfile
from functools import lru_cache
from enum import Enum, auto

import r2pipe
import yara
from plyara import Plyara
from plyara.utils import rebuild_yara_rule

from parse_yaracondition_for_logic_block import parse_yaracondition_for_logic_block
from parse_yaracondition_for_logic_block import cleanup as parse_yaracondition_for_logic_block_cleanup

QUIET = False

class ParseYaraConditionError(Exception):
    def __init__(self):
        self.super()

"""
rooted undirected graph whose children is referenced function/data from parent 
"""
class ReferenceRootedGraphNodeManager(object):
    def __init__(self, rootnode):
        self.nodes = {}
        self.addNode(rootnode)
        self.root = rootnode.offset

    def __getitem__(self, offset):
        return self.nodes[offset]

    def addNode(self, node):
        if type(node) != ReferenceRootedGraphNode:
            raise ValueError("node should be ReferenceRootedGraphNode instance")
        self.nodes[node.offset] = node

    def addChildLink(self, parentnodeoffset, childnodeoffset):
        if not(parentnodeoffset in self.nodes) or not(childnodeoffset in self.nodes):
            raise ValueError("node should be in ReferenceRootedGraphNodeManager")
        if not(childnodeoffset in self.nodes[parentnodeoffset].children):
            self.nodes[parentnodeoffset].children.append(childnodeoffset)

class ReferenceType(Enum):
    FUNCTION = auto()
    DATA = auto()

class ReferenceRootedGraphNode(object):
    def __init__(self, offset, size, bytecode, referencetype):
        self.offset = offset
        self.size = size
        self.bytecode = bytecode
        if type(referencetype) != ReferenceType:
            raise ValueError("referencetype should be ReferenceType constant")
        self.referencetype = referencetype
        self.children = []

def r2_init(filename):
    try:
        r2_bin = r2pipe.open(filename)
    except e:
        print(e)
        return None
    if not(QUIET):
        print('Wait a few seconds for analyzing binary by radare2.')
    r2_bin.cmd('aaaa;') # aac;aae; can be good, but not perfect.
    if not(QUIET):
        print('analyze is done.')
    return r2_bin

def get_node(refaddr, reftype, r2_bin):
    if reftype is ReferenceType.FUNCTION:
        refresult = r2_bin.cmdj('afij %s' % hex(refaddr))[0]
        size = refresult["size"]
    elif reftype is ReferenceType.DATA:
        # TODO: data size is not specified. more analysis is required for specifying data size.
        size = 1024
    else:
        raise ValueError("the reference type is invalid at get_node")
    bytecode = base64.b64decode(r2_bin.cmd('s %s;p6e %d;' % (hex(refaddr), size)).encode())
    return ReferenceRootedGraphNode(refaddr, size, bytecode, reftype)

def check_function_exist(refaddr, r2_bin):
    result = r2_bin.cmdj('afij %s' % hex(refaddr))
    if result == []:
        return False
    return True

def get_reference(refaddr, reftype, r2_bin):
    if reftype is ReferenceType.FUNCTION:
        refresult = (r2_bin.cmdj('afij %s' % hex(refaddr)))[0]
        try:
            refresult["offset"]
        except:
            r2_bin.quit()
            raise ValueError("cannot extract function info at %s" % hex(refaddr))
        if "callrefs" in refresult:
            callrefs = [ele["addr"] for ele in refresult["callrefs"] if ele["type"] == "CALL" and check_function_exist(ele["addr"], r2_bin)]
        else:
            callrefs = []
        if "datarefs" in refresult:
            datarefs = refresult["datarefs"]
        else:
            datarefs = []
        return [(ele, ReferenceType.FUNCTION) for ele in callrefs] + [(ele, ReferenceType.DATA) for ele in datarefs]
    else:
        return []

def get_allfunc(r2_bin):
    funclistresult = (r2_bin.cmdj('aflj'))
    return [ele["offset"] for ele in funclistresult]

def get_main(r2_bin):
    mainresult = r2_bin.cmdj('afij main')
    if not(mainresult == []):
        return mainresult[0]['offset']
    else:
        entryresult = r2_bin.cmdj('afij ~')
        return entryresult[0]['offset']

def get_funcaddr(r2_bin, funcaddr):
    funcaddrresult = r2_bin.cmdj('afij %s' % funcaddr)
    if funcaddrresult == []:
        return int(funcaddr, 16)
    else:
        return funcaddrresult[0]['offset']

@lru_cache
def create_reference_graph(refaddr, reftype, depth, r2_bin, curdepth=0):
    rootnode = get_node(refaddr, reftype, r2_bin)
    rrgnm = ReferenceRootedGraphNodeManager(rootnode)
    if curdepth < depth:
        for refrefaddr, refreftype in get_reference(refaddr, reftype, r2_bin):
            rrgnm_child = create_reference_graph(refrefaddr, refreftype, depth, r2_bin, curdepth+1)
            # delete 1-length cycle
            if rrgnm_child.root == rrgnm.root:
                continue
            for offset, node in rrgnm_child.nodes.items():
                if not(offset in rrgnm.nodes):
                    rrgnm.addNode(node)
                else:
                    if offset == rrgnm.root:
                        continue
                    # already inserted node can be leaf node(no children)
                    if len(rrgnm.nodes[offset].children) < len(node.children):
                        rrgnm.nodes[offset].children = node.children[:]
            rrgnm.addChildLink(rrgnm.root, rrgnm_child.root)
    return rrgnm

def targetbyte_refgraph(refgraph):
    nodes = sorted([node for node in refgraph.nodes.values()], key=lambda x:x.offset)
    bytecodes = b''.join(node.bytecode for node in nodes)

    stringoffsetmap = [0]
    for i in range(len(nodes)):
        stringoffsetmap.append(stringoffsetmap[-1] + nodes[i].size)

    def offsetmap(string_offset):
        # search a node which matched string_offset and return vaddr corresponding to string_offset based on offset of the node
        for i in range(len(stringoffsetmap)):
            if string_offset < stringoffsetmap[i]:
                string_offset_in_node = string_offset - stringoffsetmap[i-1]
                return (nodes[i-1].offset + string_offset_in_node), nodes[i-1].offset
        raise ValueError("offset is not found at offsetmap.")

    return bytecodes, offsetmap, stringoffsetmap


def rebuild_rule_refgraph(parsed_rule, stringoffsetmap):
    """
    transform to string in specific bytecode range.

    For example:
    #a==6 or $b -> (#a==6 and (($a in (0..100)) and ($a in (101..200)))) or ($b and (($b in (0..100)) and ($b in (101..200))))
    any of them -> for any of them : ( $ ) and (($ in (0..100)) or ($ in (101..200)))
    for any of them : ( $ ) -> for any of them : ( $ ) and (($ in (0..100)) or ($ in (101..200)))

    NOTE: we cannot transform correctly (that is, it is not meaningful) for the expression like "any of ($a*) in (1000..2000)" or "$a at 100" or "for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )".
    """

    parsed_rule_modified = dict(parsed_rule)
    rule_condition = parsed_rule_modified['condition_terms']

    # reconstruct parsed_rule (for, (, ), :, and, or, not is separated) and compute variables($a, #b, @abc, !d, etc.)
    condition_vars, condition_blocks = parse_yaracondition_for_logic_block(' '.join(rule_condition))

    condition_vars += [None]
    condition_vars_pos = 0
    rule_condition_modified = []
    for_scope = False

    def transform_condition_block(condition_block, condition_var_each):
        # transform such as: @a[0]<100 -> ( @a[0]<100 ) and (($a in (0..100)) or ($a in (101..200)))
        # condition_var_each is a list such as: $a, @b, #abc, !abcd, etc.
        transformed_condition = ['('] + [condition_block] + [')']
        for condition_var in condition_var_each:
            rule_condition_each_var = []
            for i in range(0, len(stringoffsetmap)-1):
                if len(rule_condition_each_var) != 0:
                    rule_condition_each_var += ['or']
                rule_condition_each_var += ('( ' + ('$'+condition_var[1:]) + ' in ( ' + str(stringoffsetmap[i]) + ' .. ' + str(stringoffsetmap[i+1]-1) + ' ) )').split(' ')
            transformed_condition += ['and', '('] +  rule_condition_each_var + [')']
        return ['('] + transformed_condition + [')']

    for condition_block in condition_blocks:
        if condition_block == 'for':
            for_scope = True
            rule_condition_modified += [condition_block]
        elif ' of ' in condition_block:
            if not(for_scope):
                # transform such as: any of them -> for any of them: ( $ ) and (($ in (0..100)) and ($ in (101..200)))
                rule_condition_modified += ['for'] + [condition_block] + [':'] + transform_condition_block('( $ )', ['$'])
            else:
                rule_condition_modified += [condition_block]
        elif condition_block == ')':
            for_scope = False
            rule_condition_modified += [condition_block]
        elif not(condition_block in ('not', 'and', 'or', '(', ':')):
            # transform such as: #a==6 -> (#a==6) and (($a in (0..100)) or ($a in (101..200)))
            condition_var_each = []
            while(True):
                condition_var = condition_vars[condition_vars_pos]
                if condition_var == None or not(condition_var in condition_block):
                    break
                condition_var_each.append(condition_var)
                condition_vars_pos += 1
            rule_condition_modified += transform_condition_block(condition_block, condition_var_each)
        else:
            rule_condition_modified += [condition_block]

    parsed_rule_modified['condition_terms'] = rule_condition_modified

    rule = rebuild_yara_rule(parsed_rule_modified)

    return rule

def string_convert_to_refaddr_offset(string, offsetmap):
    byte_offset = string[0]
    string_identifier = string[1]
    string_data = string[2]

    vaddr, nodeaddr = offsetmap(byte_offset)

    return {'vaddr':vaddr, 'nodeaddr':nodeaddr, 'string_identifier':string_identifier, 'string_data':string_data}

def check_yararule_for_referenced_node(refgraph, parsed_rules):
    targetbyte, offsetmap, stringoffsetmap = targetbyte_refgraph(refgraph)
    rules = ""
    for parsed_rule in parsed_rules:
        rule = rebuild_rule_refgraph(parsed_rule, stringoffsetmap)
        rules += rule

    # temp file for rule
    fd_, tmprulefilename = tempfile.mkstemp()
    try:
        fp = open(tmprulefilename, 'wb+')
        fp.write(rules.encode())
        fp.close()
        yararule = yara.compile(tmprulefilename)
    except (yara.SyntaxError, yara.Error) as e:
        print(e)
        os.close(fd_)
        os.unlink(tmprulefilename)
        raise ParseYaraConditionError
    except:
        print('error occured at check_yararule_for_reference_node')
        os.close(fd_)
        os.unlink(tmprulefilename)
        raise ParseYaraConditionError
    os.close(fd_)
    os.unlink(tmprulefilename)

    # temp file for target
    fd_, tmptargetfilename = tempfile.mkstemp()
    try:
        fp = open(tmptargetfilename, 'wb+')
        fp.write(targetbyte)
        fp.close()
        matches = yararule.match(tmptargetfilename)
    except:
        print('error occured at check_yararule_for_reference_node')
        os.close(fd_)
        os.unlink(tmptargetfilename)
        raise ParseYaraConditionError
    os.close(fd_)
    os.unlink(tmptargetfilename)

    return {ele.rule:[string_convert_to_refaddr_offset(elestr, offsetmap) for elestr in ele.strings] for ele in matches}

def main(filename, funcaddr, depth=2, rulefilename=None, allrule=False, allfunc=False, funcmain=False):
    r2_bin = r2_init(filename)
    if r2_bin == None:
        sys.exit(-1)

    if allfunc:
        funcaddres = get_allfunc(r2_bin)
    elif funcmain:
        funcaddres = [get_main(r2_bin)]
    else:
        funcaddres = [get_funcaddr(r2_bin, funcaddr)]

    # TODO: to deal with include recursively (plyara itself does not handle include, just parse it)
    rulefilenames = []
    if allrule:
        for rulefilename in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yararules', '*', '*.yar')):
            rulefilenames.append(rulefilename)
    elif rulefilename == None:
        filedir = os.path.dirname(os.path.abspath(__file__))
        parser = Plyara(store_raw_sections=False)
        fp = open(os.path.join(filedir, 'yararules', 'rules.yar'), 'r')
        parser.parse_string(fp.read())
        fp.close()
        rulefilenames = list(map(lambda x:os.path.join(filedir, 'yararules', *x.replace('./', '').split('/')), parser.includes))
        parser.clear()
    else:
        rulefilenames = [os.path.expanduser(rulefilename)]

    try:
        resultdict = {}
        for rulefilename in rulefilenames:
            parser = Plyara(store_raw_sections=False)
            fp = open(rulefilename, 'r')
            parsed_rules = parser.parse_string(fp.read())[:]
            fp.close()
            parser.clear()

            resultrules_func = []
            for function_addr in funcaddres:
                refgraph = create_reference_graph(function_addr, ReferenceType.FUNCTION, depth, r2_bin)
                resultrules = check_yararule_for_referenced_node(refgraph, parsed_rules)
                resultrules_func.append(resultrules)

            resulteachruledict = {}
            for parsed_rule in parsed_rules:
                for resultrules in resultrules_func:
                    try:
                        resultrules_parsedrule = resultrules[parsed_rule['rule_name']]
                    except KeyError:
                        continue
                    rule_description = [ele for ele in parsed_rule['metadata'] if type(ele) == dict and 'description' in ele][0]['description']
                    if not(rule_description in resulteachruledict):
                        resulteachruledict[(parsed_rule['rule_name'], rule_description)] = resultrules_parsedrule
                    else:
                        resulteachruledict[(parsed_rule['rule_name'], rule_description)] += resultrules_parsedrule
            if resulteachruledict != {}:
                resultdict[rulefilename] = resulteachruledict
    except ParseYaraConditionError:
        r2_bin.quit()
        parse_yaracondition_for_logic_block_cleanup()
        sys.exit(-1)

    r2_bin.quit()
    parse_yaracondition_for_logic_block_cleanup()

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
                print(f'\t\tvaddr={hex(each_string["vaddr"])}(nodeaddr={hex(each_string["nodeaddr"])}):{each_string["string_identifier"]}: {stringhex}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="yara rule matching within functions/data referenced from given function address")

    parser.add_argument("filename", help="filename for the binary of analyzing target")
    parser.add_argument("--rulefilename", help="filename for the yara file which includes specific yara rules")
    parser.add_argument("--allrule", help="flag for processing all defined yara rules one by one", action='store_true')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--funcaddr", help="function address of starting point for analyzing the binary. The address expression should be recognizable by radare2 (such as hex string, decimal string, function name, etc.)")
    group.add_argument("--funcmain", help="use main function (or entrypoint) for starting point for analyzing the binary", action='store_true')
    group.add_argument("--allfunc", help="flag for analyzing all function (much time for large binary)", action='store_true')

    parser.add_argument("--depth", help="depth for analyzing function call/data reference (default: 2)", default=2, type=int)
    parser.add_argument("--quiet", help="suppress error output", action='store_true')

    args = parser.parse_args()

    if args.quiet:
        QUIET = True
        # r2pipe feeds error from stderr
        os.close(sys.stderr.fileno())
        sys.stderr = open(os.devnull, 'a')

    result = main(args.filename, args.funcaddr, depth=args.depth, rulefilename=args.rulefilename, allrule=args.allrule, allfunc=args.allfunc, funcmain=args.funcmain)
    view(result)
