# This code refers source of plyara/core.py partially.
# the following copyright is from plyara.

# Copyright 2014 Christian Buia
# Copyright 2020 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re

from ply.lex import lex
from ply.yacc import yacc


def parse_yaracondition_for_logic_block(parse_target):
    var_lex_pos = []

    reserved = {
        "and" : "AND",
        "or"  : "OR",
        "not" : "NOT",
        "for" : "FOR",
    }

    tokens = \
        [
            'LPAREN', 'RPAREN', 'COLON', 'NEQUALS'
        ] +\
        list(reserved.values()) +\
        [
            'ID', 'STRINGNAME', 'STRINGNAME_COUNT', 'STRINGNAME_ARRAY',
            'STRINGNAME_LENGTH'
        ]

    t_ignore = ' \t'

    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_COLON = r':'
    t_NEQUALS = r'!='

    def t_ID(t):
        r'[a-zA-Z0-9._\[\]~*\\%+\-<>&\^|=,]+'
        t.type = reserved.get(t.value, 'ID')  # Check for reserved words
        return t

    def t_STRINGNAME(t):
        r'\$[0-9a-zA-Z\-_]*[*]?'
        return t

    def t_STRINGNAME_COUNT(t):
        r'\#([a-zA-Z][0-9a-zA-Z\-_]*[*]?)?'
        return t

    def t_STRINGNAME_ARRAY(t):
        r'@[0-9a-zA-Z\-_]*[*]?'
        return t

    def t_STRINGNAME_LENGTH(t):
        r'![0-9a-zA-Z\-_]*[*]?(?!=)'
        return t

    def t_error(t):
        print(f'Illegal character {t.value[0]!r}')
        t.lexer.skip(1)

    lexer = lex()

    # it seems that we have to define first for parsing end state
    def p_expression(p):
        '''
        expression : term
        '''
        p[0] = p[1]

    def p_logic(p):
        '''
        term       : term AND term
                   | term OR term
                   | NOT term
        '''
        if len(p) == 4:
            p[0] = p[1] + [p[2]] + p[3]
        elif len(p) == 3:
            p[0] = [p[1]] + p[2]

    def p_colon(p):
        '''
        term        : FOR term COLON term
        '''
        p[0] = [p[1]] + p[2] + [p[3]] + p[4]

    def p_id(p):
        '''
        ids : ID
            | NEQUALS
        '''
        p[0] = [p[1]]

    def p_ids_double(p):
        '''
        ids : ids ids
        '''
        # for expression like '!ddd[0]'
        p[0] = [re.sub(
            r'(@|!)([a-zA-Z0-9]+) \[',
            r'\1\2[', p[1][0] + ' ' + p[2][0]
            )]

    def p_ids_term(p):
        '''
        term : ids
        '''
        p[0] = p[1]

    def p_var(p):
        '''
        ids : STRINGNAME
            | STRINGNAME_COUNT
            | STRINGNAME_ARRAY
            | STRINGNAME_LENGTH
        '''
        var_lex_pos.append((p[1], p.lexpos(1)))
        p[0] = [p[1]]

    def p_grouped(p):
        '''
        term : LPAREN term RPAREN
        '''
        p[0] = [p[1]] + p[2] + [p[3]]

    def p_notgrouped(p):
        '''
        ids : LPAREN ids RPAREN
        '''
        p[0] = [p[1] + ' ' + p[2][0] + ' ' + p[3]]

    def p_error(p):
        print(f'Syntax error at {p.value}')

    parser = yacc()

    ast = parser.parse(parse_target)

    return [ele[0] for ele in sorted(var_lex_pos, key=lambda x:x[1])], ast


def cleanup():
    filedir = os.path.dirname(os.path.abspath(__file__))
    try:
        os.unlink(os.path.join(filedir, 'parsetab.py'))
    except OSError:
        pass
    try:
        os.unlink(os.path.join(filedir, 'parser.out'))
    except OSError:
        pass


def test():
    # case 1
    case1 = '( ( $abcdefg and $b ) or ( $c and $d ) ) and not ( $e )'
    result1 = parse_yaracondition_for_logic_block(case1)
    assert result1[0] == ['$abcdefg', '$b', '$c', '$d', '$e']
    assert result1[1] == [
        '(', '(', '$abcdefg', 'and', '$b', ')',
        'or',
        '(', '$c', 'and', '$d', ')', ')', 'and', 'not', '( $e )'
        ]

    # case 2
    case2 = '( $a in ( 1 .. 100 ) or ( #b * 2 ) != 6' +\
            ' or ' +\
            '( $c > 100 and !d[1] == 2 ) )'
    result2 = parse_yaracondition_for_logic_block(case2)
    assert result2[0] == ['$a', '#b', '$c', '!d']
    assert result2[1] == [
        '(', '$a in ( 1 .. 100 )',
        'or', '( #b * 2 ) != 6',
        'or',
        '(', '$c > 100', 'and', '!d[1] == 2', ')',
        ')'
        ]

    # case 3
    case3 = '1 of ( $* )'
    result3 = parse_yaracondition_for_logic_block(case3)
    assert result3[0] == ['$*']
    assert result3[1] == ['1 of ( $* )']

    # case 4
    case4 = '( ( for any of ( $a, $b, $c ) : ( $ ) and ( $d ) )' +\
            ' or ' +\
            '( for all of ( $g* ) : ( @ > @h ) ) )'
    result4 = parse_yaracondition_for_logic_block(case4)
    assert result4[0] == ['$a', '$b', '$c', '$', '$d', '$g*', '@', '@h']
    assert result4[1] == [
        '(',
        '(',
        'for',
        'any of ( $a , $b , $c )',
        ':',
        '( $ )',
        'and',
        '( $d )',
        ')',
        'or',
        '(',
        'for',
        'all of ( $g* )',
        ':',
        '( @ > @h )',
        ')',
        ')'
        ]
