#!/usr/bin/env python3
"""Emit production Python and Lean predicates from one typed expression tree.

The small renderer and host integer/string semantics are a trusted boundary.
This is a predicate correspondence mechanism, not a Python program verifier.
"""
import argparse
import ast
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
BEGIN='# BEGIN GENERATED VERIFIED GUARDS\n'
END='# END GENERATED VERIFIED GUARDS\n'
LEAN_BEGIN='-- BEGIN GENERATED VERIFIED GUARDS\n'
LEAN_END='-- END GENERATED VERIFIED GUARDS\n'


def expression(node,parameters,language):
    if not isinstance(node,list) or not node:raise ValueError('tagged expression required')
    op,*args=node
    if op=='var':
        if len(args)!=1 or args[0] not in parameters:raise ValueError('declared parameter required')
        return parameters[args[0]],args[0]
    if op=='nat':
        if len(args)!=1 or type(args[0]) is not int or args[0]<0:raise ValueError('natural literal required')
        return 'Nat',str(args[0])
    if op=='str':
        if len(args)!=1 or not isinstance(args[0],str) or not args[0].isascii():raise ValueError('ASCII protocol literal required')
        return 'String',json.dumps(args[0])
    rendered=[expression(child,parameters,language) for child in args]
    if op in {'add','le','lt','eq'}:
        if len(rendered)!=2 or rendered[0][0]!=rendered[1][0] or op!='eq' and rendered[0][0]!='Nat':raise ValueError('typed binary expression required')
        symbol={'add':'+','le':'<=' if language=='py' else '≤','lt':'<','eq':'==' if language=='py' else '='}[op]
        return ('Nat' if op=='add' else 'Prop'), '('+rendered[0][1]+' '+symbol+' '+rendered[1][1]+')'
    def proposition(item):
        kind,text=item
        if kind not in {'Prop','Bool'}:raise ValueError('predicate operand required')
        return '('+text+' = true)' if language=='lean' and kind=='Bool' else text
    if op in {'and','or'}:
        if len(rendered)<2:raise ValueError('two or more predicate operands required')
        symbol=(' and ' if op=='and' else ' or ') if language=='py' else (' ∧ ' if op=='and' else ' ∨ ')
        return 'Prop','('+symbol.join(proposition(item) for item in rendered)+')'
    if op=='not' and len(rendered)==1:
        return 'Prop',('not ' if language=='py' else '¬ ')+proposition(rendered[0])
    if op in {'nonempty','all'} and len(rendered)==1 and rendered[0][0]=='ListBool':
        text=rendered[0][1]
        if op=='nonempty':return 'Prop',('bool('+text+')' if language=='py' else text+' ≠ []')
        return 'Prop',('all('+text+')' if language=='py' else '∀ value ∈ '+text+', value = true')
    raise ValueError('unsupported expression operator')


def replace_region(path,start,end,text,write):
    source=path.read_text()
    if source.count(start)!=1 or source.count(end)!=1:raise ValueError('exactly one generated region required: '+str(path))
    prefix,tail=source.split(start,1);old,suffix=tail.split(end,1)
    expected=prefix+start+text+end+suffix
    if write:path.write_text(expected)
    elif source!=expected:raise ValueError('production/Lean predicate drift: '+str(path))


def generate(write=False):
    spec=json.loads((ROOT/'formal/contracts.json').read_text())
    python='''def _contract_argument(value, kind):
    valid = (type(value) is int and value >= 0) if kind == "Nat" else type(value) is bool if kind == "Bool" else type(value) is str if kind == "String" else type(value) is list and all(type(item) is bool for item in value)
    if not valid: raise ValueError("verified guard argument outside its proved domain: " + kind)


'''
    lean={}
    for name,item in spec['predicates'].items():
        if not re.fullmatch('[a-z][a-z0-9_]*',name):raise ValueError('safe predicate identifier required')
        parameters=item['parameters']
        if any(not re.fullmatch('[a-z][a-z0-9_]*',p) or t not in {'Nat','Bool','String','ListBool'} for p,t in parameters.items()):raise ValueError('typed parameters required')
        kind,py=expression(item['expression'],parameters,'py')
        if kind not in {'Prop','Bool'}:raise ValueError('predicate result required')
        python+='def '+name+'('+', '.join(parameters)+'):\n'
        python+=''.join('    _contract_argument('+p+', '+repr(t)+')\n' for p,t in parameters.items())
        python+='    return '+py+'\n\n\n'
        _,value=expression(item['expression'],parameters,'lean')
        if kind=='Bool':value='('+value+' = true)'
        arguments=' '.join('('+p+' : '+('List Bool' if t=='ListBool' else t)+')' for p,t in parameters.items())
        definition='abbrev '+name+' '+arguments+' : Prop :=\n  '+value+'\n\n'
        for relative in item.get('production_bindings',[]):
            tree=ast.parse((ROOT/relative).read_text())
            if not any(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id==name for node in ast.walk(tree)):
                raise ValueError('production predicate call disappeared: '+relative+':'+name)
        for target in item['lean_targets']:lean[target]=lean.get(target,'')+definition
    ast.parse(python)
    target=ROOT/spec['python_target']
    if not target.exists():
        if not write:raise ValueError('generated production module missing')
        target.write_text('"""Generated contract predicates; edit formal/contracts.json, then regenerate."""\n'+BEGIN+END)
    replace_region(target,BEGIN,END,python,write)
    for target,definitions in lean.items():replace_region(ROOT/target,LEAN_BEGIN,LEAN_END,definitions,write)
    print(json.dumps({'schema':'ziokt.predicate-correspondence.v1','predicates':len(spec['predicates']),'python_target':spec['python_target'],'lean_targets':sorted(lean),'checked':not write}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');parser.add_argument('--check',action='store_true');args=parser.parse_args();generate(args.write)
