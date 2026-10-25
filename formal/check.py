#!/usr/bin/env python3
"""Check exact source correspondence hashes and Lean kernel proofs/axioms.

Hashes detect implementation drift; they do not prove Python/FFI refinement.
Updating source hashes requires explicit review with --refresh-sources.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def check(refresh=False, inventory_only=False):
    path=ROOT/'formal/models.json';manifest=json.loads(path.read_text())
    actual={p.name for p in (ROOT/'formal').glob('*.lean')}
    if actual!=set(manifest['models']):raise ValueError('formal module inventory drift')
    counts={};source_files=set()
    if not inventory_only and not subprocess.check_output(['lean','--version'],text=True,timeout=10).startswith('Lean (version 4.19.0,'):
        raise ValueError('Lean 4.19.0 required')
    for name,model in manifest['models'].items():
        source=(ROOT/'formal'/name).read_text()
        code=re.sub(r'/\-[\s\S]*?\-/','',source)
        code=re.sub(r'--[^\n]*','',code)
        if re.search(r'\b(sorry|admit|axiom|unsafe|implemented_by|extern|native_decide)\b',code):raise ValueError('proof escape in '+name)
        if re.findall(r'^import\s+(.+)$',code,re.M)!=['Init']:raise ValueError('only Lean Init dependency permitted')
        namespaces=re.findall(r'^namespace\s+(\S+)',code,re.M)
        if namespaces!=[model['namespace']]:raise ValueError('namespace inventory mismatch')
        names=re.findall(r'^theorem\s+([A-Za-z_][A-Za-z_0-9]*)\b',code,re.M)
        if not names or len(names)!=len(set(names)):raise ValueError('missing or duplicate theorem inventory')
        counts[name]=len(names)
        for relative,digest in model['source_sha256'].items():
            source_files.add(relative)
            target=ROOT/relative
            if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(ROOT):raise ValueError('regular repository source required')
            current=hashlib.sha256(target.read_bytes()).hexdigest()
            if refresh:model['source_sha256'][relative]=current
            elif digest!=current:raise ValueError('review source/model correspondence drift: '+relative)
        if inventory_only:continue
        with tempfile.TemporaryDirectory(prefix='formal-axioms-') as temporary:
            audit=Path(temporary)/name
            audit.write_text(source+'\n'+'\n'.join('#print axioms '+model['namespace']+'.'+name for name in names)+'\n')
            result=subprocess.run(['lean',str(audit)],capture_output=True,text=True,timeout=30)
            if result.returncode:raise ValueError(result.stdout+result.stderr)
            allowed={'propext','Quot.sound','Classical.choice'}
            for group in re.findall(r'depends on axioms: \[([^]]*)\]',result.stdout):
                if set(filter(None,(s.strip() for s in group.split(','))))-allowed:raise ValueError('unexpected proof axioms')
            if 'sorryAx' in result.stdout:raise ValueError('incomplete proof')
    if refresh:path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    return {'schema':'ziokt.formal-check.v1','models':counts,'theorems':sum(counts.values()),'source_files':len(source_files),
            'kernel_checked':not inventory_only,'source_correspondence':'manual; exact hashes detect drift','production_refinement_proved':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--refresh-sources',action='store_true');parser.add_argument('--inventory-only',action='store_true');args=parser.parse_args()
    print(json.dumps(check(args.refresh_sources,args.inventory_only),sort_keys=True))
