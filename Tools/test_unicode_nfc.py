"""Small native parser/NFC checks; never compile a Core or download a toolchain."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unicodedata
import unittest

ROOT=Path(__file__).resolve().parents[1]


class NativeUnicodeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('c++'),'C++ compiler required for native parser verification')
    def test_cpp_json_corpus_and_unicode_nfc(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-json-check-') as temporary:
            root=Path(temporary);source=root/'check.cpp';binary=root/'check'
            source.write_text('#include "'+str(ROOT/'Core-Cpp/src/json.hpp')+'"\n#include <iostream>\nint main(){std::string line;while(std::getline(std::cin,line)){shadow6::Json value;shadow6::JsonParser parser;std::cout<<(parser.parse(line,value)?"1":"0")<<"\\n";}}\n')
            subprocess.run(['c++','-std=c++20','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True,timeout=60)
            cases=json.loads((ROOT/'Tools/strict_json_conformance.json').read_text())['cases']
            samples={'Å\u0301','Ḋ\u0323','\u1100\u1161','\uac00\u11a8','\u0301\u0323','中文','é','😀'}
            for point in range(0x110000):
                character=chr(point)
                decomposition=unicodedata.decomposition(character)
                if decomposition and not decomposition.startswith('<'):
                    samples.add(character);samples.add(unicodedata.normalize('NFD',character))
            for text in sorted(samples):cases.append({'input':json.dumps({'text':text},ensure_ascii=True),'accepted':unicodedata.normalize('NFC',text)==text})
            result=subprocess.run([str(binary)],input='\n'.join(case['input'] for case in cases)+'\n',capture_output=True,text=True,check=True,timeout=15)
            self.assertEqual(len(result.stdout.splitlines()),len(cases))
            for actual,case in zip(result.stdout.splitlines(),cases):self.assertEqual(actual=='1',case['accepted'],case)

    @unittest.skipUnless(shutil.which('rustc'),'Rust compiler required for standalone NFC verification')
    def test_rust_nfc_without_building_a_core(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-rust-nfc-') as temporary:
            root=Path(temporary);source=root/'check.rs';binary=root/'check'
            source.write_text('#[path="'+str(ROOT/'Core-Rust/src/unicode_nfc.rs')+'"] mod nfc;\nfn main(){for (text,expected) in [("中文",true),("é",true),("가",true),("각",true),("가각",true),("가\\u{11a8}",false),("e\\u{301}",false),("Å\\u{301}",false),("Ḋ\\u{323}",false),("\\u{1100}\\u{1161}",false)] {assert_eq!(nfc::is_nfc(text),expected);}}')
            subprocess.run(['rustc','--edition=2021',str(source),'-o',str(binary)],check=True,timeout=45)
            subprocess.run([str(binary)],check=True,timeout=5)

    @unittest.skipUnless(shutil.which('go'),'Go compiler required for standalone strict parser verification')
    def test_go_parser_without_building_a_core(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-go-json-') as temporary:
            root=Path(temporary)
            for name in ('strict_json.go','unicode_nfc.go'):shutil.copyfile(ROOT/'Core-Go'/name,root/name)
            (root/'go.mod').write_text('module shadow6-parser-check\n\ngo 1.23\n')
            corpus=(ROOT/'Tools/strict_json_conformance.json').read_text()
            # Native syntax verification does not need the Core's canonical
            # builder or any third-party transport dependency.
            (root/'check_test.go').write_text('package main\nimport("testing";"encoding/json")\nfunc TestCorpus(t *testing.T){var corpus struct{Cases []struct{ID string;Input string;Accepted bool}};if err:=json.Unmarshal([]byte('+json.dumps(corpus)+'),&corpus);err!=nil{t.Fatal(err)};for _,row:=range corpus.Cases{err:=validateStrictJSON([]byte(row.Input),nil);if (err==nil)!=row.Accepted{t.Fatalf("%s: %v",row.ID,err)}}}\n')
            subprocess.run(['go','test','-v','.'],cwd=root,env={**os.environ,'GOTOOLCHAIN':'local','GOPROXY':'off'},check=True,timeout=90)
