import tempfile,unittest
from pathlib import Path
from shadow6_i18n import Translator,I18nError,normalize_locale,MAX_MESSAGES,MAX_TEXT
class I18nTests(unittest.TestCase):
 def test_locale_and_fallback(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/"en.json").write_text('{"demo.message":"Hello {name}"}')
   self.assertEqual(Translator(root,"fr").text("demo.message",name="S6"),"Hello S6")
   self.assertEqual(normalize_locale("zh_cn"),"zh-CN")
 def test_invalid_key_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/"en.json").write_text('{"BAD":"x"}')
   with self.assertRaises(I18nError):Translator(root)
 def test_invalid_bundle_values_and_placeholders_rejected(self):
  import json
  documents=[{'demo.message':42},{'demo.message':'x'*(MAX_TEXT+1)},
             {'demo.message':'{name.attr}'},{'demo.message':'{name!r}'},
             {'demo.message':'{name:10}'},{'demo.message':'{'},
             {'demo.'+'x'*252:'message'},
             {f'demo.message{i}':'x' for i in range(MAX_MESSAGES+1)}]
  for document in documents:
   with self.subTest(case=len(document),sample=str(document)[:80]),tempfile.TemporaryDirectory() as d:
    root=Path(d);(root/'en.json').write_text(json.dumps(document),encoding='utf-8')
    with self.assertRaises(I18nError):Translator(root)
 def test_strict_json_bundle_rejected(self):
  for source in ('{"demo.message":"first","demo.message":"second"}',
                 '{"demo.message":1.5}','{"demo.message":{"nested":"x"}}'):
   with self.subTest(source=source),tempfile.TemporaryDirectory() as d:
    root=Path(d);(root/'en.json').write_text(source,encoding='utf-8')
    with self.assertRaises(I18nError):Translator(root)
if __name__=="__main__":unittest.main()
