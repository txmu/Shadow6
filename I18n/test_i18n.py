import tempfile,unittest
from pathlib import Path
from shadow6_i18n import Translator,I18nError,normalize_locale
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
if __name__=="__main__":unittest.main()
