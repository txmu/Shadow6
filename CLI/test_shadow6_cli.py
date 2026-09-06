import unittest
import contextlib,io,json,os,subprocess,sys,tempfile
from pathlib import Path
from unittest import mock
import shadow6
from shadow6 import command_for,COMPONENTS,TRANSPORTS
class CLITests(unittest.TestCase):
 def test_bilingual_guide_is_readonly(self):
  for language, phrase in (("en", "Welcome"), ("zh", "欢迎")):
   result=subprocess.run([sys.executable,shadow6.__file__,"guide","--lang",language],capture_output=True,text=True,timeout=10)
   self.assertEqual(result.returncode,0,result.stderr)
   document=json.loads(result.stdout);self.assertEqual(document["lang"],language)
   self.assertIn(phrase,document["message"]);self.assertIn("shadow6 features",document["steps"])
 def test_events_do_not_echo_arguments(self):
  output=io.StringIO()
  with mock.patch("subprocess.run",return_value=mock.Mock(returncode=0)),contextlib.redirect_stdout(output):
   self.assertEqual(shadow6.run("control",["--params",'{"secret":"SENSITIVE_MARKER"}'],True),0)
  self.assertNotIn("SENSITIVE_MARKER",output.getvalue());self.assertNotIn("argv",output.getvalue())
 def cli(self,*args):
  return subprocess.run([sys.executable,str(Path(shadow6.__file__)),"hands",*map(str,args)],input="",capture_output=True,text=True,timeout=20)
 def test_hands_key_sign_verify_and_tamper_rejection(self):
  with tempfile.TemporaryDirectory() as directory:
   base=Path(directory);private=base/"key.pem";public=base/"key.json";plan=base/"plan.json"
   result=self.cli("keygen","--private-key",private,"--public-key",public)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(private.stat().st_mode&0o777,0o600)
   result=self.cli("sign","--private-key",private,"--action","audit","--output",plan,"--ttl",60)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(plan.stat().st_mode&0o777,0o600)
   result=self.cli("verify","--plan",plan,"--public-key",public)
   self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(json.loads(result.stdout)["valid"])
   result=self.cli("sign","--private-key",private,"--action","audit","--output",private)
   self.assertEqual(result.returncode,2);self.assertIn("BEGIN PRIVATE KEY",private.read_text())
   document=json.loads(plan.read_text());document["action"]="build";plan.write_text(json.dumps(document))
   result=self.cli("verify","--plan",plan,"--public-key",public)
   self.assertEqual(result.returncode,2);self.assertIn("signature",result.stderr)
 def test_hands_noninteractive_missing_arguments_fail_without_prompt(self):
  result=self.cli("sign");self.assertEqual(result.returncode,2);self.assertIn("--private-key",result.stderr)
  result=self.cli("keygen","--interactive");self.assertEqual(result.returncode,2);self.assertIn("terminal",result.stderr)
 def test_hands_interactive_keygen(self):
  with tempfile.TemporaryDirectory() as directory:
   private=Path(directory)/"key.pem";public=Path(directory)/"key.json"
   with mock.patch.object(sys,"argv",["shadow6","hands","keygen","--interactive"]),mock.patch.object(sys.stdin,"isatty",return_value=True),mock.patch("builtins.input",side_effect=[str(private),str(public)]),contextlib.redirect_stdout(io.StringIO()):
    self.assertEqual(shadow6.main(),0)
   self.assertTrue(private.is_file());self.assertTrue(public.is_file())
 def test_known_component_without_shell(self):self.assertEqual(command_for("gate",["--feature-report"])[-1],"--feature-report")
 def test_api_transports_integrated(self):self.assertTrue({"mcp","lsp","openai-rpc","serve","rpc"}<=TRANSPORTS);self.assertIn("migrate",COMPONENTS)
if __name__=="__main__":unittest.main()
