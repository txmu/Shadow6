import tempfile,unittest
from pathlib import Path
from shadow6_migrate import export,import_bundle,plan,MigrationError
class MigrationTests(unittest.TestCase):
 def test_round_trip_and_default_dry_run(self):
  with tempfile.TemporaryDirectory() as a,tempfile.TemporaryDirectory() as b:
   root=Path(a);(root/"config.mk").write_text("BUILD_GATE=1\n");out=Path(a)/"migration.zip"
   self.assertEqual(plan(root,["config"])["format"],"shadow6-migration-v1");export(root,out,"zip",["config"]);result=import_bundle(out,Path(b));self.assertTrue(result["dry_run"]);self.assertFalse((Path(b)/"config.mk").exists());import_bundle(out,Path(b),False);self.assertTrue((Path(b)/"config.mk").is_file())
 def test_secrets_require_consent(self):
  with tempfile.TemporaryDirectory() as a:
   root=Path(a);(root/"node.key").write_text("secret")
   with self.assertRaises(MigrationError):plan(root,["identities"])
if __name__=="__main__":unittest.main()
