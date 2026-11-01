"""Archive handoff tests; no native transport execution is claimed here."""
import io,tarfile,tempfile,unittest
from pathlib import Path
from artifacts import merge_runtime_companions

class GleamArtifactRuntimeTests(unittest.TestCase):
 def test_verified_release_tar_supplies_exact_native_resolver_file(self):
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary);core=root/'Core-Gleam';core.mkdir();(core/'shadow6-gleam').write_bytes(b'archive member fixture, never executed')
   archive=root/'ci-artifacts/linux/Shadow6.tar.gz';archive.parent.mkdir(parents=True);data=b'{lookup,[file]}.\n'
   with tarfile.open(archive,'w:gz')as output:
    member=tarfile.TarInfo('Shadow6/Core-Gleam/inetrc');member.mode=0o644;member.size=len(data);output.addfile(member,io.BytesIO(data))
   archive.chmod(0o644)
   self.assertEqual(merge_runtime_companions(root,idris_artifact=None,s6epe_artifact=None),[])
   self.assertEqual((core/'inetrc').read_bytes(),data)
 def test_missing_and_altered_resolver_are_rejected(self):
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary);core=root/'Core-Gleam';core.mkdir();(core/'shadow6-gleam').write_bytes(b'archive fixture')
   self.assertTrue(any('Gleam'in item for item in merge_runtime_companions(root,idris_artifact=None,s6epe_artifact=None)))
   (core/'inetrc').write_bytes(b'{lookup,[native]}.\n')
   with self.assertRaises(ValueError):merge_runtime_companions(root,idris_artifact=None,s6epe_artifact=None)
