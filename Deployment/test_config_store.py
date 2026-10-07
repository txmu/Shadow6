import json
import os
from pathlib import Path
import tempfile
import unittest
from Deployment.config_store import ConfigStore, digest
from Deployment.service_registry import encoded


class ConfigStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-config-store-')
        self.addCleanup(self.temp.cleanup)
        registry = type('Registry', (), {'path':Path(self.temp.name)/'services.json'})()
        self.store = ConfigStore(registry)
        self.params = dict(core='go',profile='go-kcp',
            document=json.dumps({'role':'client','client':{'private_key':'PRIVATE','transport':'kcp'}}),
            expected_digest=None)

    def save(self, params):
        review = self.store.review('home/game',**params)
        return self.store.save('home/game',confirmed=True,
            expected_review_digest=digest(encoded(review)),**params)

    def test_secret_safe_diff_private_atomic_save_and_unchanged_secret(self):
        first = self.save(self.params)
        self.assertNotIn('PRIVATE',json.dumps(first))
        path = Path(first['native_config'])
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        params = {**self.params,'expected_digest':first['digest'],
            'document':json.dumps({'role':'client','client':{'private_key':{'unchanged':True},'transport':'kcp','id':'new'}})}
        second = self.save(params)
        self.assertEqual(json.loads(Path(second['native_config']).read_text())['client']['private_key'],'PRIVATE')
        self.assertNotEqual(second['native_config'],first['native_config'])
        self.assertNotIn('new',path.read_text())
        self.assertNotIn('PRIVATE',json.dumps(self.store.inspect('home/game')))
        self.assertFalse(second['applied'])
        with self.assertRaisesRegex(ValueError,'ReviewedConfigurationChanged'): self.save(params)

    def test_symlink_unknown_name_command_float_and_profile_mismatch(self):
        for name in ('../../etc','a/b/c'):
            with self.assertRaises(ValueError): self.store.inspect(name)
        path = self.store.path('home/game')
        path.symlink_to(Path(self.temp.name)/'absent')
        with self.assertRaises((ValueError,OSError)): self.store.review('home/game',**self.params)
        path.unlink()
        for document in ('{"role":"client","on_success":"execute"}',
                         '{"role":"client","x":1.5}',
                         '{"role":"client","client":{"transport":"quic"}}'):
            with self.assertRaises(ValueError): self.store.review('home/game',**{**self.params,'document':document})
