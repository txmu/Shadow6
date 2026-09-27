import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import native_config as native
import native_key
import shadow6
import shadow6_connect
from join_code import issue

class NativeToolsTests(unittest.TestCase):
    def topology(self, core):
        return {'nodes': [{'name': role, 'type': role, 'engines': ['shadow6-' + core]} for role in native.ROLES]}

    def configs(self, core):
        keys = {role: (str(i) * 64, str(i + 3) * 64) for i, role in enumerate(native.ROLES, 1)}
        return native.topology_configs(self.topology(core), keys, 'ab' * 32)

    def test_four_cores_roles_and_argv(self):
        for core in native.CORES:
            for role, config in self.configs(core).items():
                with self.subTest(core=core, role=role), tempfile.TemporaryDirectory() as directory:
                    command = native.prepare(config, '/opt/bin/shadow6-' + core, directory)
                    data = (Path(directory) / 'native.config').read_bytes()
                    self.assertEqual((Path(directory) / 'native.config').stat().st_mode & 0o777, 0o600)
                    if core in ('hare', 'pony'):
                        self.assertEqual(command[1], '--config')
                        self.assertNotIn('core', json.loads(data))
                    else:
                        self.assertEqual(len(data), 96)
                        self.assertEqual(command[1], '--' + role if core == 'carp' else '--chain')
                        if role == 'broker': self.assertEqual(data[:32], bytes(32))

    def test_unknown_fields_bool_ports_float_and_duplicate_rejected(self):
        valid = self.configs('pony')['client']
        for bad in ({**valid, 'command': 'echo'}, {**valid, 'listen_port': True}, {**valid, 'listen_port': 1.5}):
            with self.assertRaises(ValueError): native.validate(bad)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for text in ('{"core":"pony","core":"hare"}', '{"listen_port":1.0}', '{"value":NaN}'):
                if path.exists(): path.unlink()
                native.write_new(path, text.encode())
                with self.assertRaises(ValueError): native.load(path)

    @unittest.skipIf(os.name == 'nt', 'POSIX mode/symlink contract')
    def test_secret_file_symlink_mode_and_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'secret'
            native.write_new(path, b'private')
            with self.assertRaises(FileExistsError): native.write_new(path, b'overwrite')
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises((OSError, ValueError)): native.secure_read(link)
            path.chmod(0o644)
            with self.assertRaises(ValueError): native.secure_read(path)
            self.assertEqual(path.read_bytes(), b'private')

    def test_native_key_reciprocity_binding_and_broker_has_no_seed(self):
        code = issue('manual')
        for core in ('carp', 'idris'):
            with tempfile.TemporaryDirectory() as directory:
                keys = {}
                for role in native.ROLES:
                    path = Path(directory) / role
                    native_key.generate_native_key(core, role, code, path)
                    keys[role] = path.read_bytes()
                self.assertEqual(keys['agent'][64:], keys['client'][64:])
                self.assertEqual(keys['broker'][:32], bytes(32))
                self.assertEqual(keys['broker'][32:64], keys['agent'][32:64])
                self.assertEqual(keys['broker'][64:], keys['client'][32:64])
                with self.assertRaises(FileExistsError): native_key.generate_native_key(core, 'client', code, Path(directory)/'client')

    def test_unsupported_topology_is_rejected(self):
        for field, value in (('ssh_host','192.0.2.1'), ('domain','red'), ('on_success','echo')):
            topo=self.topology('hare'); topo['nodes'][0][field]=value
            with self.assertRaises(ValueError): native.topology_configs(topo, {}, 'ab'*32)

    def test_cli_routes_forward_options_and_help(self):
        for name in ('connect','native-config','native-key','paranoid-proxy-benchmark','extensions','easybuild','virtual-adapter'):
            self.assertTrue(shadow6.COMPONENTS[name].is_file(), name)
            with patch.object(sys, 'argv', ['shadow6', name, '--help']), patch.object(shadow6, 'run', return_value=0) as run:
                self.assertEqual(shadow6.main(), 0)
                run.assert_called_once_with(name, ['--help'], False)

    def test_connect_check_writes_nothing_and_passes_manual_pin(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(shadow6_connect, 'resolve', return_value={'routes':[{'core':'carp'}]}) as resolve, patch.object(shadow6_connect, 'install_peer') as install, contextlib.redirect_stdout(io.StringIO()):
            output=Path(directory)/'new'
            result=shadow6_connect.connect('test','carp','client',output,'gate',1086,1087,False,profile=Path('profile'),pin='pin',check=True)
            self.assertTrue(result['valid']); self.assertFalse(output.exists()); install.assert_not_called()
            resolve.assert_called_once_with('test',directory=None,manual_profile=Path('profile'),manual_pin='pin')

if __name__ == '__main__': unittest.main()
