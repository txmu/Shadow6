#!/usr/bin/env python3
"""Test shadow6_connect.py one-click Public6 connection tool."""
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "CLI"))
from shadow6_connect import CORE_NAMES

class TestShadow6Connect(unittest.TestCase):
    def test_core_names_matches_public6(self):
        sys.path.insert(0, str(ROOT / "Public6"))
        from join_code import CORE_NAMES as PUBLIC6_CORES
        self.assertEqual(set(CORE_NAMES), PUBLIC6_CORES)
    
    def test_all_twelve_cores_present(self):
        self.assertEqual(len(CORE_NAMES), 12)
        expected = {"go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp"}
        self.assertEqual(set(CORE_NAMES), expected)


class UnifiedConnectTests(unittest.TestCase):
    def test_s6p1_plan_without_invitation_and_ambiguous_scope(self):
        import subprocess
        sys.path.insert(0,str(ROOT/'Deployment'))
        from protocol_context import minimal_context
        from join_code import pack_protocol
        for scope,expected in (('go',0),('all',2)):
            result=subprocess.run([sys.executable,str(ROOT/'CLI/shadow6.py'),'connect','--protocol-envelope',pack_protocol(minimal_context(scope))],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,expected,result.stderr)
            if expected == 0:
                import json
                plan=json.loads(result.stdout);self.assertEqual(plan['schema'],'shadow6.connection-plan.v1');self.assertFalse(plan['connected'])
            else:self.assertIn('AmbiguousCore',result.stderr)

    def test_old_public6_provisioning_calls_shared_resolver(self):
        import tempfile
        from unittest.mock import patch
        import shadow6_connect as module
        with tempfile.TemporaryDirectory() as directory, patch.object(module,'resolve',return_value={'routes':[{'core':'go'}]}), patch.object(module,'install_peer',return_value={'artifacts':[]}), patch.object(module,'resolve_connection',wraps=module.resolve_connection) as resolver:
            result=module.connect('x'*40,'go','client',Path(directory),'gate',1086,1087,False,check=True)
            self.assertTrue(result['valid']);self.assertFalse(result['connectionPlan']['connected'])
            resolver.assert_called_once()
            self.assertEqual(resolver.call_args.kwargs['role'],'client')

    def test_public6_gate_provisioning_cannot_override_component_disable(self):
        import tempfile
        from unittest.mock import patch
        import shadow6_connect as module
        context=module.minimal_context('go');context['components']={'gate':False}
        with tempfile.TemporaryDirectory() as directory, patch.object(module,'resolve') as lookup, patch.object(module,'install_peer') as install:
            with self.assertRaisesRegex(ValueError,'does not advertise'):
                module.connect('x'*40,'go','client',Path(directory),'gate',1086,1087,False,context=context)
            lookup.assert_not_called();install.assert_not_called()

    def test_public6_role_argument_cannot_bypass_passport_scope(self):
        import tempfile
        from unittest.mock import patch
        import shadow6_connect as module
        from join_code import issue_passport
        context=module.minimal_context('go')
        context['credentials']={'passport':issue_passport('nas',components=('gate',),roles=('agent',),issuer_key=b'r'*32)}
        with tempfile.TemporaryDirectory() as directory, patch.object(module,'resolve') as lookup:
            with self.assertRaisesRegex(ValueError,'role'):
                module.connect('x'*40,'go','client',Path(directory),'gate',1086,1087,False,context=context)
            lookup.assert_not_called()

    def test_s6p1_role_option_is_checked_by_the_shared_pipeline(self):
        import subprocess,json
        from join_code import pack_protocol,issue_passport
        from protocol_context import minimal_context
        context=minimal_context('go')
        argv=[sys.executable,str(ROOT/'CLI/shadow6.py'),'connect','--protocol-envelope',pack_protocol(context),'--role','client']
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['role'],'client')
        context['credentials']={'passport':issue_passport('nas',components=('all',),roles=('agent',),issuer_key=b'r'*32)}
        argv[4]=pack_protocol(context)
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2);self.assertIn('role',result.stderr)


if __name__ == '__main__':unittest.main()
