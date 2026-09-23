"""File-security tests shared by Python and Node; Windows runs in Actions."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from shadow6_network import create_key, load_key


class SecureKeyTests(unittest.TestCase):
    def test_windows_create_uses_line_framing_and_bounded_deadline(self):
        from shadow6_network import _windows_key
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"SystemRoot": directory}), mock.patch("shadow6_network.subprocess.run") as call:
                call.return_value.returncode = 0
                _windows_key("create", Path(directory) / "key", b"x" * 32)
                self.assertEqual(call.call_args.kwargs["input"], __import__("base64").b64encode(b"x" * 32) + b"\n")
                self.assertEqual(call.call_args.kwargs["timeout"], 90)
    def node(self, path):
        module = Path(__file__).with_name('shadow6_network.mjs').as_uri()
        return subprocess.run([shutil.which('node'), '--input-type=module', '-e',
            "const m=await import(process.argv[1]);process.stdout.write(m.loadKey(process.argv[2]));",
            module, str(path)], capture_output=True, timeout=100)

    def test_create_and_read_both_backends(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'key'; key=os.urandom(32)
            create_key(path,key)
            self.assertEqual(load_key(path),key)
            if shutil.which('node'):
                result=self.node(path)
                self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
                self.assertEqual(result.stdout,key)
            with self.assertRaises((OSError,PermissionError)):
                create_key(path,b'x'*32)
            self.assertEqual(load_key(path),key)

    @unittest.skipUnless(os.name=='posix','POSIX modes')
    def test_public_mode_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'key'; create_key(path,os.urandom(32))
            path.chmod(0o644)
            with self.assertRaises(PermissionError): load_key(path)
            if shutil.which('node'): self.assertNotEqual(self.node(path).returncode,0)
            path.chmod(0o600)
            link=Path(directory)/'link'; link.symlink_to(path)
            with self.assertRaises(PermissionError): load_key(link)
            if shutil.which('node'): self.assertNotEqual(self.node(link).returncode,0)

    @unittest.skipUnless(os.name=='nt','native Windows DACL test')
    def test_other_principal_cannot_read_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'key'; create_key(path,os.urandom(32))
            script="""$ErrorActionPreference='Stop'
$p=$env:SHADOW6_TEST_KEY
$acl=Get-Acl -LiteralPath $p
$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'Read','Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $p -AclObject $acl
"""
            shell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
            subprocess.run([str(shell),'-NoProfile','-NonInteractive','-Command',script],
                           env=dict(os.environ,SHADOW6_TEST_KEY=str(path)),check=True,timeout=20)
            with self.assertRaises(PermissionError): load_key(path)
            if shutil.which('node'): self.assertNotEqual(self.node(path).returncode,0)


if __name__=='__main__': unittest.main()
