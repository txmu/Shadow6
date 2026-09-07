import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_android_cores as cores


class NimAndroidBuildTests(unittest.TestCase):
    def test_both_abis_use_target_headers_static_dependencies_and_pie(self):
        for abi, (_, target) in cores.TARGETS.items():
            with self.subTest(abi=abi), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                crypto, rtc, tools = root / 'crypto', root / 'rtc', root / 'toolchain'
                paths = [crypto / name for name in ('include/openssl/evp.h', 'lib/libssl.a', 'lib/libcrypto.a')]
                paths += [rtc / name for name in ('include/rtc/rtc.h', 'lib/libdatachannel.a', 'lib/libjuice.a', 'lib/libusrsctp.a')]
                paths += [tools / 'bin' / (target + '28-' + compiler) for compiler in ('clang', 'clang++')]
                for path in paths:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                with mock.patch.object(cores.shutil, 'which', return_value='/nim'), \
                     mock.patch.object(cores.subprocess, 'run') as run:
                    cores.build_nim(abi, target, tools, crypto, rtc, root, 2)
                    command = run.call_args.args[0]
                    for prefix in (crypto, rtc):
                        self.assertIn('--passC:-I' + str(prefix / 'include'), command)
                        self.assertIn('--passL:-L' + str(prefix / 'lib'), command)
                    self.assertIn('--clang.exe:' + str(tools / 'bin' / (target + '28-clang')), command)
                    self.assertIn('--clang.linkerexe:' + str(tools / 'bin' / (target + '28-clang++')), command)
                    self.assertIn('--passL:-pie', command)
                    self.assertNotIn('--passL:-shared', command)
                    self.assertIn('--passL:-static-libstdc++', command)
                    for lib in ('datachannel', 'usrsctp', 'juice', 'ssl', 'crypto'):
                        self.assertIn('--passL:-l' + lib, command)
                    self.assertTrue(run.call_args.kwargs['check'])
                    run.reset_mock()
                    (rtc / 'include/rtc/rtc.h').unlink()
                    with self.assertRaisesRegex(SystemExit, 'rtc/rtc.h'):
                        cores.build_nim(abi, target, tools, crypto, rtc, root, 2)
                    run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
