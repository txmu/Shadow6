#!/usr/bin/env python3
"""Build Android crypto from explicitly supplied sources; never download."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

from build_android_cores import TARGETS, build_jobs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--openssl-source', type=Path, required=True)
    parser.add_argument('--sodium-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--abi', choices=TARGETS, action='append')
    args = parser.parse_args()
    ndk = args.ndk.resolve(strict=True)
    sources = [args.openssl_source.resolve(strict=True), args.sodium_source.resolve(strict=True)]
    candidates = list((ndk / 'toolchains/llvm/prebuilt').iterdir())
    if len(candidates) != 1 or candidates[0].is_symlink():
        raise SystemExit('NDK must contain exactly one non-symlink LLVM toolchain')
    tools = candidates[0] / 'bin'
    jobs = str(build_jobs())
    for abi in args.abi or TARGETS:
        prefix = args.output.resolve() / abi
        prefix.mkdir(parents=True, exist_ok=True)
        target = TARGETS[abi][1]
        env = dict(os.environ, ANDROID_NDK_ROOT=str(ndk),
                   PATH=str(tools) + os.pathsep + os.environ.get('PATH', ''))
        # Out-of-source builds keep the supplied source trees unchanged.
        with tempfile.TemporaryDirectory(prefix='shadow6-android-crypto-') as temporary:
            work = Path(temporary)
            openssl = work / 'openssl'
            sodium = work / 'sodium'
            openssl.mkdir()
            sodium.mkdir()
            def run(command, cwd, environment=env):
                subprocess.run(command, cwd=cwd, env=environment, check=True)
            run(['perl', str(sources[0] / 'Configure'),
                 'android-arm64' if abi == 'arm64-v8a' else 'android-x86_64',
                 '-D__ANDROID_API__=28', 'no-shared', 'no-tests', 'no-module',
                 '-fPIC', '--prefix=' + str(prefix), '--libdir=lib',
                 '--openssldir=/system/etc/security'], openssl)
            run(['make', '-j' + jobs], openssl)
            run(['make', 'install_sw'], openssl)
            sodium_env = dict(env, CC=str(tools / (target + '28-clang')),
                              AR=str(tools / 'llvm-ar'), RANLIB=str(tools / 'llvm-ranlib'),
                              CFLAGS='-O2 -fPIC')
            run([str(sources[1] / 'configure'), '--host=' + target,
                 '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib'),
                 '--disable-shared', '--enable-static', '--with-pic'], sodium, sodium_env)
            run(['make', '-j' + jobs], sodium, sodium_env)
            run(['make', 'install'], sodium, sodium_env)


if __name__ == '__main__':
    main()
