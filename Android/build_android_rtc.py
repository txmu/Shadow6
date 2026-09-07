#!/usr/bin/env python3
"""Build libdatachannel and its pinned submodules using existing Android crypto."""
import argparse
from pathlib import Path
import subprocess
import tempfile

from build_android_cores import ROOT, TARGETS, build_jobs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--crypto-prefix', type=Path, default=ROOT / '.tmp/android-crypto')
    parser.add_argument('--output', type=Path, default=ROOT / '.tmp/android-rtc')
    parser.add_argument('--abi', choices=TARGETS, action='append')
    args = parser.parse_args()
    ndk = args.ndk.resolve(strict=True)
    source = args.source.resolve(strict=True)
    # Provisioning is explicit in CI; this builder never fetches sources.
    for name in ('libjuice', 'usrsctp', 'plog', 'json'):
        if not (source / 'deps' / name / 'CMakeLists.txt').is_file():
            raise SystemExit(f'Missing libdatachannel submodule: {name}; initialize pinned submodules first')
    jobs = str(build_jobs())
    for abi in args.abi or TARGETS:
        crypto = args.crypto_prefix.resolve() / abi
        for name in ('include/openssl/ssl.h', 'lib/libssl.a', 'lib/libcrypto.a'):
            if not (crypto / name).is_file():
                raise SystemExit(f'Missing Android crypto: {crypto / name}')
        prefix = args.output.resolve() / abi
        with tempfile.TemporaryDirectory(prefix='shadow6-android-rtc-') as work:
            subprocess.run([
                'cmake', '-S', str(source), '-B', work,
                '-DCMAKE_TOOLCHAIN_FILE=' + str(ndk / 'build/cmake/android.toolchain.cmake'),
                '-DANDROID_ABI=' + abi, '-DANDROID_PLATFORM=android-28',
                '-DANDROID_STL=c++_static', '-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
                '-DCMAKE_INSTALL_PREFIX=' + str(prefix), '-DCMAKE_INSTALL_LIBDIR=lib',
                '-DBUILD_SHARED_LIBS=OFF', '-DBUILD_SHARED_DEPS_LIBS=OFF',
                '-DPREFER_SYSTEM_LIB=OFF', '-DUSE_GNUTLS=OFF', '-DUSE_MBEDTLS=OFF',
                '-DUSE_NICE=OFF', '-DNO_TESTS=ON', '-DNO_EXAMPLES=ON',
                # Shadow6 uses WebRTC data channels and WebSockets, not A/V.
                '-DNO_MEDIA=ON', '-DNO_WEBSOCKET=OFF',
                '-DOPENSSL_USE_STATIC_LIBS=TRUE', '-DOPENSSL_ROOT_DIR=' + str(crypto),
                '-DOPENSSL_INCLUDE_DIR=' + str(crypto / 'include'),
                '-DOPENSSL_SSL_LIBRARY=' + str(crypto / 'lib/libssl.a'),
                '-DOPENSSL_CRYPTO_LIBRARY=' + str(crypto / 'lib/libcrypto.a'),
            ], check=True)
            subprocess.run(['cmake', '--build', work, '--target', 'datachannel',
                            '--parallel', jobs], check=True)
            subprocess.run(['cmake', '--install', work], check=True)
        for name in ('include/rtc/rtc.h', 'lib/libdatachannel.a', 'lib/libjuice.a', 'lib/libusrsctp.a'):
            if not (prefix / name).is_file():
                raise SystemExit(f'Incomplete Android RTC installation: {prefix / name}')


if __name__ == '__main__':
    main()
