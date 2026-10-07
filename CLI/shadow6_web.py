#!/usr/bin/env python3
"""Explicit Operator surface: start the canonical Control Center and gateway."""
import argparse
import asyncio
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import webbrowser

HERE = Path(__file__).resolve().parent
if (HERE.parent/'Control-Center').is_dir():
    sys.path.insert(0, str(HERE.parent/'Control-Center'))
else:
    sys.path.insert(0, str(HERE.parent/'share/shadow6/modules'))
# Installed gateway imports the exact extensionless canonical Control Center.
if not (HERE.parent/'Control-Center').is_dir():
    from importlib.machinery import SourceFileLoader
    import importlib.util
    loader = SourceFileLoader('shadow6_control', str(HERE/'shadow6-control'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module; loader.exec_module(module)
from shadow6_control import secure_read, atomic_write, _loopback


def initialize(directory):
    directory = Path(directory).expanduser().absolute()
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('web state requires an owner-controlled non-symlink 0700 directory')
    for name in ('backend-token','operator-pairing'):
        path = directory/name
        if path.exists() or path.is_symlink(): secure_read(path,4096,secret=True)
        if name == 'operator-pairing' or not path.exists():
            atomic_write(path,(secrets.token_urlsafe(32)+'\n').encode(),0o600)
    return directory


async def serve(args):
    if not _loopback(args.host) and not (args.tls_cert and args.tls_key):
        raise ValueError('remote gateway requires explicit TLS')
    if not 1 <= args.port <= 65535 or not 1 <= args.backend_port <= 65535 or args.port == args.backend_port:
        raise ValueError('gateway and backend require distinct valid ports')
    state = initialize(args.state_dir)
    source = HERE.parent/'Control-Center'
    control = source/'shadow6_control.py' if source.is_dir() else HERE/'shadow6-control'
    gateway = source/'web_gateway.py' if source.is_dir() else HERE/'shadow6-web-gateway'
    backend_args = [sys.executable,str(control),'serve','--host','127.0.0.1','--port',str(args.backend_port),
        '--token-file',str(state/'backend-token'),'--allow-mutations']
    gateway_args = [sys.executable,str(gateway),'--host',args.host,'--port',str(args.port),
        '--backend-port',str(args.backend_port),'--token-file',str(state/'backend-token'),
        '--pairing-file',str(state/'operator-pairing')]
    for option in ('tls_cert','tls_key'):
        value = getattr(args,option)
        if value: gateway_args += ['--'+option.replace('_','-'),str(value)]
    # Owned Control HTTP adapter exits without stopping independently supervised
    # Named Services. Neither launcher nor gateway invokes runtime kill commands.
    children = []
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT,signal.SIGTERM): loop.add_signal_handler(sig,stop.set)
    tasks = []
    try:
        backend_environment = {**os.environ,'SHADOW6_ACTIVITY_ENABLED':'1'}
        if args.lab_report:
            content = secure_read(args.lab_report,16*1024*1024)
            atomic_write(state/'testlab-report.json',content,0o600)
            backend_environment['SHADOW6_TESTLAB_REPORT'] = str(state/'testlab-report.json')
        children.append(await asyncio.create_subprocess_exec(*backend_args,env=backend_environment))
        children.append(await asyncio.create_subprocess_exec(*gateway_args))
        scheme = 'https' if args.tls_cert and args.tls_key else 'http'
        url = f'{scheme}://{args.host}:{args.port}/'
        print(f'Open: {url}\nPairing code (one use, expires in 10 minutes):\n'+secure_read(state/'operator-pairing',4096,secret=True).decode().strip(),flush=True)
        if args.open_browser: webbrowser.open(url)
        tasks = [asyncio.create_task(child.wait()) for child in children]
        tasks.append(asyncio.create_task(stop.wait()))
        done, _ = await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            result = task.result()
            if type(result) is int and result != 0: raise RuntimeError('Web component failed; inspect local component diagnostics')
    finally:
        for child in reversed(children):
            if child.returncode is None:
                child.terminate()
                try: await asyncio.wait_for(child.wait(),5)
                except TimeoutError: child.kill(); await child.wait()
        for task in tasks: task.cancel()
        if tasks: await asyncio.gather(*tasks,return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('init','serve'), nargs='?', default='serve')
    parser.add_argument('--state-dir', type=Path, default=Path.home()/'.local/share/shadow6/web')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9467)
    parser.add_argument('--backend-port', type=int, default=9466)
    parser.add_argument('--tls-cert', type=Path)
    parser.add_argument('--tls-key', type=Path)
    parser.add_argument('--open-browser', action='store_true')
    parser.add_argument('--lab-report', type=Path, help='attach an existing bounded Test Lab report, copied to private Web state')
    args = parser.parse_args()
    if args.action == 'init':
        initialize(args.state_dir); print('Shadow6 Web Control initialized. Run shadow6 web to pair this browser.')
    else: asyncio.run(serve(args))


if __name__ == '__main__':
    try: main()
    except (ValueError,OSError,RuntimeError):
        print('Web surface rejected. Check private state, listen ports and TLS configuration locally.',file=sys.stderr)
        raise SystemExit(1)
