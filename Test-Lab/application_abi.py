"""Own the existing FD gateway around one canonical Test Lab ServiceRegistry."""
import asyncio
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import sys
import threading

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'Control-Center'))
from fd_gateway import FDGateway
from Deployment.service_storage import atomic_write


@contextmanager
def application_gateway(registry,directory):
    library=Path(os.environ.get('SHADOW6_APPLICATION_LIBRARY',ROOT/'libshadow6/native/libshadow6.so')).absolute()
    if not library.is_file():raise ValueError('NativeApplicationABIUnavailable: provide the same-run application SDK artifact')
    directory=Path(directory)/'application-abi';directory.mkdir(mode=0o700)
    token=secrets.token_hex(32);token_path=directory/'token';atomic_write(token_path,token.encode())
    loop=asyncio.new_event_loop();ready=threading.Event();shutdown=threading.Event();errors=[]
    gateway=FDGateway(directory/'control.sock',token,allow_mutations=True,registry=registry)
    async def serve():
        try:
            await gateway.start();ready.set()
            while not shutdown.is_set():await asyncio.sleep(.02)
        finally:await gateway.close()
    def run():
        try:loop.run_until_complete(serve())
        except BaseException as error:errors.append(error);ready.set()
        finally:loop.close()
    thread=threading.Thread(target=run,name='shadow6-lab-application-abi');thread.start()
    previous={name:os.environ.get(name) for name in ('SHADOW6_CONTROL_SOCKET','SHADOW6_CONTROL_TOKEN_FILE','SHADOW6_APPLICATION_LIBRARY')}
    try:
        if not ready.wait(5) or errors:raise ValueError('ApplicationABIGatewayUnavailable')
        os.environ.update(SHADOW6_CONTROL_SOCKET=str(gateway.path),SHADOW6_CONTROL_TOKEN_FILE=str(token_path),SHADOW6_APPLICATION_LIBRARY=str(library))
        yield {'schema':'shadow6.application-abi-evidence.v1','version':1,
               'backend':'C-ABI/SCM_RIGHTS','authority':'canonical-ServiceRegistry',
               'credential':'owner-controlled-0600','peerIdentity':'same-effective-uid',
               'ownership':'borrowed-handle-and-caller-owned-duplicates'}
    finally:
        for name,value in previous.items():
            if value is None:os.environ.pop(name,None)
            else:os.environ[name]=value
        shutdown.set();thread.join(40)
        if thread.is_alive() or errors:raise ValueError('ApplicationABIGatewayCleanupFailed')
