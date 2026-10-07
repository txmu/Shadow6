#!/usr/bin/env python3
"""Single Operator gateway. Fixed loopback backend; no lifecycle authority."""
import argparse
import asyncio
import hmac
import secrets
import ssl
import time
import tempfile
from pathlib import Path
import importlib.util
from importlib.machinery import SourceFileLoader
import sys

# The installed canonical dispatcher is an extensionless executable. Import
# that exact sibling instead of shipping a second implementation.
if not (Path(__file__).parent / 'shadow6_control.py').is_file():
    control_path = Path(__file__).parent / 'shadow6-control'
    if not control_path.is_file() or control_path.is_symlink():
        raise ImportError('installed Control Center is unavailable')
    loader = SourceFileLoader('shadow6_control', str(control_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)

from aiohttp import web, ClientSession, ClientTimeout, DummyCookieJar
from shadow6_control import (MAX_REQUEST, MAX_RESPONSE, secure_read,
                             strict_json_loads, http_runner, _loopback, atomic_write)

CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"


def gateway_app(backend_token, pairing_code, *, backend_port=9466, tls=False):
    if type(backend_port) is not int or not 1 <= backend_port <= 65535:
        raise ValueError('invalid backend port')
    if not 32 <= len(backend_token) <= 4096 or not 32 <= len(pairing_code) <= 4096:
        raise ValueError('credentials must contain 32..4096 characters')
    # Gateway credentials are independent from the backend bearer.
    if hmac.compare_digest(backend_token, pairing_code):
        raise ValueError('operator and backend credentials must differ')
    sessions = {}
    pairing_deadline = time.monotonic() + 600
    pairing_used = False
    attempts = []
    requests = []
    slots = asyncio.Semaphore(16)
    cookie_name = '__Host-shadow6_session' if tls else 'shadow6_loopback_session'
    client_key = web.AppKey('backend', ClientSession)
    session_key = web.RequestKey('operator_session', dict)

    @web.middleware
    async def security(request, handler):
        now = time.monotonic()
        local = request.transport.get_extra_info('sockname') if request.transport else None
        hosts = request.headers.getall('Host', [])
        address = f'[{local[0]}]' if local and ':' in local[0] else local[0] if local else ''
        authorities = {f'{address}:{local[1]}'} if local else set()
        if local and _loopback(local[0]): authorities.add(f'localhost:{local[1]}')
        host = hosts[0] if len(hosts) == 1 else ''
        origin = f'{"https" if tls else "http"}://{host}'
        origins = request.headers.getall('Origin', [])
        sites = request.headers.getall('Sec-Fetch-Site', [])
        for key, value in tuple(sessions.items()):
            if now-value['used'] >= 1800 or now-value['created'] >= 43200:
                sessions.pop(key, None)
        requests[:] = [stamp for stamp in requests if now-stamp < 1]
        if request.method not in {'GET','HEAD','POST'} or request.headers.get('Upgrade'):
            result = web.json_response({'code':'MethodRejected'}, status=405)
        elif host not in authorities or (origins and origins != [origin]) or (sites and sites not in (['same-origin'], ['none'])):
            result = web.json_response({'code':'OriginRejected'}, status=403)
        elif len(requests) >= 64 or slots.locked():
            result = web.json_response({'code':'RateLimited'}, status=429)
        else:
            requests.append(now)
            session = sessions.get(request.cookies.get(cookie_name, ''))
            public = request.path in {'/','/ui.js','/ui.css','/operator.js','/gateway/pair'}
            if not public and session is None:
                result = web.json_response({'code':'OperatorAuthenticationRequired'}, status=401)
            elif request.method == 'POST' and (origins != [origin] or sites and sites != ['same-origin']):
                result = web.json_response({'code':'OriginRequired'}, status=403)
            elif request.method == 'POST' and request.path != '/gateway/pair' and (
                session is None or request.headers.getall('X-Shadow6-CSRF', []) != [session['csrf']]):
                result = web.json_response({'code':'CSRFRejected'}, status=403)
            else:
                if session: session['used'] = now
                request[session_key] = session
                async with slots:
                    try: result = await handler(request)
                    except web.HTTPException as error:
                        result = web.json_response({'code':'RequestRejected'}, status=error.status)
                    except (ValueError, TimeoutError, OSError):
                        result = web.json_response({'code':'RequestRejected'}, status=400)
        result.headers.update({'Cache-Control':'no-store', 'Content-Security-Policy':CSP,
            'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY'})
        return result

    app = web.Application(client_max_size=MAX_REQUEST, middlewares=[security])

    async def client_context(application):
        async with ClientSession(timeout=ClientTimeout(total=20), cookie_jar=DummyCookieJar(),
                                 auto_decompress=False, trust_env=False) as client:
            application[client_key] = client
            yield
    app.cleanup_ctx.append(client_context)

    async def pair(request):
        nonlocal pairing_used
        now = time.monotonic()
        attempts[:] = [stamp for stamp in attempts if now-stamp < 60]
        if len(attempts) >= 5: return web.json_response({'code':'PairingRateLimited'}, status=429)
        attempts.append(now)
        raw = await asyncio.wait_for(request.read(), 5)
        value = strict_json_loads(raw, limit=MAX_REQUEST)
        if not isinstance(value,dict) or set(value) != {'code'} or not isinstance(value['code'],str):
            raise ValueError('invalid pairing request')
        if pairing_used or now >= pairing_deadline or not hmac.compare_digest(value['code'].encode(), pairing_code.encode()):
            return web.json_response({'code':'PairingRejected'}, status=401)
        if len(sessions) >= 16: return web.json_response({'code':'SessionCapacity'}, status=503)
        pairing_used = True
        handle, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        sessions[handle] = dict(csrf=csrf, created=now, used=now)
        result = web.json_response({'authenticated':True, 'csrf':csrf})
        result.set_cookie(cookie_name, handle, httponly=True, secure=tls,
                          samesite='Strict', path='/', max_age=43200)
        return result

    async def session(request):
        return web.json_response({'authenticated':True, 'csrf':request[session_key]['csrf']})

    async def logout(request):
        sessions.pop(request.cookies.get(cookie_name,''), None)
        result = web.json_response({'authenticated':False})
        result.del_cookie(cookie_name, path='/')
        return result

    async def revoke(request):
        sessions.clear()
        return await logout(request)

    async def proxy(request):
        routes = {'/v1/schema','/v1/status','/v1/services/page','/v1/service/status','/v1/rpc'}
        if request.path not in routes: raise web.HTTPNotFound()
        if (request.path == '/v1/rpc') != (request.method == 'POST'): raise web.HTTPMethodNotAllowed(request.method, ['POST'] if request.path == '/v1/rpc' else ['GET','HEAD'])
        raw = b''
        if request.method == 'POST':
            if request.content_type != 'application/json' or request.headers.get('Content-Encoding'):
                raise web.HTTPUnsupportedMediaType()
            raw = await asyncio.wait_for(request.read(), 5)
            strict_json_loads(raw, limit=MAX_REQUEST)
        # Reconstruct every header. Client Authorization, Forwarded and all
        # hop-by-hop headers are never forwarded. No URL/upstream selection.
        url = f'http://127.0.0.1:{backend_port}{request.rel_url}'
        try:
            async with request.app[client_key].request(request.method, url,
                data=raw, headers={'Authorization':f'Bearer {backend_token}',
                                   'Content-Type':'application/json'}, allow_redirects=False) as upstream:
                body = bytearray()
                async for chunk in upstream.content.iter_chunked(65536):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE: raise ValueError('backend response too large')
                if upstream.status not in {200,400,401,403,404,405,408,413,415,429,503}:
                    raise ValueError('unexpected backend status')
                return web.Response(body=body, status=upstream.status, content_type='application/json')
        except (TimeoutError, OSError):
            return web.json_response({'code':'ControlCenterUnavailable'}, status=503)

    async def asset(request):
        filename = {'/':'index.html','/ui.js':'ui.js','/ui.css':'ui.css','/operator.js':'operator.js'}[request.path]
        roots = [Path(__file__).parent/'web', Path(__file__).parent.parent/'share/shadow6/control/web']
        for root in roots:
            path = root/filename
            if path.is_file() and not path.is_symlink():
                raw = secure_read(path, 256*1024)
                if filename == 'index.html':
                    raw = raw.replace(b'</head>', b'<script src="/operator.js" defer></script></head>')
                return web.Response(body=raw, content_type={'html':'text/html','js':'text/javascript','css':'text/css'}[filename.rsplit('.',1)[1]])
        raise web.HTTPNotFound()

    for path in ('/','/ui.js','/ui.css','/operator.js'): app.router.add_get(path, asset)
    app.router.add_post('/gateway/pair', pair)
    app.router.add_get('/gateway/session', session)
    app.router.add_post('/gateway/logout', logout)
    app.router.add_post('/gateway/revoke', revoke)
    for path in ('/v1/schema','/v1/status','/v1/services/page','/v1/service/status'): app.router.add_get(path, proxy)
    app.router.add_post('/v1/rpc', proxy)
    return app


async def serve(args):
    tls = bool(args.tls_cert and args.tls_key)
    if bool(args.tls_cert) != bool(args.tls_key) or (not _loopback(args.host) and not tls):
        raise ValueError('non-loopback requires explicit TLS certificate and key')
    if not 1 <= args.port <= 65535: raise ValueError('invalid listen port')
    token = secure_read(args.token_file, 4096, secret=True).decode().strip()
    code = secure_read(args.pairing_file, 4096, secret=True).decode().strip()
    context = None
    if tls:
        key = secure_read(args.tls_key, 65536, secret=True)
        certificate = secure_read(args.tls_cert, 1048576)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # SSLContext takes paths; use validated private snapshots so it cannot
        # reopen a replaced source key after secure_read has checked it.
        with tempfile.TemporaryDirectory(prefix='shadow6-web-tls-') as directory:
            cert_path, key_path = Path(directory)/'certificate', Path(directory)/'key'
            atomic_write(cert_path, certificate, 0o600)
            atomic_write(key_path, key, 0o600)
            context.load_cert_chain(cert_path, key_path)
    runner = http_runner(gateway_app(token, code, backend_port=args.backend_port, tls=tls))
    await runner.setup()
    try:
        await web.TCPSite(runner, args.host, args.port, ssl_context=context, backlog=64).start()
        print(f'Shadow6 Operator gateway: {"https" if tls else "http"}://{args.host}:{args.port}', flush=True)
        await asyncio.Event().wait()
    finally: await runner.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9467)
    parser.add_argument('--backend-port', type=int, default=9466)
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--pairing-file', type=Path, required=True)
    parser.add_argument('--tls-cert', type=Path)
    parser.add_argument('--tls-key', type=Path)
    args = parser.parse_args()
    asyncio.run(serve(args))


if __name__ == '__main__': main()
