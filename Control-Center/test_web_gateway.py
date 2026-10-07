"""Real loopback HTTP tests for the Operator gateway security boundary."""
import unittest
from aiohttp.test_utils import TestServer, TestClient
from web_gateway import gateway_app
from shadow6_control import http_app


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = TestServer(http_app('b'*32))
        await self.backend.start_server()
        self.client = TestClient(TestServer(gateway_app('b'*32, 'p'*32,
            backend_port=self.backend.port)))
        await self.client.start_server()
        self.origin = str(self.client.make_url('/')).rstrip('/')
        self.addAsyncCleanup(self.client.close)
        self.addAsyncCleanup(self.backend.close)

    async def pair(self):
        response = await self.client.post('/gateway/pair', json={'code':'p'*32},
            headers={'Origin':self.origin})
        self.assertEqual(response.status, 200)
        cookie = response.cookies['shadow6_loopback_session']
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'], 'Strict')
        self.cookie = cookie.value
        return (await response.json())['csrf']

    def headers(self, csrf=None):
        value = {'Cookie':f'shadow6_loopback_session={self.cookie}', 'Origin':self.origin}
        if csrf: value['X-Shadow6-CSRF'] = csrf
        return value

    async def test_auth_csrf_origin_fixed_backend_and_no_token_leak(self):
        response = await self.client.get('/v1/schema')
        self.assertEqual(response.status, 401)
        csrf = await self.pair()
        response = await self.client.get('/v1/schema', headers={**self.headers(),
            'Authorization':'Bearer attacker', 'X-Forwarded-Host':'attacker.example'})
        self.assertEqual(response.status, 200)
        self.assertNotIn('b'*32, await response.text())
        body = {'method':'system.schema','params':{}}
        response = await self.client.post('/v1/rpc', json=body, headers=self.headers())
        self.assertEqual(response.status, 403)
        response = await self.client.post('/v1/rpc', json=body, headers=self.headers(csrf))
        self.assertEqual(response.status, 200)
        response = await self.client.post('/v1/rpc', json=body,
            headers={**self.headers(csrf),'Origin':'http://evil.example'})
        self.assertEqual(response.status, 403)
        response = await self.client.get('/v1/schema', headers={**self.headers(),'Host':'evil.example'})
        self.assertEqual(response.status, 403)
        response = await self.client.get('/arbitrary-upstream', headers=self.headers())
        self.assertEqual(response.status, 404)
        response = await self.client.request('TRACE','/v1/schema', headers=self.headers())
        self.assertEqual(response.status, 405)

    async def test_pairing_one_use_revoke_and_external_scripts(self):
        csrf = await self.pair()
        response = await self.client.post('/gateway/pair', json={'code':'p'*32}, headers={'Origin':self.origin})
        self.assertEqual(response.status, 401)
        response = await self.client.get('/')
        self.assertIn('/operator.js', await response.text())
        self.assertNotIn('unsafe-inline', response.headers['Content-Security-Policy'])
        response = await self.client.post('/gateway/revoke', headers=self.headers(csrf))
        self.assertEqual(response.status, 200)
        response = await self.client.get('/v1/schema', headers=self.headers())
        self.assertEqual(response.status, 401)

    def test_credentials_must_be_separate(self):
        with self.assertRaises(ValueError): gateway_app('x'*32, 'x'*32)


if __name__ == '__main__': unittest.main()
