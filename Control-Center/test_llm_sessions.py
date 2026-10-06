import unittest

import shadow6_control as control


class LLMSessionControlTests(unittest.TestCase):
    def test_session_tools_share_mutation_gate_without_reconfirming_each_chunk(self):
        self.assertTrue(control.METHOD_SPECS['service.connect_execute']['mutating'])
        self.assertTrue(control.METHOD_SPECS['service.connect_execute']['confirmation_required'])
        for method in ('service.session_read','service.session_write','service.session_close'):
            with self.subTest(method=method):
                spec = control.METHOD_SPECS[method]
                self.assertTrue(spec['mutating'])
                self.assertFalse(spec['confirmation_required'])
                self.assertIn('CONNECT', spec['permissions'])
                rejected = control.response({'method':method,'params':self._params(method)}, allow_mutations=False)
                self.assertFalse(rejected['ok'])
                self.assertEqual(rejected['error']['code'], 'PermissionError')

    @staticmethod
    def _params(method):
        handle = 'x' * 43
        if method == 'service.session_read':
            return {'handle':handle,'max_bytes':1024,'timeout_ms':1000}
        if method == 'service.session_write':
            return {'handle':handle,'data_base64':'','timeout_ms':1000}
        return {'handle':handle}

    def test_mcp_and_openai_discovery_expose_same_session_methods(self):
        expected = {'shadow6_service_session_read','shadow6_service_session_write','shadow6_service_session_close'}
        for protocol in ('mcp','openai'):
            names = {item['name'] for item in control._tool_definitions(protocol)}
            self.assertTrue(expected <= names)

    def test_session_schema_bounds_rpc_payloads(self):
        read = control.METHOD_SPECS['service.session_read']['input_schema']['properties']
        write = control.METHOD_SPECS['service.session_write']['input_schema']['properties']
        self.assertEqual(read['max_bytes']['maximum'], 65536)
        self.assertEqual(read['timeout_ms']['maximum'], 5000)
        self.assertEqual(write['data_base64']['maxLength'], 44000)


if __name__ == '__main__':
    unittest.main()
