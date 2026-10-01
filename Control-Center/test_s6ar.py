import unittest
from s6ar import pack, unpack, request, to_rpc, response_for, error_for
from shadow6_control import response

class S6ARTests(unittest.TestCase):
    def test_round_trip(self):
        value={"schema":"shadow6.api-receiver-router.v1","version":1,"kind":"request","receiver":{"component":"detector"},"router":{"route":"local"},"payload":{"action":"status","correlation_id":"abc"}}
        self.assertEqual(unpack(pack(value)), value)
    def test_schema_rejects_unknown_kind(self):
        with self.assertRaises(ValueError): pack({"schema":"shadow6.api-receiver-router.v1","version":1,"kind":"bad","receiver":{},"router":{},"payload":{}})
        with self.assertRaises(ValueError): unpack(pack({"schema":"shadow6.api-receiver-router.v1","version":1,"kind":"request","receiver":{"component":"detector"},"router":{"route":"local"},"payload":{"action":"status","correlation_id":"abc","params":{"x": 1.5}}}))

    def test_legacy_rpc_bridge(self):
        self.assertEqual(to_rpc(unpack(request("system", "local", "schema")))["method"], "system.schema")
        result = response({"s6ar1": request("system", "local", "schema")})
        self.assertTrue(result["ok"])
        self.assertTrue(result["result"]["s6ar1"].startswith("S6AR1."))
        envelope = unpack(request("system", "local", "schema"))
        self.assertEqual(unpack(response_for(envelope, {"ok": True}))['kind'], "response")
        self.assertEqual(unpack(error_for(envelope, "denied", "no"))["payload"]["error"]["code"], "denied")
