import unittest
from s6ar import pack, unpack

class S6ARTests(unittest.TestCase):
    def test_round_trip(self):
        value={"schema":"shadow6.api-receiver-router.v1","version":1,"kind":"request","receiver":{"component":"detector"},"router":{"route":"local"},"payload":{"action":"status","correlation_id":"abc"}}
        self.assertEqual(unpack(pack(value)), value)
    def test_schema_rejects_unknown_kind(self):
        with self.assertRaises(ValueError): pack({"schema":"shadow6.api-receiver-router.v1","version":1,"kind":"bad","receiver":{},"router":{},"payload":{}})
