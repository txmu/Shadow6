import unittest
from privacy_envelope import EnvelopeMetrics, compatibility

class PrivacyEnvelopeTests(unittest.TestCase):
    def test_metrics_are_aggregate_only(self):
        value = EnvelopeMetrics(preauth_rejections=2).public()
        self.assertEqual(value["preauth_rejection_count"], 2)
        self.assertNotIn("payload", value)
        self.assertNotIn("token", value)
    def test_transport_matrix_marks_datagram_limits(self):
        self.assertTrue(compatibility("rust")["supported"])
        self.assertTrue(compatibility("hare")["supported"])

if __name__ == "__main__": unittest.main()
