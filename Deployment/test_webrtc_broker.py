import tempfile, threading, time, unittest
from Deployment.webrtc_broker import SignallingBroker
from libshadow6.webrtc_signal import WebrtcClientReflector

class WebrtcBrokerTests(unittest.TestCase):
    def test_offer_poll_answer_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            broker = SignallingBroker(d + '/signal.sock', 'svc').start()
            try:
                result = {}
                poller = threading.Thread(target=lambda: result.setdefault('offer', WebrtcClientReflector(d + '/signal.sock', 'svc.1').poll()))
                offerer = threading.Thread(target=lambda: result.setdefault('answer', WebrtcClientReflector(d + '/signal.sock', 'svc.1').offer('offer')))
                poller.start(); offerer.start(); time.sleep(.1)
                poller.join(2); self.assertEqual(result['offer'], 'offer')
                self.assertIsNone(WebrtcClientReflector(d + '/signal.sock', 'svc.1').answer('answer'))
                offerer.join(2); self.assertEqual(result['answer'], 'answer')
            finally: broker.close()

if __name__ == '__main__': unittest.main()
