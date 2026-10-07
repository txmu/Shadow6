import tempfile, threading, time, unittest
from Deployment.webrtc_broker import SignallingBroker
from libshadow6.webrtc_signal import WebrtcClientReflector

class WebrtcBrokerTests(unittest.TestCase):
    def test_nondefault_session_limit_drives_the_actual_waiter_enforcement(self):
        with tempfile.TemporaryDirectory() as d:
            broker = SignallingBroker(d + '/signal.sock', 'svc', max_sessions=7, max_clients=28)
            self.assertEqual(broker.max_clients, 28)
            for _ in range(28): self.assertTrue(broker.clients.acquire(blocking=False))
            self.assertFalse(broker.clients.acquire(blocking=False))
            for _ in range(28): broker.clients.release()
            for value in (27, 32, True):
                with self.assertRaises(ValueError): SignallingBroker(d + '/signal.sock', 'svc', max_sessions=7, max_clients=value)

    def test_outer_and_native_leg_offers_do_not_overwrite_each_other(self):
        with tempfile.TemporaryDirectory() as d:
            broker = SignallingBroker(d + '/signal.sock', 'svc', max_sessions=1).start()
            try:
                result = {}
                workers = [threading.Thread(target=lambda leg=leg: result.setdefault(leg,
                    WebrtcClientReflector(d + '/signal.sock', 'svc.same', leg=leg).offer('offer-' + leg)))
                    for leg in ('E', 'N')]
                for worker in workers: worker.start()
                for leg in ('E', 'N'):
                    reflector = WebrtcClientReflector(d + '/signal.sock', 'svc.same', leg=leg)
                    self.assertEqual(reflector.poll(), 'offer-' + leg)
                    reflector.answer('answer-' + leg)
                for worker in workers: worker.join(2)
                self.assertEqual(result, {'E': 'answer-E', 'N': 'answer-N'})
                self.assertEqual(len(broker.sessions), 1)
            finally: broker.close()

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
