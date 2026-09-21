import unittest
from shadow6_virtual_adapter import validate_packet
class VirtualAdapterTests(unittest.TestCase):
    def test_tun_and_tap_bounds(self):
        validate_packet("tun",b"\x45"+bytes(39),1400); validate_packet("tun",b"\x60"+bytes(39),1400); validate_packet("tap",bytes(14),1400)
        for packet in (b"",b"\x10"+bytes(20),bytes(1419)):
            with self.assertRaises(ValueError): validate_packet("tun",packet,1400)
if __name__=="__main__": unittest.main()
