import unittest
import os
from pathlib import Path
import socket
import tempfile
import threading
from shadow6_virtual_adapter import Config, run, validate_packet
from setup_interface import plan
class VirtualAdapterTests(unittest.TestCase):
    def test_interface_plan_has_fixed_commands_and_no_default_route(self):
        value=plan(name="s6tun0",owner=1000,address="10.66.0.1/30",system="Linux")
        self.assertEqual(value["commands"][0],['ip','tuntap','add','dev','s6tun0','mode','tun','user','1000'])
        self.assertFalse(value["changes_default_route"])
        for name in ("x;id", "../tun0", "-help"):
            with self.assertRaises(ValueError): plan(name=name,owner=1000,system="Linux")
        self.assertFalse(plan(name="tun0",owner=1000,system="Darwin")["supported"])

    def test_bidirectional_carrier_without_privileged_interface(self):
        with tempfile.TemporaryDirectory() as temporary:
            key=Path(temporary)/"key"
            key.write_bytes(os.urandom(32)); key.chmod(0o600)
            reservations=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(2)]
            for item in reservations: item.bind(("127.0.0.1",0))
            ports=[item.getsockname()[1] for item in reservations]
            for item in reservations: item.close()
            pairs=[socket.socketpair() for _ in range(2)]
            errors=[]
            def worker(config):
                try: run(config)
                except EOFError: pass
                except Exception as error: errors.append(error)
            workers=[]
            try:
                for side in range(2):
                    app,interface=pairs[side]
                    app.settimeout(3)
                    config=Config("tun","go",interface.fileno(),"127.0.0.1",ports[side],
                                  "127.0.0.1",ports[1-side],key,None,side=side)
                    thread=threading.Thread(target=worker,args=(config,),daemon=True)
                    workers.append(thread); thread.start()
                packet=b"\x45"+bytes(39)
                pairs[0][0].sendall(packet)
                self.assertEqual(pairs[1][0].recv(1400),packet)
                pairs[1][0].sendall(packet)
                self.assertEqual(pairs[0][0].recv(1400),packet)
            finally:
                for app,_ in pairs: app.shutdown(socket.SHUT_WR)
                for thread in workers: thread.join(3)
                for pair in pairs:
                    for item in pair: item.close()
            self.assertFalse(any(thread.is_alive() for thread in workers))
            self.assertEqual(errors,[])
    def test_tun_and_tap_bounds(self):
        validate_packet("tun",b"\x45"+bytes(39),1400); validate_packet("tun",b"\x60"+bytes(39),1400); validate_packet("tap",bytes(14),1400)
        for packet in (b"",b"\x10"+bytes(20),bytes(1419)):
            with self.assertRaises(ValueError): validate_packet("tun",packet,1400)
if __name__=="__main__": unittest.main()
