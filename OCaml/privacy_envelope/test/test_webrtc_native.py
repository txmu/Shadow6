"""Actual loopback ICE/DTLS/DataChannels, not a queue-only mock or TCP view."""
import ctypes as c
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]

class Channel(c.Structure):
    _fields_=[('id',c.c_uint),('ordered',c.c_uint),('policy',c.c_uint),('budget',c.c_uint)]

class Event(c.Structure):
    _fields_=[('kind',c.c_uint),('channel',c.c_uint),('text',c.c_uint),('size',c.c_size_t)]

class WebRTCNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='s6epe-native-webrtc-')
        cls.addClassCleanup(cls.temp.cleanup)
        library=Path(cls.temp.name)/'webrtc.so'
        command=['gcc','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',
                 str(ROOT/'src/carrier_webrtc_native.c'),'-o',str(library),'-ldl','-pthread']
        if os.environ.get('S6EPE_RTC_INCLUDE'):command+=['-I',os.environ['S6EPE_RTC_INCLUDE']]
        subprocess.run(command,check=True,capture_output=True,timeout=30)
        cls.lib=c.CDLL(str(library))
        functions={
            's6_rtc_available':([],c.c_int),
            's6_rtc_create':([c.c_char_p,c.POINTER(Channel),c.c_uint,c.c_size_t,c.c_uint,c.c_size_t],c.c_void_p),
            's6_rtc_local':([c.c_void_p,c.c_int,c.c_void_p,c.c_size_t],c.c_int),
            's6_rtc_remote':([c.c_void_p,c.c_int,c.c_char_p,c.c_size_t],c.c_int),
            's6_rtc_open':([c.c_void_p],c.c_int),
            's6_rtc_send':([c.c_void_p,c.c_uint,c.c_int,c.c_char_p,c.c_size_t],c.c_int),
            's6_rtc_receive':([c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(Event)],c.c_int),
            's6_rtc_close_channel':([c.c_void_p,c.c_uint],c.c_int),
            's6_rtc_buffered':([c.c_void_p],c.c_int),
            's6_rtc_wait':([c.c_void_p,c.c_uint],c.c_int),
            's6_rtc_free':([c.c_void_p],None),
        }
        for name,(args,result) in functions.items():
            function=getattr(cls.lib,name);function.argtypes=args;function.restype=result
        if not cls.lib.s6_rtc_available():
            if os.environ.get('S6EPE_WEBRTC_REQUIRED')=='1':raise RuntimeError('required native WebRTC backend unavailable')
            raise unittest.SkipTest('optional libdatachannel 0.23 backend unavailable')

    def create(self,*,maximum=73728,depth=64,budget=1048576,channels=None):
        policies=channels or [Channel(0,1,0,0),Channel(1,0,0,0),Channel(2,0,1,0),Channel(3,1,2,1000)]
        array=(Channel*len(policies))(*policies)
        handle=self.lib.s6_rtc_create(b'127.0.0.1',array,len(array),maximum,depth,budget)
        self.assertTrue(handle,'native bounded RTC peer creation failed')
        self.addCleanup(self.lib.s6_rtc_free,handle)
        return handle

    def description(self,handle,offer):
        buffer=c.create_string_buffer(32769);until=time.monotonic()+5
        while time.monotonic()<until:
            size=self.lib.s6_rtc_local(handle,offer,buffer,len(buffer))
            self.assertGreaterEqual(size,0)
            if size:return buffer.raw[:size-1]
            self.assertEqual(self.lib.s6_rtc_wait(handle,10),0)
        self.fail('bounded native ICE gathering deadline')

    def pair(self,**options):
        first=self.create(**options);second=self.create(**options)
        self.assertEqual(self.lib.s6_rtc_open(first),0)
        offer=self.description(first,1)
        self.assertIn(b'a=fingerprint:',offer);self.assertIn(b'127.0.0.1',offer)
        self.assertEqual(self.lib.s6_rtc_remote(second,1,offer,len(offer)),0)
        answer=self.description(second,0)
        self.assertEqual(self.lib.s6_rtc_remote(first,0,answer,len(answer)),0)
        until=time.monotonic()+5
        while time.monotonic()<until:
            states=[self.lib.s6_rtc_open(handle) for handle in (first,second)]
            self.assertNotIn(-1,states)
            if states==[1,1]:return first,second
            time.sleep(.01)
        self.fail('bounded ICE/DTLS/channel-open deadline')

    def receive(self,handle):
        buffer=c.create_string_buffer(73728);event=Event()
        result=self.lib.s6_rtc_receive(handle,buffer,len(buffer),c.byref(event))
        return result,event,buffer.raw[:event.size]

    def next_event(self,handle):
        until=time.monotonic()+3
        while time.monotonic()<until:
            result,event,data=self.receive(handle)
            if result:return result,event,data
            self.assertEqual(self.lib.s6_rtc_wait(handle,10),0)
        self.fail('bounded native DataChannel receive deadline')

    def test_channels_order_reliability_and_binary_text_boundaries(self):
        first,second=self.pair()
        messages=[(0,0,b'ordered-binary'),(1,0,b'unordered-binary'),(2,0,b'PR-retransmit-zero'),
                  (3,0,b'PR-time-budget'),(0,1,'native UTF-8 文本'.encode()),(1,0,b''),(0,1,b'')]
        for channel,text,payload in messages:
            self.assertEqual(self.lib.s6_rtc_send(first,channel,text,payload,len(payload)),1)
            result,event,data=self.next_event(second)
            self.assertEqual((result,event.kind,event.channel,event.text,data),(1,1,channel,text,payload))
        self.assertEqual(self.receive(second)[0],0)

    def test_native_close_is_observed_and_other_channels_survive(self):
        first,second=self.pair()
        self.assertEqual(self.lib.s6_rtc_close_channel(first,1),1)
        for handle in (first,second):
            result,event,data=self.next_event(handle)
            self.assertEqual((result,event.kind,event.channel,data),(1,2,1,b''))
            self.assertEqual(self.lib.s6_rtc_close_channel(handle,1),1)
            self.assertEqual(self.receive(handle)[0],0)
        self.assertEqual(self.lib.s6_rtc_send(first,1,0,b'closed',6),-1)
        self.assertEqual(self.lib.s6_rtc_send(first,0,0,b'other-channel',13),1)
        result,event,data=self.next_event(second)
        self.assertEqual((result,event.kind,event.channel,data),(1,1,0,b'other-channel'))

    def test_callback_queue_overflow_is_terminal_not_silent_drop(self):
        first,second=self.pair(depth=1)
        for _ in range(3):self.assertEqual(self.lib.s6_rtc_send(first,0,0,b'bounded',7),1)
        time.sleep(.15)
        self.assertEqual(self.receive(second)[0],-1)
        self.assertEqual(self.lib.s6_rtc_send(second,0,0,b'closed-on-failure',17),-1)

    def test_invalid_channels_size_text_and_sdp_fail_closed(self):
        policies=(Channel*2)(Channel(0,1,0,0),Channel(0,1,0,0))
        self.assertFalse(self.lib.s6_rtc_create(b'127.0.0.1',policies,2,4096,1,4096))
        first,second=self.pair(maximum=4096)
        for channel,text,data in ((4,0,b'unadmitted'),(0,0,bytes(4097)),(0,1,b'text\0with-NUL'),
                                  (0,1,b'\xc0\x80'),(0,1,b'\xed\xa0\x80'),(0,1,b'\xf4\x90\x80\x80')):
            self.assertEqual(self.lib.s6_rtc_send(first,channel,text,data,len(data)),-1)
        self.assertEqual(self.receive(second)[0],0)
        self.assertEqual(self.lib.s6_rtc_remote(first,1,b'v=0\0',4),-1)
        self.assertEqual(self.lib.s6_rtc_remote(first,1,b'x'*32769,32769),-1)
        self.assertEqual(self.lib.s6_rtc_remote(first,1,b'v=0',3),-1,'renegotiation may not reuse a security session')

    def test_real_backpressure_refuses_whole_message_and_retry_keeps_order(self):
        first,second=self.pair(depth=128,budget=16777216)
        accepted=[];pending=None
        for number in range(128):
            payload=number.to_bytes(4,'big')+bytes(73724)
            result=self.lib.s6_rtc_send(first,0,0,payload,len(payload))
            self.assertIn(result,(0,1))
            if not result:pending=payload;break
            accepted.append(payload)
        self.assertIsNotNone(pending,'native send buffered-amount bound never applied')
        for payload in accepted:
            result,event,data=self.next_event(second)
            self.assertEqual((result,event.kind,event.channel,data),(1,1,0,payload))
        until=time.monotonic()+3
        while time.monotonic()<until:
            result=self.lib.s6_rtc_send(first,0,0,pending,len(pending))
            self.assertGreaterEqual(result,0)
            if result:break
            time.sleep(.005)
        else:self.fail('native whole-message retry deadline')
        result,event,data=self.next_event(second)
        self.assertEqual((result,event.kind,event.channel,data),(1,1,0,pending))
        self.assertEqual(self.receive(second)[0],0)

    def test_wrong_dtls_fingerprint_never_establishes_ready_channels(self):
        import re
        first=self.create();second=self.create()
        offer=self.description(first,1)
        self.assertEqual(self.lib.s6_rtc_remote(second,1,offer,len(offer)),0)
        answer=self.description(second,0)
        pattern=rb'(a=fingerprint:sha-256 )[0-9A-Fa-f:]+'
        bad,count=re.subn(pattern,lambda match:match[1]+b':'.join([b'00']*32),answer)
        self.assertEqual(count,1)
        self.assertEqual(self.lib.s6_rtc_remote(first,0,bad,len(bad)),0)
        until=time.monotonic()+5
        while time.monotonic()<until:
            status=self.lib.s6_rtc_open(first)
            self.assertNotEqual(status,1,'unverified DTLS certificate reported ready')
            if status==-1:break
            time.sleep(.01)
        else:self.fail('DTLS fingerprint failure was not observed')
        self.assertEqual(self.receive(first)[0],-1)

    def test_peer_queue_reservations_are_globally_bounded_and_released(self):
        policies=(Channel*1)(Channel(0,1,0,0));handles=[]
        try:
            for _ in range(4):
                handle=self.lib.s6_rtc_create(b'127.0.0.1',policies,1,4096,1,16777216)
                self.assertTrue(handle);handles.append(handle)
            self.assertFalse(self.lib.s6_rtc_create(b'127.0.0.1',policies,1,4096,1,16777216))
        finally:
            for handle in handles:self.lib.s6_rtc_free(handle)
        self.create(budget=16777216)


class WebRTCUnavailableBuildTests(unittest.TestCase):
    def test_compiled_out_provider_has_no_successful_operations(self):
        with tempfile.TemporaryDirectory(prefix='s6epe-unavailable-rtc-') as directory:
            output=Path(directory)/'unavailable.so'
            subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',
                            '-DS6EPE_DISABLE_WEBRTC',str(ROOT/'src/carrier_webrtc_native.c'),
                            '-o',str(output)],check=True,capture_output=True,timeout=30)
            backend=c.CDLL(str(output));backend.s6_rtc_create.restype=c.c_void_p
            self.assertEqual(backend.s6_rtc_available(),0)
            self.assertFalse(backend.s6_rtc_create(None,None,0,0,0,0))
            self.assertEqual(backend.s6_rtc_open(None),-1)


if __name__=='__main__':unittest.main()
