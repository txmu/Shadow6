import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wan_evidence_repro import evidence_errors
from first_datagram_fault import FirstCarrierDatagramDrop


class ExactEvidenceGateTests(unittest.TestCase):
    def row(self):
        return {'status':'FAIL', 'stages':{
            'PCAP':{'status':'PASS'},'wireClassification':{'status':'PASS'},'leakScan':{'status':'PASS'},
            'correctness':{'status':'FAIL','reason':'TimeoutError: timed out'}},
            'noBypass':{'status':'PASS'}, 'faultInjection':{
                'status':'PASS','observedDroppedPackets':'1','filterRemoved':True}}

    def test_loss_must_remain_failed_while_evidence_passes(self):
        self.assertEqual(evidence_errors(self.row(),expected_loss=True),[])

    def test_missing_pcap_or_unowned_flow_cannot_pass(self):
        for key in ('PCAP','noBypass'):
            row=self.row()
            (row['stages'][key] if key=='PCAP' else row[key])['status']='FAIL'
            self.assertIn(key,evidence_errors(row,expected_loss=True))

    def test_undropped_data_or_unrelated_admission_error_is_not_a_reproduction(self):
        row=self.row(); row['faultInjection']['observedDroppedPackets']='0'
        self.assertIn('firstDrop',evidence_errors(row,expected_loss=True))
        row=self.row(); row['stages']['correctness']['reason']='FDAttachmentRejected'
        self.assertIn('unexpectedWorkloadFailure',evidence_errors(row,expected_loss=True))
        row=self.row(); row['status']='PASS';row['stages']['correctness']['status']='PASS'
        self.assertIn('lostBytesMustFail',evidence_errors(row,expected_loss=True))


class OwnedDropTests(unittest.TestCase):
    def run_fault(self, count):
        calls=[]
        pair=SimpleNamespace(a='owned-a',exec=lambda namespace,argv:['owned-netns',namespace,*argv])
        def command(argv,**kwargs):
            calls.append(argv)
            rows=[{'pref':404,'options':{'actions':[{'stats':{'packets':count}}]}}]
            return SimpleNamespace(stdout=json.dumps(rows).encode() if '-j' in argv else b'')
        with patch('first_datagram_fault.system_tool',return_value='/usr/sbin/tc'), \
             patch('first_datagram_fault.subprocess.run',side_effect=command):
            fault=FirstCarrierDatagramDrop(pair).start()
            fault.thread.join(timeout=3); fault.close()
        return fault.evidence(),calls

    def test_observed_single_drop_is_removed_only_in_the_owned_namespace(self):
        evidence,calls=self.run_fault(1)
        self.assertEqual(evidence['status'],'PASS')
        self.assertTrue(all(command[:2]==['owned-netns','owned-a'] for command in calls))
        self.assertIn('del',calls[-1]);self.assertIn('18402',calls[1])

    def test_boolean_counter_is_rejected_and_filter_is_still_removed(self):
        evidence,calls=self.run_fault(True)
        self.assertEqual(evidence['status'],'FAIL')
        self.assertEqual(evidence['errors'],['ValueError'])
        self.assertTrue(evidence['filterRemoved'])


if __name__=='__main__':unittest.main()
