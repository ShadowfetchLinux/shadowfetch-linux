"""Pure failure-path tests. No Podman/container/load is executed here."""
import hashlib
import subprocess
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qa_4_0_0"))
import unittest
from unittest.mock import patch
import container_stress as target

EXPECTED = hashlib.sha256(bytes(32*1024*1024)).hexdigest() + '  /tmp/load.bin\n'


def row(rc=0, error=None, stdout='', **more):
    return dict(rc=rc,error=error,stdout=stdout,stderr='',client_exited=True,**more)


class Fixture:
    def __init__(self, outputs): self.outputs=list(outputs);self.calls=[];self.time=0.0
    def run(self, argv, timeout, stopped):
        self.calls.append((argv,timeout));self.time+=11
        value=self.outputs.pop(0)
        if isinstance(value,Exception):raise value
        return value
    def profile(self):
        return target.run_profile(10,'a'*64,'pure-test',run=self.run,clock=lambda:self.time,sleep=lambda _:None,emit=lambda _:None)


class LifecycleTests(unittest.TestCase):
    def test_primary_timeout_and_cleanup_failure_both_survive(self):
        f=Fixture([row(None,'operation timeout'),row(None,'operation timeout'),row(1)])
        r=f.profile()
        self.assertEqual(r['status'],'FAIL')
        self.assertEqual(r['primary_error']['operation']['error'],'operation timeout')
        self.assertEqual(r['cleanup_errors'][0]['operation']['error'],'operation timeout')
        self.assertIs(r['final_container_exists'],False)

    def test_cleanup_exception_cannot_mask_primary_and_exists_still_runs(self):
        f=Fixture([row(125),RuntimeError('cleanup unavailable'),row(1)])
        r=f.profile()
        self.assertEqual(r['primary_error']['operation']['rc'],125)
        self.assertIn('cleanup unavailable',r['cleanup_errors'][0]['operation']['error'])
        self.assertEqual(f.calls[-1][0],['podman','container','exists','sfqa-stress-pure-test'])

    def test_valid_data_removed_and_independently_absent_can_smoke_pass(self):
        r=Fixture([row(stdout=EXPECTED),row(),row(1)]).profile()
        self.assertEqual(r['status'],'SMOKE_PASS');self.assertIsNone(r['primary_error'])
        self.assertEqual(r['cleanup_errors'],[]);self.assertIs(r['final_container_exists'],False)

    def test_checksum_mismatch_never_passes_even_with_clean_cleanup(self):
        r=Fixture([row(stdout='wrong'),row(),row(1)]).profile()
        self.assertEqual(r['status'],'FAIL');self.assertIsNotNone(r['primary_error'])

    def test_remaining_container_fails(self):
        r=Fixture([row(stdout=EXPECTED),row(),row(0)]).profile()
        self.assertEqual(r['status'],'FAIL');self.assertIs(r['final_container_exists'],True)

    def test_unknown_existence_and_unexited_client_are_retained(self):
        r=Fixture([row(stdout=EXPECTED),row(),row(None,'operation timeout',client_pid=123)]).profile()
        self.assertEqual(r['status'],'FAIL');self.assertIsNone(r['final_container_exists'])
        self.assertTrue(r['cleanup_errors'])

    def test_every_lifecycle_has120_limit_and_no_work_retry(self):
        f=Fixture([row(125),row(),row(1)]);f.profile()
        self.assertEqual(len(f.calls),3)
        self.assertTrue(all(timeout==120 for _,timeout in f.calls))
        self.assertEqual(sum(argv[1]=='run' for argv,_ in f.calls),1)
        argv=f.calls[0][0]
        for option in ('--network=none','--pull=never','--memory=256m','--pids-limit=64'):self.assertIn(option,argv)

    def test_timeout_remains_primary_after_client_term_exits(self):
        class FakeProcess:
            pid=123456;returncode=None;stdout=None;stderr=None
            def __init__(self):self.calls=0
            def poll(self):return self.returncode
            def communicate(self,timeout):
                self.calls+=1
                if self.calls==1:raise subprocess.TimeoutExpired('podman',timeout,output=b'partial',stderr=b'detail')
                self.returncode=-15;return 'partial','detail'
        proc=FakeProcess()
        with patch.object(target.subprocess,'Popen',return_value=proc),patch.object(target.os,'killpg') as kill,patch.object(target.time,'monotonic',side_effect=[0,0,121,121]):
            r=target.operation(['podman','run'],timeout=120)
        self.assertEqual(r['error'],'operation timeout');self.assertEqual(r['stdout'],'partial')
        self.assertEqual(r['rc'],-15);self.assertIs(r['client_exited'],True);kill.assert_called_once()

    def test_unexited_client_makes_cleanup_fail_even_if_container_absent(self):
        value=row(None,'operation timeout');value['client_exited']=False;value['client_pid']=123
        r=Fixture([value,row(),row(1)]).profile()
        self.assertTrue(any('client exit' in e['error'] for e in r['cleanup_errors']))
        self.assertEqual(r['status'],'FAIL')


if __name__=='__main__':unittest.main()
