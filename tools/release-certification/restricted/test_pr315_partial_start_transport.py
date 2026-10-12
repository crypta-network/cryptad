"""Root/kernel observer lifetime checks, not installed acceptance results."""
import os
from pathlib import Path
import pwd
import sys
import time
import unittest
from unittest.mock import patch

import pr314_workload_driver as driver
import pr315_partial_start_transport as transport
from cross_version_workload import WorkloadClient


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,
                     'requires disposable native Linux root and pidfd')
class PartialStartTransportTest(unittest.TestCase):
    def test_actual_observer_remains_alive_after_delayed_start_response_until_sampled(self):
        account = pwd.getpwnam('nobody')
        def delayed_request(*args):
            time.sleep(.05)
            return {'state': 'running'}
        deadline=time.monotonic_ns()+10*10**9
        with patch.object(WorkloadClient, 'request', side_effect=delayed_request):
            parent,pid,response,started,observed=transport.start(
                driver,account,'a'*64,deadline)
        try:
            self.assertGreaterEqual(observed-started,40_000_000)
            self.assertEqual('transient-start-response',response['classification'])
            time.sleep(.02)  # A normal return would already have ended the old child.
            actual=driver._positive_observer_epoch(pid,account.pw_uid,deadline)
            self.assertEqual(pid,actual['pid'])
            self.assertGreater(actual['observedMonotonicNs'],observed)
            descriptor=os.pidfd_open(pid)
            try:
                self.assertFalse(driver.select.select([descriptor],[],[],0)[0])
                transport.finish(driver,parent,pid,deadline)
                self.assertTrue(driver.select.select([descriptor],[],[],1)[0])
            finally:
                os.close(descriptor)
        finally:
            parent.close()
            try:driver.stop_child(pid)
            except ChildProcessError:pass

    def test_invalid_start_reply_is_rejected_and_actor_reaped(self):
        with patch.object(WorkloadClient,'request',return_value={'state':'wrong'}):
            with self.assertRaisesRegex(ValueError,'start-response-invalid'):
                transport.start(driver,pwd.getpwnam('nobody'),'a'*64,
                    time.monotonic_ns()+5*10**9)


if __name__=='__main__':unittest.main()
