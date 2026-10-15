"""Protocol startup boundaries and false-positive controls for the local lab runner."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from recon81.codex_review import _process, ReviewFailure

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('community_reproduce',ROOT/'examples/community_reproduce.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)


class StartupAndReproductionTests(unittest.TestCase):
    def test_no_execution_events_is_distinct_from_model_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ReviewFailure) as caught:
                _process([sys.executable,'-c','import time;time.sleep(2)'],directory,2,
                         on_event=lambda e:None,first_response_timeout=.1)
        error=caught.exception
        self.assertEqual(('CLI_EVENT_TIMEOUT','startup'),(error.code,error.stage))
        self.assertEqual(0,error.diagnostic['execution_events_received'])
        self.assertFalse(error.diagnostic['model_response_seen'])
    def test_diagnostic_never_copies_strings_or_unknown_keys(self):
        error=ReviewFailure('CLI_EVENT_TIMEOUT','startup',{'stderr':'NEVER_SAVE','stdout_bytes':5,
                            'elapsed_seconds':float('inf'),'model_response_seen':False})
        self.assertEqual({'stdout_bytes':5,'model_response_seen':False},error.diagnostic)
    def test_nonzero_exit_keeps_error_code_and_safe_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ReviewFailure) as caught:
                _process([sys.executable,'-c',"import sys;sys.stderr.write('quota exceeded PRIVATE');sys.exit(2)"],directory,2)
        self.assertEqual('RATE_LIMIT',caught.exception.code)
        self.assertGreater(caught.exception.diagnostic['stderr_bytes'],0)
        self.assertNotIn('PRIVATE',str(caught.exception.diagnostic))
    def test_loopback_only_and_no_userinfo_or_path(self):
        self.assertEqual('http://127.0.0.1:18090',lab.local_target('http://127.0.0.1:18090/'))
        for target in ('https://127.0.0.1:18090','http://example.test','http://127.0.0.1@evil.test',
                       'http://127.0.0.1:18090/private','http://127.0.0.1:18090?target=external'):
            with self.subTest(target=target),self.assertRaises(ValueError):lab.local_target(target)
    def test_redirect_is_blocked_before_another_request(self):
        with self.assertRaises(ValueError):lab.NoRedirect().redirect_request(None,None,302,'',{},'http://external.test')
    def test_http_200_without_private_data_is_not_a_finding(self):
        case=lab.CASES[0]
        row=lab.classify(case,'alice',200,'{"error":"not found"}')
        self.assertFalse(row['unauthorized_data_returned']);self.assertFalse(row['policy_match'])
        row=lab.classify(case,'alice',200,'{"ID":102,"OWNER_ID":2,"PRODUCT":"fixture"}')
        self.assertTrue(row['unauthorized_data_returned'])
    def test_fixed_denial_and_allowed_owner_controls(self):
        case=lab.CASES[0]
        self.assertTrue(lab.classify(case,'alice',404,'{"error":"missing"}')['policy_match'])
        self.assertFalse(lab.classify(case,'bob',200,'{}')['policy_match'])
        self.assertTrue(lab.classify(case,'bob',200,'{"ID":102,"OWNER_ID":2,"PRODUCT":"fixture"}')['policy_match'])
        self.assertFalse(lab.classify(case,'alice',404,'{"ID":102,"OWNER_ID":2,"PRODUCT":"fixture"}')['policy_match'])


if __name__=='__main__':unittest.main()
