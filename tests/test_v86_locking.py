"""Real child-process crash/resume and contention checks; no model or network calls."""
import errno
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from recon81.locking import advisory_file_lock, acquire_file_lock
from recon81.review_batch import serialized

ROOT = Path(__file__).resolve().parents[1]


class CrashReleasedLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.lock = self.directory / '.review-write.lock'
    def tearDown(self):
        self.tmp.cleanup()
    def invoke(self):
        @serialized
        def operation(directory):
            return 'resumed'
        return operation(self.directory)
    def test_abrupt_child_exit_releases_lock_and_preserves_inode_for_resume(self):
        code = """import os,sys
from recon81.review_batch import serialized
@serialized
def crash(directory):
    os._exit(9)
crash(sys.argv[1])
"""
        child = subprocess.run([sys.executable, '-c', code, str(self.directory)], cwd=ROOT,
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(9, child.returncode, child.stderr)
        self.assertTrue(self.lock.is_file())
        before = self.lock.stat().st_ino
        self.assertEqual('resumed', self.invoke())
        self.assertEqual(before, self.lock.stat().st_ino)
    def test_live_child_blocks_second_writer_then_releases_on_exit(self):
        code = """import sys
from recon81.review_batch import serialized
@serialized
def hold(directory):
    print('locked',flush=True)
    sys.stdin.read(1)
hold(sys.argv[1])
"""
        child = subprocess.Popen([sys.executable, '-c', code, str(self.directory)], cwd=ROOT,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual('locked\n', child.stdout.readline())
            before = self.lock.stat().st_ino
            with self.assertRaisesRegex(ValueError, 'Another batch writer'):
                self.invoke()
            self.assertEqual(before, self.lock.stat().st_ino)
            child.communicate('x', timeout=10)
            self.assertEqual(0, child.returncode)
            self.assertEqual('resumed', self.invoke())
            self.assertEqual(before, self.lock.stat().st_ino)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
    def test_old_unlocked_file_is_adopted_without_removal_or_truncation(self):
        self.lock.write_bytes(b'legacy writer marker')
        before = self.lock.stat().st_ino
        self.assertEqual('resumed', self.invoke())
        self.assertEqual(before, self.lock.stat().st_ino)
        self.assertEqual(b'legacy writer marker', self.lock.read_bytes())
    def test_exception_releases_lock(self):
        with self.assertRaises(RuntimeError):
            with advisory_file_lock(self.lock):
                raise RuntimeError('offline fixture')
        self.assertEqual('resumed', self.invoke())
    def test_windows_nonblocking_byte_lock_and_contention(self):
        windows = Mock(LK_NBLCK=2)
        with self.lock.open('w+b') as stream:
            with patch.dict(sys.modules, {'msvcrt': windows}), patch('recon81.locking.os.name', 'nt'):
                acquire_file_lock(stream.fileno(), 'busy')
                windows.locking.assert_called_once_with(stream.fileno(), 2, 1)
                self.assertEqual(1, os.fstat(stream.fileno()).st_size)
                self.assertEqual(0, os.lseek(stream.fileno(), 0, os.SEEK_CUR))
                windows.locking.side_effect = OSError(errno.EACCES, 'held')
                with self.assertRaisesRegex(ValueError, 'busy'):
                    acquire_file_lock(stream.fileno(), 'busy')
    def test_symlink_lock_is_rejected(self):
        target = self.directory / 'target';target.write_text('unchanged')
        try:
            self.lock.symlink_to(target)
        except OSError:
            self.skipTest('Symlink creation unavailable')
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual('unchanged', target.read_text())


if __name__ == '__main__':
    unittest.main()
