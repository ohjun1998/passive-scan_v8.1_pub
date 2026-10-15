"""Nonblocking, process-owned file locks with automatic release after a crash."""
import errno
import os
import stat
from contextlib import contextmanager
from pathlib import Path


def acquire_file_lock(fd, busy_message='Another writer is running'):
    """Lock a regular, open descriptor; its caller releases ownership by closing it."""
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise ValueError('Lock must be a regular file')
    try:
        if os.name == 'nt':
            import msvcrt
            # Lock the same byte even for empty O_EXCL lock files from older versions.
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'\0')
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EAGAIN, errno.EBUSY):
            raise ValueError(busy_message) from None
        raise


@contextmanager
def advisory_file_lock(path, busy_message='Another writer is running'):
    """Keep the inode stable: existing unlocked files are reusable, never unlinked.

    A leftover legacy lock file has no kernel owner and is automatically adopted.
    Live ownership is determined by the operating system, not by file existence.
    """
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Lock must not be a symlink')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_NONBLOCK', 0), 0o600)
    try:
        acquire_file_lock(fd, busy_message)
        yield
    finally:
        # Do not unlink: another waiter may already hold this same inode open.
        os.close(fd)
