import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from java4shell import common, processes

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "linux", "Linux /proc identity checks")
class ProcessIdentityTests(unittest.TestCase):
    def test_pidfd_wrappers_prefer_native_python_functions(self):
        with mock.patch.object(processes.os, "pidfd_open", return_value=41, create=True) as opened, \
                mock.patch.object(processes.signal, "pidfd_send_signal", return_value=None,
                                  create=True) as sent, \
                mock.patch.object(processes, "_libc_pidfd_call", side_effect=AssertionError("libc fallback used")):
            self.assertEqual(processes.pidfd_open(123), 41)
            self.assertIsNone(processes.pidfd_send_signal(41, signal.SIGTERM))
        opened.assert_called_once_with(123, 0)
        sent.assert_called_once_with(41, signal.SIGTERM, None, 0)

    def test_libc_pidfd_errors_and_missing_symbols_preserve_errno(self):
        with mock.patch.object(processes.os, "pidfd_open", None, create=True), \
                mock.patch.object(processes.signal, "pidfd_send_signal", None, create=True):
            with self.assertRaises(OSError) as opened:
                processes.pidfd_open(-1)
            self.assertEqual(opened.exception.errno, errno.EINVAL)
            with self.assertRaises(OSError) as sent:
                processes.pidfd_send_signal(-1, 0)
            self.assertEqual(sent.exception.errno, errno.EBADF)
            with mock.patch.object(processes.ctypes, "CDLL", return_value=object()):
                with self.assertRaises(OSError) as missing:
                    processes.pidfd_open(os.getpid())
                self.assertEqual(missing.exception.errno, errno.ENOSYS)
                with self.assertRaises(common.Unavailable):
                    processes.require_pidfd_support()

    def test_pidfd_support_check_rejects_kernel_failures_and_closes_probe(self):
        with mock.patch.object(processes, "pidfd_open", side_effect=OSError(errno.ENOSYS, "unavailable")):
            with self.assertRaises(common.Unavailable):
                processes.require_pidfd_support()
        for function in ("pidfd_send_signal", "waitid"):
            descriptor = processes.pidfd_open(os.getpid())
            target = os if function == "waitid" else processes
            with self.subTest(function=function), \
                    mock.patch.object(processes, "pidfd_open", return_value=descriptor), \
                    mock.patch.object(target, function,
                                      side_effect=OSError(errno.ENOSYS, "unavailable")):
                with self.assertRaises(common.Unavailable):
                    processes.require_pidfd_support()
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_unreadable_or_malformed_stat_is_not_absence(self):
        pid = os.getpid()
        for error in (PermissionError("stat denied"), OSError("stat unavailable")):
            with self.subTest(error=error), mock.patch.object(Path, "read_text", side_effect=error):
                with self.assertRaises(type(error)):
                    processes.process_start_ticks(pid)
        with mock.patch.object(Path, "read_text", return_value="malformed"):
            with self.assertRaisesRegex(RuntimeError, "Malformed process stat"):
                processes.process_start_ticks(pid)
        with mock.patch.object(Path, "read_text", side_effect=FileNotFoundError("hidden stat")):
            with self.assertRaisesRegex(RuntimeError, "unavailable for live PID"):
                processes.process_start_ticks(pid)
        with mock.patch.object(Path, "read_text", side_effect=FileNotFoundError("gone")), \
                mock.patch.object(processes.os, "getpgid", side_effect=ProcessLookupError("gone")):
            self.assertIsNone(processes.process_start_ticks(pid))

    def test_unreadable_or_malformed_children_record_is_not_empty(self):
        target = Path("/proc") / str(os.getpid()) / "task" / str(os.getpid()) / "children"
        real_read = Path.read_text
        for replacement in (PermissionError("children denied"), "not-a-pid"):
            def read(path, *args, **kwargs):
                if path == target:
                    if isinstance(replacement, Exception):
                        raise replacement
                    return replacement
                return real_read(path, *args, **kwargs)
            with self.subTest(replacement=replacement), mock.patch.object(Path, "read_text", read):
                with self.assertRaises((PermissionError, RuntimeError)):
                    processes.descendant_pids(os.getpid())

    def test_missing_recorded_identity_does_not_mean_live_child_exited(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        try:
            with mock.patch.object(processes, "refresh_owned"):
                with self.assertRaisesRegex(RuntimeError, "No recorded start time"):
                    processes.remaining_owned(child.pid, {child.pid: None}, child.pid)
            self.assertIsNone(child.poll())
        finally:
            child.kill()
            child.wait(timeout=5)

    def test_live_identity_in_another_group_is_not_reported_exited(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        try:
            identities = {child.pid: processes.process_start_ticks(child.pid)}
            wrong_group = child.pid + 1
            with mock.patch.object(processes, "refresh_owned"):
                with self.assertRaisesRegex(RuntimeError, "changed process group"):
                    processes.remaining_owned(wrong_group, identities, child.pid)
                self.assertFalse(processes.signal_owned_group(wrong_group, identities, signal.SIGTERM))
            self.assertIsNone(child.poll())
        finally:
            child.kill()
            child.wait(timeout=5)

    def test_unreadable_descendant_stat_cannot_hide_surviving_listener(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_read = Path.read_text
        previous = processes.set_subreaper(True)
        child = None
        identities = {}
        try:
            with tempfile.TemporaryDirectory(prefix="identity-unit-", dir=common.SCRATCH) as temporary:
                out = Path(temporary)
                source = ("import json,os,signal,socket,time; from pathlib import Path; "
                          "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); child=os.fork();"
                          "\nif child==0:"
                          "\n signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                          "Path('child-ready').write_text('ready'); time.sleep(60); os._exit(0)"
                          "\nwhile not Path('child-ready').exists(): time.sleep(0.01)"
                          "\nPath('ready.tmp').write_text(json.dumps({'child':child,'port':s.getsockname()[1]})); "
                          "Path('ready.tmp').replace('ready.json'); time.sleep(60)")
                child = subprocess.Popen([sys.executable, "-c", source], cwd=out,
                                         start_new_session=True)
                deadline = time.monotonic() + 5
                while not (out / "ready.json").exists():
                    self.assertIsNone(child.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                ready = json.loads((out / "ready.json").read_text())
                descendant = ready["child"]
                identities[child.pid] = processes.process_start_ticks(child.pid)
                processes.refresh_owned(child.pid, identities)
                self.assertIn(descendant, identities)
                target = Path("/proc") / str(descendant) / "stat"

                def deny_descendant(path, *args, **kwargs):
                    if path == target:
                        raise PermissionError("injected owned-descendant stat denial")
                    return real_read(path, *args, **kwargs)

                errors = []
                report = {"forced_cleanup": False, "owned_processes_exited": False,
                          "remaining_owned_pids": None}
                with mock.patch.object(Path, "read_text", deny_descendant):
                    processes.shutdown_case(child, identities, report, errors)
                    self.assertTrue(errors)
                    self.assertTrue(report["forced_cleanup"])
                    self.assertFalse(report["owned_processes_exited"])
                    self.assertIsNone(report["remaining_owned_pids"])
                self.assertIsNotNone(child.poll())
        finally:
            if child is not None:
                processes.refresh_owned(child.pid, identities)
                processes.signal_owned_group(child.pid, identities, signal.SIGKILL)
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                deadline = time.monotonic() + 5
                while processes.remaining_owned(child.pid, identities, child.pid):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
            processes.set_subreaper(previous)

    def test_captured_pidfd_terminates_unreadable_descendant_listener(self):
        processes.require_pidfd_support()
        self.captured_pidfd_terminates_unreadable_descendant_listener()

    def test_libc_fallback_terminates_unreadable_descendant_listener(self):
        with mock.patch.object(processes.os, "pidfd_open", None, create=True), \
                mock.patch.object(processes.signal, "pidfd_send_signal", None, create=True), \
                mock.patch.object(processes.os, "P_PIDFD", None, create=True):
            self.assertEqual(processes.pidfd_waitid_type(), 3)
            processes.require_pidfd_support()
            self.captured_pidfd_terminates_unreadable_descendant_listener()

    def captured_pidfd_terminates_unreadable_descendant_listener(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_read = Path.read_text
        previous = processes.set_subreaper(True)
        child = None
        identities = processes.OwnedProcesses()
        try:
            with tempfile.TemporaryDirectory(prefix="pidfd-identity-unit-", dir=common.SCRATCH) as temporary:
                out = Path(temporary)
                source = ("import json,os,signal,socket,time; from pathlib import Path; "
                          "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); child=os.fork();"
                          "\nif child==0:"
                          "\n signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                          "Path('child-ready').write_text('ready'); time.sleep(60); os._exit(0)"
                          "\nwhile not Path('child-ready').exists(): time.sleep(0.01)"
                          "\nPath('ready.tmp').write_text(json.dumps({'child':child,'port':s.getsockname()[1]})); "
                          "Path('ready.tmp').replace('ready.json'); time.sleep(60)")
                child = subprocess.Popen([sys.executable, "-c", source], cwd=out,
                                         start_new_session=True)
                deadline = time.monotonic() + 5
                while not (out / "ready.json").exists():
                    self.assertIsNone(child.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                ready = json.loads((out / "ready.json").read_text())
                descendant = ready["child"]
                identities.remember(child.pid, processes.process_start_ticks(child.pid), child.pid)
                processes.refresh_owned(child.pid, identities)
                self.assertIn(descendant, identities)
                target = Path("/proc") / str(descendant) / "stat"

                def deny_descendant(path, *args, **kwargs):
                    if path == target:
                        raise PermissionError("injected owned-descendant stat denial")
                    return real_read(path, *args, **kwargs)

                with mock.patch.object(Path, "read_text", deny_descendant):
                    self.assertIn(descendant, processes.remaining_owned(child.pid, identities, child.pid))
                    processes.signal_owned_group(child.pid, identities, signal.SIGTERM)
                    child.wait(timeout=5)
                    with socket.create_connection(("127.0.0.1", ready["port"]), timeout=1):
                        pass
                    self.assertIn(descendant, processes.remaining_owned(child.pid, identities, child.pid))
                    report = {"forced_cleanup": False, "owned_processes_exited": False,
                              "remaining_owned_pids": None}
                    errors = []
                    processes.shutdown_case(child, identities, report, errors)
                    self.assertTrue(report["forced_cleanup"])
                    self.assertTrue(report["owned_processes_exited"])
                    self.assertEqual(report["remaining_owned_pids"], [])
                    self.assertTrue(errors)
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", ready["port"]), timeout=0.2)
        finally:
            if child is not None:
                identities.signal(signal.SIGKILL)
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                deadline = time.monotonic() + 5
                while processes.remaining_owned(child.pid, identities, child.pid):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
            identities.close()
            identities.close()
            processes.set_subreaper(previous)


if __name__ == "__main__":
    unittest.main()
