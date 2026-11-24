"""Real-child regressions for the pidfd-to-identity handoff."""
from contextlib import contextmanager, ExitStack
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from java4shell import common, processes

ROOT = Path(__file__).resolve().parents[1]

CHILD_SOURCE = """import os, time
from pathlib import Path
child = os.fork()
if child == 0:
    while not Path('exit-child').exists(): time.sleep(0.005)
    os._exit(0)
Path('ready.tmp').write_text(str(child))
Path('ready.tmp').replace('ready')
while not Path('reap-child').exists(): time.sleep(0.005)
os.waitpid(child, 0)
Path('reaped.tmp').write_text('yes')
Path('reaped.tmp').replace('reaped')
while True: time.sleep(60)
"""


@unittest.skipUnless(sys.platform == "linux", "Linux owned-child pidfd capture")
class ProcessCaptureTests(unittest.TestCase):
    @contextmanager
    def pidfd_api(self, libc):
        with ExitStack() as stack:
            stack.enter_context(processes.managed_signals())
            if libc:
                stack.enter_context(mock.patch.object(processes.os, "pidfd_open", None, create=True))
                stack.enter_context(mock.patch.object(processes.signal, "pidfd_send_signal", None, create=True))
                stack.enter_context(mock.patch.object(processes.os, "P_PIDFD", None, create=True))
            processes.require_pidfd_support()
            yield

    def wait_file(self, path, process):
        deadline = time.monotonic() + 5
        while not path.is_file():
            self.assertIsNone(process.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.005)

    @contextmanager
    def owned_descendant(self):
        common.SCRATCH.mkdir(exist_ok=True)
        previous = processes.set_subreaper(True)
        identities, process, watcher = processes.OwnedProcesses(), None, None
        try:
            with tempfile.TemporaryDirectory(prefix="capture-unit-", dir=common.SCRATCH) as directory:
                directory = Path(directory)
                process = subprocess.Popen([sys.executable, "-B", "-c", CHILD_SOURCE], cwd=directory,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, start_new_session=True)
                identities.remember(process.pid, processes.process_start_ticks(process.pid), process.pid)
                self.wait_file(directory / "ready", process)
                descendant = int((directory / "ready").read_text())
                ticks = processes.process_start_ticks(descendant)
                watcher = processes.pidfd_open(descendant)
                yield directory, process, identities, descendant, ticks, watcher
        finally:
            try:
                if watcher is not None:
                    try:
                        processes.pidfd_send_signal(watcher, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process is not None:
                    # Setup can fail before the descendant pidfd exists. Use
                    # the runner's attested session discovery as well as any
                    # handles already captured, then reap every owned child.
                    errors = []
                    report = {"forced_cleanup": False, "owned_processes_exited": False,
                              "remaining_owned_pids": None}
                    processes.shutdown_case(process, identities, report, errors)
                    self.assertTrue(report["owned_processes_exited"])
                    self.assertEqual(report["remaining_owned_pids"], [])
                if watcher is not None:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            os.waitid(processes.pidfd_waitid_type(), watcher, os.WEXITED | os.WNOHANG)
                        except ChildProcessError:
                            pass
                        poller = select.poll()
                        poller.register(watcher, select.POLLIN)
                        if any(flags & (select.POLLIN | select.POLLHUP)
                               for _, flags in poller.poll(0)):
                            break
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.005)
            finally:
                if watcher is not None:
                    os.close(watcher)
                identities.close()
                processes.set_subreaper(previous)

    def release_and_reap(self, directory, process, descendant, watcher):
        (directory / "exit-child").touch()
        (directory / "reap-child").touch()
        self.wait_file(directory / "reaped", process)
        poller = select.poll()
        poller.register(watcher, select.POLLIN)
        self.assertTrue(any(flags & (select.POLLIN | select.POLLHUP)
                            for _, flags in poller.poll(0)))
        self.assertIsNone(processes.process_start_ticks(descendant))

    def assert_closed(self, descriptor):
        with self.assertRaises(OSError) as error:
            os.fstat(descriptor)
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_setup_failure_before_watcher_cleans_descendant(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc):
                real_read = Path.read_text
                observed = {}

                def empty_ready(path, *args, **kwargs):
                    if (path.name == "ready" and path.parent.name.startswith("capture-unit-")
                            and not observed):
                        deadline = time.monotonic() + 5
                        text = real_read(path, *args, **kwargs)
                        while not text:
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.005)
                            text = real_read(path, *args, **kwargs)
                        pid = int(text)
                        launcher = os.getpgid(pid)
                        observed.update(pid=pid, ticks=processes.process_start_ticks(pid),
                                        watcher=processes.pidfd_open(pid), launcher=launcher,
                                        launcher_ticks=processes.process_start_ticks(launcher))
                        return ""  # Fail setup before its own watcher exists.
                    return real_read(path, *args, **kwargs)

                try:
                    with mock.patch.object(Path, "read_text", empty_ready):
                        with self.assertRaises(ValueError):
                            with self.owned_descendant():
                                self.fail("Fixture setup unexpectedly completed")
                    self.assertTrue(observed)
                    self.assertFalse(processes.pidfd_alive(observed["watcher"], observed["pid"]))
                    self.assertNotEqual(processes.process_start_ticks(observed["pid"]), observed["ticks"])
                    self.assertNotEqual(processes.process_start_ticks(observed["launcher"]),
                                        observed["launcher_ticks"])
                finally:
                    if observed:
                        try:
                            processes.pidfd_send_signal(observed["watcher"], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitid(processes.pidfd_waitid_type(), observed["watcher"], os.WEXITED)
                        except ChildProcessError:
                            pass
                        os.close(observed["watcher"])

    def test_reaped_after_pidfd_open_is_confirmed_exit(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc), self.owned_descendant() as owned:
                directory, process, identities, descendant, ticks, watcher = owned
                real_open, opened = processes.pidfd_open, []

                def scheduled_open(pid):
                    descriptor = real_open(pid)
                    try:
                        if pid == descendant:
                            opened.append(descriptor)
                            self.release_and_reap(directory, process, descendant, watcher)
                    except BaseException:
                        os.close(descriptor)
                        raise
                    return descriptor

                with mock.patch.object(processes, "pidfd_open", scheduled_open):
                    identities.remember(descendant, ticks, process.pid)
                self.assertNotIn(descendant, identities)
                self.assertNotIn(descendant, identities._pidfds)
                self.assertEqual(len(opened), 1)
                self.assert_closed(opened[0])
                self.assertTrue(identities._state(process.pid, identities[process.pid], process.pid))

    def test_reaped_after_start_time_recheck_is_confirmed_exit(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc), self.owned_descendant() as owned:
                directory, process, identities, descendant, ticks, watcher = owned
                real_ticks, observed = processes.process_start_ticks, []

                def scheduled_ticks(pid):
                    value = real_ticks(pid)
                    if pid == descendant and not observed:
                        self.assertEqual(value, ticks)
                        observed.append(value)
                        self.release_and_reap(directory, process, descendant, watcher)
                    return value

                with mock.patch.object(processes, "process_start_ticks", scheduled_ticks):
                    identities.remember(descendant, ticks, process.pid)
                self.assertEqual(observed, [ticks])
                self.assertNotIn(descendant, identities)
                self.assertNotIn(descendant, identities._pidfds)

    def test_live_conflicting_or_unreadable_state_is_rejected(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc), self.owned_descendant() as owned:
                _, process, identities, descendant, ticks, watcher = owned
                real_ticks, real_open = processes.process_start_ticks, processes.pidfd_open
                for bad_ticks in (str(int(ticks) + 1), None, PermissionError("injected stat denial")):
                    opened = []

                    def observed_open(pid):
                        descriptor = real_open(pid)
                        opened.append(descriptor)
                        return descriptor

                    def bad_identity(pid):
                        if pid == descendant:
                            if isinstance(bad_ticks, Exception):
                                raise bad_ticks
                            return bad_ticks
                        return real_ticks(pid)

                    with self.subTest(identity=bad_ticks), \
                            mock.patch.object(processes, "pidfd_open", observed_open), \
                            mock.patch.object(processes, "process_start_ticks", bad_identity):
                        with self.assertRaises((RuntimeError, PermissionError)):
                            identities.remember(descendant, ticks, process.pid)
                    self.assertNotIn(descendant, identities)
                    self.assertNotIn(descendant, identities._pidfds)
                    self.assertEqual(len(opened), 1)
                    self.assert_closed(opened[0])
                self.assertEqual(real_ticks(descendant), ticks)
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    identities.remember(descendant, ticks, process.pid + 1)
                self.assertNotIn(descendant, identities)
                poller = select.poll()
                poller.register(watcher, select.POLLIN)
                self.assertEqual(poller.poll(0), [])

    def test_bounded_command_accepts_ordinary_grandchild_exit(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc):
                common.SCRATCH.mkdir(exist_ok=True)
                with tempfile.TemporaryDirectory(prefix="capture-command-unit-", dir=common.SCRATCH) as temporary:
                    directory = Path(temporary)
                    source = CHILD_SOURCE.replace("while True: time.sleep(60)", "raise SystemExit(0)")
                    real_open, captured = processes.pidfd_open, []

                    def scheduled_open(pid):
                        descriptor = real_open(pid)
                        try:
                            ready = directory / "ready"
                            if ready.is_file() and pid == int(ready.read_text()):
                                captured.append(pid)
                                (directory / "exit-child").touch()
                                (directory / "reap-child").touch()
                                deadline = time.monotonic() + 5
                                while not (directory / "reaped").is_file():
                                    self.assertLess(time.monotonic(), deadline)
                                    time.sleep(0.005)
                                self.assertIsNone(processes.process_start_ticks(pid))
                        except BaseException:
                            os.close(descriptor)
                            raise
                        return descriptor

                    with mock.patch.object(processes, "pidfd_open", scheduled_open):
                        result = processes.run_bounded_command([sys.executable, "-B", "-c", source],
                                                         directory, 10, directory / "process.json")
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(len(captured), 1)
                    report = json.loads((directory / "process.json").read_text())
                    self.assertEqual(report["status"], "passed")
                    self.assertTrue(report["owned_processes_exited"])
                    self.assertFalse(report["forced_cleanup"])
                    self.assertEqual(report["remaining_owned_pids"], [])
                    self.assertNotIn("cleanup_errors", report)


if __name__ == "__main__":
    unittest.main()
