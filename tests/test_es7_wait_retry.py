"""Real-child regressions for bounded retry of unknown cleanup state."""
from contextlib import contextmanager, ExitStack
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

CHILD_SOURCE = """import os, signal, time
from pathlib import Path
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path('child-ready.tmp').write_text(str(os.getpid()))
    Path('child-ready.tmp').replace('child-ready')
    while True: time.sleep(60)
while not Path('child-ready').exists(): time.sleep(0.01)
Path('ready.tmp').write_text(str(child))
Path('ready.tmp').replace('ready')
while True: time.sleep(60)
"""


@unittest.skipUnless(sys.platform == "linux", "Linux owned-child pidfd cleanup")
class WaitRemainingOwnedTests(unittest.TestCase):
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

    @contextmanager
    def owned_descendant(self):
        common.SCRATCH.mkdir(exist_ok=True)
        previous = processes.set_subreaper(True)
        identities, process = processes.OwnedProcesses(), None
        try:
            with tempfile.TemporaryDirectory(prefix="wait-retry-unit-", dir=common.SCRATCH) as directory:
                directory = Path(directory)
                process = subprocess.Popen([sys.executable, "-B", "-c", CHILD_SOURCE], cwd=directory,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, start_new_session=True)
                identities.remember(process.pid, processes.process_start_ticks(process.pid), process.pid)
                deadline = time.monotonic() + 5
                while not (directory / "ready").is_file():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                descendant = int((directory / "ready").read_text())
                processes.refresh_owned(process.pid, identities)
                self.assertIn(descendant, identities)
                process.terminate()
                process.wait(timeout=5)
                yield process, identities, descendant, identities[descendant]
        finally:
            try:
                if process is not None:
                    errors = []
                    processes.signal_owned_or_child(process, identities, signal.SIGKILL, errors)
                    process.wait(timeout=5)
                    self.assertEqual(processes.wait_remaining_owned(process, identities, errors, 5), {})
            finally:
                identities.close()
                processes.set_subreaper(previous)

    def test_exit_between_pidfd_check_and_refresh_is_retried(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc), self.owned_descendant() as owned:
                process, identities, descendant, ticks = owned
                target = Path("/proc") / str(descendant) / "stat"
                real_read, real_refresh = Path.read_text, processes.refresh_owned
                real_state = processes.OwnedProcesses._state
                real_remaining = processes.remaining_owned_or_unknown
                states, returns, transitions = [], [], []

                def denied(path, *args, **kwargs):
                    if path == target:
                        raise PermissionError("injected owned-descendant stat denial")
                    return real_read(path, *args, **kwargs)

                def observed_state(collection, pid, start_ticks, group, *, reap=False):
                    value = real_state(collection, pid, start_ticks, group, reap=reap)
                    if pid == descendant:
                        states.append((reap, value))
                    return value

                def scheduled_refresh(group, collection):
                    if not transitions:
                        # Preserve a real alive result, then make the exact
                        # captured child exit before the process-tree refresh.
                        self.assertIn((True, True), states)
                        descriptor = collection._pidfds[descendant][2]
                        processes.pidfd_send_signal(descriptor, signal.SIGKILL)
                        poller = select.poll()
                        poller.register(descriptor, select.POLLIN)
                        self.assertTrue(any(flags & select.POLLIN for _, flags in poller.poll(5000)))
                        with target.open() as source:
                            fields = source.read().rsplit(")", 1)[1].split()
                        self.assertEqual((fields[0], fields[19]), ("Z", ticks))
                        transitions.append(True)
                    return real_refresh(group, collection)

                def observed_remaining(child, collection, errors):
                    value = real_remaining(child, collection, errors)
                    returns.append(value)
                    return value

                with mock.patch.object(Path, "read_text", denied), \
                        mock.patch.object(processes.OwnedProcesses, "_state", observed_state), \
                        mock.patch.object(processes, "refresh_owned", scheduled_refresh), \
                        mock.patch.object(processes, "remaining_owned_or_unknown", observed_remaining):
                    errors = []
                    remaining = processes.wait_remaining_owned(process, identities, errors, 1)
                self.assertEqual(transitions, [True])
                self.assertIsNone(returns[0])
                self.assertEqual(remaining, {})
                self.assertGreaterEqual(len(returns), 2)
                self.assertIn((False, False), states)
                self.assertTrue(any("PermissionError" in error for error in errors))

    def test_persistent_unknown_remains_unknown_at_deadline(self):
        for libc in (False, True):
            with self.subTest(libc=libc), self.pidfd_api(libc), self.owned_descendant() as owned:
                process, identities, descendant, ticks = owned
                errors = []
                with mock.patch.object(processes, "refresh_owned",
                                       side_effect=PermissionError("injected persistent owned-tree denial")):
                    started = time.monotonic()
                    remaining = processes.wait_remaining_owned(process, identities, errors, 0.12)
                    elapsed = time.monotonic() - started
                self.assertIsNone(remaining)
                self.assertGreaterEqual(elapsed, 0.12)
                self.assertGreaterEqual(len(errors), 2)
                self.assertTrue(identities._state(descendant, ticks, process.pid))


if __name__ == "__main__":
    unittest.main()
