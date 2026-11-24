import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from java4shell import common, processes, es7 as es7_api, gc as gc_support

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("es7_cleanup_runner", ROOT / "run_es7.py")
es7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es7)


@unittest.skipUnless(sys.platform == "linux", "Linux process ownership and subreaper")
class CleanupTests(unittest.TestCase):
    def run_failure(self, fault, *, descendant=True):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        real_ticks, real_write = processes.process_start_ticks, common.write_json
        real_remaining = processes.remaining_owned_or_unknown
        children, recorded = [], {}
        previous = processes.set_subreaper(True)
        try:
            with tempfile.TemporaryDirectory(prefix="cleanup-unit-", dir=common.SCRATCH) as temporary:
                out = Path(temporary)
                source = ("import json,os,signal,socket,time; from pathlib import Path; "
                          "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); "
                          "child=os.fork() if " + repr(descendant) + " else -1;"
                          "\nif child==0:"
                          "\n if " + repr(fault == "cleanup-interrupt") + ": signal.signal(signal.SIGTERM,signal.SIG_IGN)"
                          "\n Path('child-ready').write_text('ready'); time.sleep(60); os._exit(0)"
                          "\nwhile child>0 and not Path('child-ready').exists(): time.sleep(0.01)"
                          "\nPath('ready.tmp').write_text(json.dumps({'port':s.getsockname()[1],"
                          "'child':child})); Path('ready.tmp').replace('ready.json'); time.sleep(60)")

                def launch(_command, **kwargs):
                    child = real_popen([sys.executable, "-c", source], **kwargs)
                    children.append(child)
                    deadline = time.monotonic() + 5
                    while not (out / "ready.json").exists():
                        if child.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("Harmless test child did not start")
                        time.sleep(0.01)
                    recorded.update(json.loads((out / "ready.json").read_text()))
                    recorded["identities"] = {child.pid: real_ticks(child.pid)}
                    if recorded["child"] > 0:
                        recorded["identities"][recorded["child"]] = real_ticks(recorded["child"])
                    return child

                fired = False
                cleanup_interrupted = False

                def write_report(path, value):
                    nonlocal fired
                    if "launcher_pid" in value and (not fired or fault == "persistent-write"):
                        fired = True
                        raise OSError("injected post-launch report failure")
                    return real_write(path, value)

                def read_ticks(pid):
                    nonlocal fired
                    if not fired or fault == "unattested":
                        fired = True
                        if fault == "interrupt":
                            raise KeyboardInterrupt
                        raise OSError("injected identity failure")
                    return real_ticks(pid)

                def interrupt_descendant_wait(process, identities, errors):
                    nonlocal cleanup_interrupted
                    remaining = real_remaining(process, identities, errors)
                    if not cleanup_interrupted and process.poll() is not None and remaining:
                        cleanup_interrupted = True
                        raise KeyboardInterrupt
                    return remaining

                args = SimpleNamespace(gc_stress=False, startup_timeout=1,
                                       request_timeout=1, gc_timeout=1)
                expected = KeyboardInterrupt if fault in ("interrupt", "cleanup-interrupt") else (
                    OSError if fault == "persistent-write" else RuntimeError)
                try:
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.object(es7, "prepare_case", return_value=(
                            out / "config", common.clean_environment(), ["harmless-child"], [])))
                        stack.enter_context(mock.patch.object(es7.subprocess, "Popen", side_effect=launch))
                        if fault in ("write", "persistent-write", "cleanup-interrupt"):
                            stack.enter_context(mock.patch.object(common, "write_json", side_effect=write_report))
                            if fault == "cleanup-interrupt":
                                stack.enter_context(mock.patch.object(processes, "remaining_owned_or_unknown",
                                    side_effect=interrupt_descendant_wait))
                        elif fault == "discovery":
                            stack.enter_context(mock.patch.object(processes, "refresh_owned",
                                side_effect=OSError("injected discovery failure")))
                        else:
                            stack.enter_context(mock.patch.object(processes, "process_start_ticks",
                                                                  side_effect=read_ticks))
                        with self.assertRaises(expected):
                            es7.run_case(out, out, out, "affected", 21, None,
                                         "unused", [], {}, args)
                    self.assertEqual(len(children), 1)
                    if fault == "cleanup-interrupt":
                        self.assertTrue(cleanup_interrupted)
                    child = children[0]
                    self.assertIsNotNone(child.poll(), "The direct child survived the error")
                    self.assertEqual(processes.remaining_owned(child.pid, recorded["identities"], child.pid), {})
                    with self.assertRaises(OSError):
                        socket.create_connection(("127.0.0.1", recorded["port"]), timeout=0.2)
                    if fault != "persistent-write":
                        report = json.loads((out / "report.json").read_text())
                        self.assertEqual(report["status"], "failed")
                        if fault == "discovery":
                            self.assertIs(report["owned_processes_exited"], False)
                            self.assertIsNone(report["remaining_owned_pids"])
                            self.assertTrue(report["cleanup_errors"])
                        else:
                            self.assertIs(report["owned_processes_exited"], True)
                            if fault == "unattested":
                                self.assertTrue(report["cleanup_errors"])
                finally:
                    for child in children:
                        identities = recorded.get("identities", {})
                        processes.refresh_owned(child.pid, identities)
                        processes.signal_owned_group(child.pid, identities, signal.SIGKILL)
                        if child.poll() is None:
                            child.kill()
                        child.wait(timeout=5)
                        deadline = time.monotonic() + 5
                        while processes.remaining_owned(child.pid, identities, child.pid):
                            if time.monotonic() >= deadline:
                                self.fail("Could not clean up harmless test descendants")
                            time.sleep(0.01)
        finally:
            processes.set_subreaper(previous)

    def test_report_write_failure_stops_launcher_and_descendant_listener(self):
        self.run_failure("write")

    def test_unwritable_final_report_cannot_abandon_processes(self):
        self.run_failure("persistent-write")

    def test_initial_identity_exception_still_cleans_up(self):
        self.run_failure("identity")

    def test_initial_keyboard_interrupt_still_cleans_up(self):
        self.run_failure("interrupt")

    def test_interrupt_after_launcher_exit_kills_term_ignoring_descendant(self):
        self.run_failure("cleanup-interrupt")

    def test_failed_discovery_cannot_be_reported_as_complete_cleanup(self):
        self.run_failure("discovery")

    def test_no_recorded_identity_still_terminates_direct_child(self):
        self.run_failure("unattested", descendant=False)

    def test_unattested_group_fallback_does_not_signal_another_session(self):
        first = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        try:
            errors = []
            with mock.patch.object(processes, "refresh_owned", side_effect=OSError("unavailable")):
                processes.signal_owned_or_child(first, {other.pid: processes.process_start_ticks(other.pid)},
                                          signal.SIGTERM, errors)
            first.wait(timeout=5)
            self.assertIsNone(other.poll())
            self.assertTrue(errors)
        finally:
            for child in (first, other):
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)

    def test_gc_initial_identity_failure_stops_diagnostic_child(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen, real_ticks = subprocess.Popen, processes.process_start_ticks
        children = []
        with tempfile.TemporaryDirectory(prefix="gc-launch-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            (out / "bin").mkdir()
            (out / "bin/jcmd").symlink_to(Path(sys.executable).resolve())
            runtime = {"jcmd_sha256": common.digest(out / "bin/jcmd")}

            def launch(_command, **kwargs):
                child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                children.append(child)
                return child

            fired = False

            def read_ticks(pid):
                nonlocal fired
                if not fired:
                    fired = True
                    raise OSError("injected diagnostic identity failure")
                return real_ticks(pid)

            try:
                with mock.patch.object(es7_api, "owned_java", return_value={"pid": os.getpid()}), \
                        mock.patch.object(es7.subprocess, "Popen", side_effect=launch), \
                        mock.patch.object(processes, "process_start_ticks", side_effect=read_ticks):
                    worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), out,
                                              {"pid": os.getpid()}, out, runtime, out, 1)
                    worker.start()
                    worker.request_sent()
                    report = worker.finish()
                self.assertEqual(report["status"], "failed")
                self.assertIn("injected diagnostic identity failure", report["error"])
                self.assertIs(report["owned_processes_exited"], True)
                self.assertTrue(children and all(child.poll() is not None for child in children))
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)

    def test_interrupted_gc_finish_terminates_and_joins_worker(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        started, children = threading.Event(), []
        worker = None
        with tempfile.TemporaryDirectory(prefix="gc-interrupt-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            (out / "bin").mkdir()
            (out / "bin/jcmd").symlink_to(Path(sys.executable).resolve())
            runtime = {"jcmd_sha256": common.digest(out / "bin/jcmd")}

            def launch(_command, **kwargs):
                child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                children.append(child)
                started.set()
                return child

            try:
                with mock.patch.object(es7_api, "owned_java", return_value={"pid": os.getpid()}), \
                        mock.patch.object(es7.subprocess, "Popen", side_effect=launch):
                    worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), out,
                                              {"pid": os.getpid()}, out, runtime, out, 60)
                    worker.start()
                    worker.request_sent()
                    self.assertTrue(started.wait(5))
                    real_wait = worker.finished.wait
                    interrupted = False

                    def interrupt_once(timeout=None):
                        nonlocal interrupted
                        if not interrupted:
                            interrupted = True
                            raise KeyboardInterrupt
                        return real_wait(timeout)

                    with mock.patch.object(worker.finished, "wait", side_effect=interrupt_once):
                        with self.assertRaises(KeyboardInterrupt):
                            worker.finish()
                self.assertTrue(interrupted)
                self.assertTrue(worker.finished.is_set())
                self.assertFalse(worker.thread.is_alive())
                self.assertTrue(children and all(child.poll() is not None for child in children))
            finally:
                if worker is not None:
                    worker.cancelled.set()
                    worker.gate.set()
                    worker._terminate_child()
                    worker.finished.wait(5)
                    worker.thread.join(5)
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)


class OutputDirectoryTests(unittest.TestCase):
    def test_existing_output_is_a_usage_error_and_preserves_files(self):
        common.SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="existing-output-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            sentinel = out / "keep.txt"
            sentinel.write_text("unchanged")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                es7.main(["--affected-jdk", "absent", "--fixed-jdk", "absent",
                          "--elasticsearch", "absent", "--output", str(out)])
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("must name a new directory", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertEqual(sentinel.read_text(), "unchanged")

    def test_missing_input_path_is_a_reported_failure(self):
        common.SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="missing-input-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary) / "result"
            absent = Path(temporary) / "absent"
            stdout = io.StringIO()
            with mock.patch.object(es7.sys, "platform", "linux"), \
                    mock.patch.object(es7.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(es7.os, "geteuid", return_value=1000, create=True), \
                    contextlib.redirect_stdout(stdout):
                code = es7.main(["--affected-jdk", str(absent), "--fixed-jdk", str(absent),
                                 "--elasticsearch", str(absent), "--output", str(out)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "failed")
            self.assertEqual(json.loads((out / "report.json").read_text())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
