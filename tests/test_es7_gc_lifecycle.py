import importlib.util
import json
import os
from pathlib import Path
import signal
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
spec = importlib.util.spec_from_file_location("es7_gc_lifecycle_runner", ROOT / "run_es7.py")
es7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es7)


@unittest.skipUnless(sys.platform == "linux", "Linux signals and owned diagnostic processes")
class GcLifecycleTests(unittest.TestCase):
    def run_request_failure(self, mode):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen, real_utc, real_gc = subprocess.Popen, common.utc_now, gc_support.GCInvocation
        children, workers = [], []
        started = threading.Event()
        phase = {"returned": False, "timestamp_fault": False, "second_signal": False}
        with tempfile.TemporaryDirectory(prefix="gc-request-life-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            (out / "bin").mkdir()
            (out / "bin/jcmd").symlink_to(Path(sys.executable).resolve())
            runtime = {"jcmd_sha256": common.digest(out / "bin/jcmd")}

            def launch(_command, **kwargs):
                child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                children.append(child)
                started.set()
                return child

            def make_collector(*args, **kwargs):
                worker = real_gc(*args, **kwargs)
                workers.append(worker)
                if mode == "signal":
                    terminate = worker._terminate_child

                    def signal_during_cleanup():
                        if not phase["second_signal"]:
                            phase["second_signal"] = True
                            os.kill(os.getpid(), signal.SIGTERM)
                        return terminate()

                    worker._terminate_child = signal_during_cleanup
                return worker

            def timestamp():
                if (threading.current_thread() is threading.main_thread() and
                        phase["returned"] and not phase["timestamp_fault"]):
                    phase["timestamp_fault"] = True
                    if mode == "signal":
                        os.kill(os.getpid(), signal.SIGINT)
                    else:
                        raise OSError("injected request timestamp failure")
                return real_utc()

            class Endpoint:
                def execute(self, _source, _params, _timeout, *, on_sent):
                    on_sent()
                    if not started.wait(5):
                        raise RuntimeError("Harmless diagnostic child did not start")
                    phase["returned"] = True
                    if mode == "primary-and-timing":
                        raise RuntimeError("primary trigger failure")
                    return {"status": 200, "body": {"result": "unused"}}

            marker = {"marker_return": "unused", "bytes": b"unused", "binary_name": "Unused",
                      "sha256": "unused"}
            args = SimpleNamespace(requests_per_node=2, gc_stress=True,
                                   gc_timeout=60, request_timeout=60)
            expected = processes.StopRequested if mode == "signal" else (
                RuntimeError if mode == "primary-and-timing" else OSError)
            state = None
            try:
                with processes.managed_signals() as state, \
                        mock.patch.object(gc_support, "GCInvocation", side_effect=make_collector), \
                        mock.patch.object(es7_api, "owned_java", return_value={"pid": os.getpid()}), \
                        mock.patch.object(es7, "gc_counters", return_value={"node_id": "unused"}), \
                        mock.patch.object(es7.subprocess, "Popen", side_effect=launch), \
                        mock.patch.object(common, "utc_now", side_effect=timestamp):
                    began = time.monotonic()
                    with self.assertRaises(expected) as raised:
                        es7.exercise_request(out, out, Endpoint(), SimpleNamespace(pid=os.getpid()),
                                             out, {"pid": os.getpid(), "start_ticks": "unused"},
                                             out, runtime, "affected", "unused", marker, 2, args)
                    self.assertLess(time.monotonic() - began, 8)
                    if mode == "signal":
                        self.assertEqual(raised.exception.signum, signal.SIGINT)
                        self.assertEqual(state.first_signum, signal.SIGINT)
                        self.assertEqual(state.count, 2)
                    elif mode == "primary-and-timing":
                        self.assertIn("primary trigger failure", str(raised.exception))
                self.assertTrue(phase["timestamp_fault"])
                self.assertEqual(len(workers), 1)
                self.assertTrue(workers[0].finished.is_set())
                self.assertFalse(workers[0].thread.is_alive())
                self.assertTrue(children and all(child.poll() is not None for child in children))
                report = json.loads((out / "request.json").read_text())
                self.assertIn("gc_command", report)
                self.assertIs(report["gc_command"]["owned_processes_exited"], True)
                if mode == "signal":
                    self.assertEqual(report["status"], "interrupted")
                    self.assertEqual(report["interruption"]["name"], "SIGINT")
                    self.assertEqual(report["interruption"]["count"], 2)
                    self.assertIn("StopRequested", report["gc_cleanup_error"])
                else:
                    self.assertEqual(report["status"], "failed")
                    self.assertIn("injected request timestamp failure", report["timing_error"])
                    if mode == "primary-and-timing":
                        self.assertIn("primary trigger failure", report["trigger_error"])
                        self.assertIn("primary trigger failure", report["error"])
            finally:
                for worker in workers:
                    worker.cancel()
                    worker._terminate_child()
                    worker.finished.wait(5)
                    if worker.thread.ident is not None:
                        worker.thread.join(5)
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)

    def test_sigint_during_timestamp_and_sigterm_during_cleanup_finalize_gc(self):
        self.run_request_failure("signal")

    def test_timestamp_exception_cannot_skip_gc_finalization(self):
        self.run_request_failure("timing")

    def test_primary_trigger_failure_survives_timestamp_failure(self):
        self.run_request_failure("primary-and-timing")

    def test_pending_sigterm_stops_gc_without_waiting_for_its_timeout(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        children, started = [], threading.Event()
        worker = None
        with tempfile.TemporaryDirectory(prefix="gc-cancel-life-unit-", dir=common.SCRATCH) as temporary:
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
                with processes.managed_signals(), \
                        mock.patch.object(es7_api, "owned_java", return_value={"pid": os.getpid()}), \
                        mock.patch.object(es7.subprocess, "Popen", side_effect=launch):
                    worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), out,
                                              {"pid": os.getpid()}, out, runtime, out, 60)
                    worker.start()
                    worker.request_sent()
                    self.assertTrue(started.wait(5))
                    os.kill(os.getpid(), signal.SIGTERM)
                    began = time.monotonic()
                    with self.assertRaises(processes.StopRequested) as raised:
                        worker.finish()
                    self.assertEqual(raised.exception.signum, signal.SIGTERM)
                    self.assertLess(time.monotonic() - began, 8)
                    with self.assertRaises(processes.StopRequested) as repeated:
                        worker.finish()
                    self.assertEqual(repeated.exception.signum, signal.SIGTERM)
                self.assertTrue(worker.finished.is_set())
                self.assertFalse(worker.thread.is_alive())
                self.assertTrue(worker._identities_closed)
                self.assertTrue(children and all(child.poll() is not None for child in children))
            finally:
                if worker is not None:
                    worker.cancel()
                    worker._terminate_child()
                    worker.finished.wait(5)
                    if worker.thread.ident is not None:
                        worker.thread.join(5)
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
