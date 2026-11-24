import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from java4shell import common, processes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("es7_signal_runner", ROOT / "run_es7.py")
es7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es7)


@unittest.skipUnless(sys.platform == "linux", "Linux process and signal lifecycle")
class SignalTests(unittest.TestCase):
    def wait_json(self, path, process, timeout=5):
        deadline = time.monotonic() + timeout
        while not path.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                self.fail("Harmless process did not report readiness")
            time.sleep(0.01)
        return json.loads(path.read_text())

    def assert_listener_closed(self, port):
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)

    def handoff_signal(self, signum):
        processes.require_pidfd_support()
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        children = []
        saved = {}
        previous_handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        previous_subreaper = processes.set_subreaper(True)
        identities = processes.OwnedProcesses()
        try:
            with tempfile.TemporaryDirectory(prefix="handoff-unit-", dir=common.SCRATCH) as temporary:
                out = Path(temporary)
                source = ("import json,os,signal,socket,time; from pathlib import Path; "
                          "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); child=os.fork();"
                          "\nif child==0: time.sleep(60); os._exit(0)"
                          "\nPath('ready.tmp').write_text(json.dumps({'pid':os.getpid(),'child':child,"
                          "'port':s.getsockname()[1],'blocked':[int(x) for x in "
                          "signal.pthread_sigmask(signal.SIG_BLOCK,set())]}));"
                          "Path('ready.tmp').replace('ready.json'); time.sleep(60)")

                def launch(_command, **kwargs):
                    child = real_popen([sys.executable, "-c", source], **kwargs)
                    children.append(child)
                    saved.update(self.wait_json(out / "ready.json", child))
                    for pid in (child.pid, saved["child"]):
                        identities.remember(pid, processes.process_start_ticks(pid), child.pid)
                    os.kill(os.getpid(), signum)
                    # The handler must not throw between real spawn and return.
                    saved["handoff_returned"] = True
                    return child

                args = SimpleNamespace(gc_stress=False, startup_timeout=1,
                                       request_timeout=1, gc_timeout=1)
                with mock.patch.object(es7, "prepare_case", return_value=(
                        out / "config", common.clean_environment(), ["harmless"], [])), \
                        mock.patch.object(es7.subprocess, "Popen", side_effect=launch):
                    with self.assertRaises(processes.StopRequested) as raised:
                        es7.run_case(out, out, out, "affected", 21, None, "unused", [], {}, args)
                self.assertEqual(raised.exception.signum, signum)
                self.assertTrue(saved["handoff_returned"])
                self.assertNotIn(int(signal.SIGINT), saved["blocked"])
                self.assertNotIn(int(signal.SIGTERM), saved["blocked"])
                report = json.loads((out / "report.json").read_text())
                self.assertEqual(report["launcher_pid"], children[0].pid)
                self.assertEqual(report["interruption"]["signal"], signum)
                self.assertIs(report["owned_processes_exited"], True)
                self.assertEqual(processes.remaining_owned(children[0].pid, identities, children[0].pid), {})
                self.assert_listener_closed(saved["port"])
        finally:
            identities.signal(signal.SIGKILL)
            for child in children:
                child.wait(timeout=5)
                processes.remaining_owned(child.pid, identities, child.pid)
            identities.close()
            processes.set_subreaper(previous_subreaper)
            for sig, handler in previous_handlers.items():
                self.assertEqual(signal.getsignal(sig), handler)

    def test_sigint_between_spawn_and_popen_return_is_deferred(self):
        self.handoff_signal(signal.SIGINT)

    def test_sigterm_between_spawn_and_popen_return_is_deferred(self):
        self.handoff_signal(signal.SIGTERM)

    def test_primary_write_failure_survives_repeated_cleanup_signals(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen, real_write, real_shutdown = subprocess.Popen, common.write_json, processes.shutdown_case
        children = []
        with tempfile.TemporaryDirectory(prefix="primary-error-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            fired = False

            def launch(_command, **kwargs):
                child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                children.append(child)
                return child

            def write_report(path, value):
                nonlocal fired
                if "launcher_pid" in value and not fired:
                    fired = True
                    raise OSError("primary injected write failure")
                real_write(path, value)

            def shutdown(*args):
                os.kill(os.getpid(), signal.SIGINT)
                os.kill(os.getpid(), signal.SIGTERM)
                return real_shutdown(*args)

            args = SimpleNamespace(gc_stress=False, startup_timeout=1,
                                   request_timeout=1, gc_timeout=1)
            try:
                with mock.patch.object(es7, "prepare_case", return_value=(
                        out / "config", common.clean_environment(), ["harmless"], [])), \
                        mock.patch.object(es7.subprocess, "Popen", side_effect=launch), \
                        mock.patch.object(common, "write_json", side_effect=write_report), \
                        mock.patch.object(processes, "shutdown_case", side_effect=shutdown):
                    with self.assertRaises(processes.StopRequested) as raised:
                        es7.run_case(out, out, out, "affected", 21, None, "unused", [], {}, args)
                self.assertEqual(raised.exception.signum, signal.SIGINT)
                report = json.loads((out / "report.json").read_text())
                self.assertIn("primary injected write failure", report["error"])
                self.assertEqual(report["interruption"]["signal"], signal.SIGINT)
                self.assertEqual(report["interruption"]["count"], 2)
                self.assertIs(report["owned_processes_exited"], True)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)

    def test_direct_sigterm_to_runner_cleans_its_separate_session(self):
        common.SCRATCH.mkdir(exist_ok=True)
        previous = processes.set_subreaper(True)
        identities = processes.OwnedProcesses()
        runner = None
        group = None
        try:
            with tempfile.TemporaryDirectory(prefix="sigterm-runner-unit-", dir=common.SCRATCH) as temporary:
                root = Path(temporary)
                out = root / "case"
                out.mkdir()
                node_source = ("import json,os,socket,time; from pathlib import Path; "
                               "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); "
                               "Path('ready.tmp').write_text(json.dumps({'pid':os.getpid(),"
                               "'port':s.getsockname()[1]})); Path('ready.tmp').replace('ready.json'); "
                               "time.sleep(60)")
                harness = root / "runner.py"
                harness.write_text(
                    "import sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
                    "from unittest.mock import patch\n"
                    "sys.path.insert(0," + repr(str(ROOT)) + ")\nimport run_es7 as es7; from java4shell import common, processes, es7 as es7_api, gc as gc_support, bytecode\n"
                    "out=Path(" + repr(str(out)) + ")\n"
                    "args=SimpleNamespace(gc_stress=False,startup_timeout=60,request_timeout=1,gc_timeout=1)\n"
                    "command=[sys.executable,'-c'," + repr(node_source) + "]\n"
                    "def run(_argv):\n return es7.run_case(out,out,out,'affected',21,None,'unused',[],{},args)\n"
                    "with patch.object(es7,'prepare_case',return_value=(out/'config',common.clean_environment(),command,[])), "
                    "patch.object(es7_api,'owned_java',side_effect=es7_api.NotReady('waiting')), "
                    "patch.object(es7,'_main',side_effect=run):\n raise SystemExit(es7.main([]))\n")
                runner = subprocess.Popen([sys.executable, "-B", str(harness)], cwd=ROOT,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                          start_new_session=True)
                ready = self.wait_json(out / "ready.json", runner)
                group = ready["pid"]
                self.assertIn(group, processes.descendant_pids(runner.pid))
                identities.remember(group, processes.process_start_ticks(group), group)
                os.kill(runner.pid, signal.SIGTERM)
                stdout, stderr = runner.communicate(timeout=10)
                self.assertEqual(runner.returncode, 143, (stdout, stderr))
                report = json.loads((out / "report.json").read_text())
                self.assertEqual(report["interruption"]["signal"], signal.SIGTERM)
                self.assertIs(report["owned_processes_exited"], True)
                self.assertEqual(processes.remaining_owned(group, identities, -1), {})
                self.assert_listener_closed(ready["port"])
        finally:
            identities.signal(signal.SIGKILL)
            if runner is not None:
                if runner.poll() is None:
                    runner.kill()
                runner.communicate(timeout=5)
            if group is not None:
                processes.remaining_owned(group, identities, -1)
            identities.close()
            processes.set_subreaper(previous)

    def test_bounded_preflight_command_owns_child_before_cancellation(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        children = []
        with tempfile.TemporaryDirectory(prefix="bounded-signal-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)

            def launch(command, **kwargs):
                child = real_popen(command, **kwargs)
                children.append(child)
                os.kill(os.getpid(), signal.SIGTERM)
                return child

            try:
                with mock.patch.object(es7.subprocess, "Popen", side_effect=launch):
                    with self.assertRaises(processes.StopRequested) as raised:
                        processes.run_bounded_command([sys.executable, "-c", "import time; time.sleep(60)"],
                                                out, 60, out / "process.json")
                self.assertEqual(raised.exception.signum, signal.SIGTERM)
                self.assertTrue(children and all(child.poll() is not None for child in children))
                self.assertIs(json.loads((out / "process.json").read_text())["owned_processes_exited"], True)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)

    def test_signal_during_final_reporting_cannot_return_success(self):
        def finish_reporting(_argv):
            os.kill(os.getpid(), signal.SIGTERM)
            return 0

        with mock.patch.object(es7, "_main", side_effect=finish_reporting), \
                mock.patch("builtins.print") as output:
            code = es7.main([])
        self.assertEqual(code, 143)
        self.assertEqual(json.loads(output.call_args.args[0])["interruption"]["signal"],
                         signal.SIGTERM)
        self.assertIsNone(processes.cancellation_pending())


if __name__ == "__main__":
    unittest.main()
