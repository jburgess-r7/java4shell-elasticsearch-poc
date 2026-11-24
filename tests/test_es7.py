import importlib.util
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
spec = importlib.util.spec_from_file_location("run_es7", ROOT / "run_es7.py")
es7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es7)


def execution_result(**updates):
    fields = {
        "last_transaction": "{transaction=24, last_success_transaction=24, prior_unchanged_count=0, decoder_exception_kind=1}",
        "stage": "bytecode-marker", "success": "true",
        "bytecode_result": es7_api.MARKER_RETURN, "file_denied": "true",
        "manager_present_before": "true", "security_restored": "true",
        "security_readback": "true", "post_restore_denied": "true",
        "restored_lookup": "true", "restored_heap": "true",
    }
    fields.update(updates)
    return "{" + ", ".join(key + "=" + value for key, value in fields.items()) + "}"


CONTROL = ("{stage=unchanged, restored=false, no_write_proven=false, diagnostic={"
           "transaction=1, last_success_transaction=0, witness_length=20, decoder_exception_kind=1}}")


class ResultTests(unittest.TestCase):
    def test_full_execution_and_clean_controls(self):
        self.assertTrue(es7_api.validate_result(execution_result(), "affected", es7_api.MARKER_TEXT, False)["marker_present"])
        for role in ("disabled", "fixed"):
            self.assertFalse(es7_api.validate_result(CONTROL, role, None, False)["marker_present"])

    def test_rejects_partial_repair_and_wrong_marker(self):
        partial = execution_result(last_transaction="{transaction=24, last_success_transaction=23, prior_unchanged_count=0, decoder_exception_kind=1}")
        for value, marker in ((partial, es7_api.MARKER_TEXT), (execution_result(), b"wrong\n")):
            with self.assertRaises(RuntimeError):
                es7_api.validate_result(value, "affected", marker, False)

    def test_nested_success_cannot_replace_top_level_success(self):
        value = execution_result(success="false", error="{success=true}")
        with self.assertRaises(RuntimeError):
            es7_api.validate_result(value, "affected", es7_api.MARKER_TEXT, False)

    def test_control_cannot_create_a_marker(self):
        with self.assertRaises(RuntimeError):
            es7_api.validate_result(CONTROL, "fixed", es7_api.MARKER_TEXT, False)

    def test_file_denial_and_duplicate_keys_are_required(self):
        with self.assertRaises(RuntimeError):
            es7_api.validate_result(execution_result(), "affected", es7_api.MARKER_TEXT, True)
        with self.assertRaises(RuntimeError):
            es7_api.parse_java_map("{stage=unchanged, stage=bytecode-marker}")

    def test_retained_request_requires_its_own_class_and_return_token(self):
        name = "org.elasticsearch.painless.OwnedBase64M00002"
        token = "owned-bytecode-00000002"
        value = execution_result(bytecode_result=token, marker_class="class " + name)
        self.assertTrue(es7_api.validate_result(value, "affected", es7_api.MARKER_TEXT,
                                            False, token, name)["marker_present"])
        for wrong in (execution_result(bytecode_result=es7_api.MARKER_RETURN,
                                       marker_class="class " + name),
                      execution_result(bytecode_result=token,
                                       marker_class="class " + es7_api.MARKER_CLASS_NAME)):
            with self.assertRaises(RuntimeError):
                es7_api.validate_result(wrong, "affected", es7_api.MARKER_TEXT,
                                    False, token, name)


class ClusterSettleTests(unittest.TestCase):
    def test_retries_real_unready_response_shapes_and_records_success(self):
        endpoint = mock.Mock()
        endpoint.request.side_effect = [
            {"status": 408, "body": {"status": "red", "timed_out": True}},
            {"status": 503, "body": {"error": {"type": "master_not_discovered_exception"}}},
            {"status": 200, "body": {"status": "yellow", "timed_out": False}}]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(es7.time, "sleep"):
            out = Path(temporary)
            report = es7_api.wait_for_cluster(endpoint, out, 10)
            self.assertEqual(report["status"], "passed")
            self.assertEqual([x["response"]["status"] for x in report["attempts"]],
                             [408, 503, 200])
            self.assertEqual(json.loads((out / "cluster-settle.json").read_text()), report)
        for call in endpoint.request.call_args_list:
            self.assertEqual(call.args[0], "GET")
            self.assertTrue(call.args[1].startswith("/_cluster/health?"))
            self.assertLessEqual(call.kwargs["timeout"], 10)

    def test_socket_timeout_is_retried_but_an_unready_cluster_cannot_pass(self):
        endpoint = mock.Mock()
        endpoint.request.side_effect = [TimeoutError("slow owned node"),
                                        {"status": 200, "body": {"status": "green", "timed_out": False}}]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(es7.time, "sleep"):
            report = es7_api.wait_for_cluster(endpoint, Path(temporary), 10)
            self.assertIn("TimeoutError", report["attempts"][0]["error"])
            self.assertEqual(report["status"], "passed")
        endpoint.request.side_effect = None
        endpoint.request.return_value = {"status": 408, "body": {"timed_out": True}}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(es7.time, "monotonic", side_effect=[0, 0, 0, 2, 2]):
            out = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "did not settle"):
                es7_api.wait_for_cluster(endpoint, out, 1)
            saved = json.loads((out / "cluster-settle.json").read_text())
            self.assertEqual(saved["status"], "failed")
            self.assertEqual(len(saved["attempts"]), 1)

    def test_success_after_the_overall_deadline_cannot_pass(self):
        endpoint = mock.Mock()
        endpoint.request.return_value = {"status": 200, "body": {"status": "green", "timed_out": False}}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(es7.time, "monotonic", side_effect=[0, 0, 2]):
            out = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "did not settle"):
                es7_api.wait_for_cluster(endpoint, out, 1)
            saved = json.loads((out / "cluster-settle.json").read_text())
            self.assertEqual(saved["status"], "failed")
            self.assertEqual(saved["attempts"][0]["response"]["status"], 200)

    def test_rejects_authentication_errors_and_malformed_success(self):
        for reply in ({"status": 401, "body": {}},
                      {"status": 200, "body": {"status": "green"}},
                      {"status": 200, "body": {"status": "red", "timed_out": False}}):
            with self.subTest(reply=reply), tempfile.TemporaryDirectory() as temporary:
                endpoint = mock.Mock()
                endpoint.request.return_value = reply
                with self.assertRaises(RuntimeError):
                    es7_api.wait_for_cluster(endpoint, Path(temporary), 10)
                saved = json.loads((Path(temporary) / "cluster-settle.json").read_text())
                self.assertEqual(saved["status"], "failed")
                endpoint.request.assert_called_once()


@unittest.skipUnless(sys.platform == "linux", "Linux /proc ownership check")
class OwnershipTests(unittest.TestCase):
    def test_forked_java_argv_does_not_replace_the_recorded_process(self):
        conf = ROOT / ".validation-local" / "ownership-process-test"
        env = os.environ.copy()
        env["ES_PATH_CONF"] = str(conf)
        source = ("import os,time; child=os.fork();"
                  "\nif child==0: time.sleep(60); os._exit(0)"
                  "\nprint(child,flush=True); time.sleep(60)")
        child = subprocess.Popen([sys.executable, "-c", source,
                                  "org.elasticsearch.bootstrap.Elasticsearch"],
                                 env=env, stdout=subprocess.PIPE, text=True,
                                 start_new_session=True)
        try:
            grandchild = int(child.stdout.readline())
            self.assertIn(grandchild, processes.descendant_pids(child.pid))
            with self.assertRaises(es7_api.NotReady):
                es7_api.owned_java(child.pid, conf)
            identity = {"pid": child.pid,
                        "start_ticks": processes.process_start_ticks(child.pid),
                        "executable_sha256": common.digest(Path("/proc") / str(child.pid) / "exe")}
            self.assertEqual(es7_api.owned_java(child.pid, conf, identity)["pid"], child.pid)
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                es7_api.owned_java(child.pid, conf, dict(identity, start_ticks="wrong"))
        finally:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=5)
            child.stdout.close()

    def test_owned_child_listener(self):
        source = ("import socket,time; s=socket.socket(); "
                  "s.bind(('127.0.0.1',0)); s.listen(); "
                  "print(s.getsockname()[1],flush=True); time.sleep(60)")
        child = subprocess.Popen([sys.executable, "-c", source], stdout=subprocess.PIPE,
                                 text=True, start_new_session=True)
        try:
            port = int(child.stdout.readline())
            self.assertIn(child.pid, processes.descendant_pids(child.pid))
            self.assertTrue(es7_api.owns_listener(child.pid, port))
            self.assertFalse(es7_api.owns_listener(os.getpid(), port))
        finally:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=5)
            child.stdout.close()

    @unittest.skipUnless(socket.has_ipv6, "IPv6 sockets unavailable")
    def test_mapped_ipv6_listener_and_accepted_connection(self):
        try:
            with socket.socket(socket.AF_INET6) as check:
                check.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                check.bind(("::ffff:127.0.0.1", 0))
        except OSError as error:
            self.skipTest(str(error))
        source = ("import socket,time; s=socket.socket(socket.AF_INET6); "
                  "s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0); "
                  "s.bind(('::ffff:127.0.0.1',0)); s.listen(); "
                  "print(s.getsockname()[1],flush=True); c,a=s.accept(); "
                  "print('accepted',flush=True); time.sleep(60)")
        child = subprocess.Popen([sys.executable, "-c", source], stdout=subprocess.PIPE,
                                 text=True, start_new_session=True)
        try:
            port = int(child.stdout.readline())
            self.assertTrue(es7_api.owns_listener(child.pid, port))
            with socket.create_connection(("127.0.0.1", port)) as client:
                self.assertEqual(child.stdout.readline().strip(), "accepted")
                self.assertTrue(es7_api.owns_tcp_socket(child.pid, port, client.getsockname()[1]))
                self.assertFalse(es7_api.owns_tcp_socket(os.getpid(), port, client.getsockname()[1]))
        finally:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=5)
            child.stdout.close()

    def test_no_http_data_before_guard_accepts(self):
        received = []
        sent = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            def accept():
                connection, _ = listener.accept()
                with connection:
                    received.append(connection.recv(1024))
            thread = threading.Thread(target=accept)
            thread.start()
            def reject(_):
                raise RuntimeError("wrong owner")
            with self.assertRaisesRegex(RuntimeError, "wrong owner"):
                es7_api.request(listener.getsockname()[1], "POST", "/", {"payload": "test"},
                            guard=reject, on_sent=lambda: sent.append(True))
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(received, [b""])
            self.assertEqual(sent, [])

    def test_gc_command_cannot_start_after_server_identity_changes(self):
        common.SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="gc-owner-unit-", dir=common.SCRATCH) as temporary:
            with mock.patch.object(es7_api, "owned_java", side_effect=RuntimeError("identity changed")):
                with mock.patch.object(es7.subprocess, "Popen") as popen:
                    worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), Path("config"),
                                              {"pid": os.getpid()}, Path("jdk"), {},
                                              Path(temporary), 1)
                    worker.start()
                    worker.request_sent()
                    report = worker.finish()
                    self.assertEqual(report["status"], "failed")
                    self.assertIn("identity changed", report["error"])
                    popen.assert_not_called()

    def test_gc_worker_can_be_cancelled_before_http_send(self):
        common.SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="gc-cancel-unit-", dir=common.SCRATCH) as temporary:
            with mock.patch.object(es7_api, "owned_java") as owner:
                with mock.patch.object(es7.subprocess, "Popen") as popen:
                    worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), Path("config"),
                                              {"pid": os.getpid()}, Path("jdk"), {},
                                              Path(temporary), 1)
                    worker.start()
                    self.assertEqual(worker.finish()["status"], "not-started")
                    self.assertFalse(worker.thread.is_alive())
                    owner.assert_not_called()
                    popen.assert_not_called()

    def test_gc_timeout_stops_only_its_owned_diagnostic_process(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        children = []
        with tempfile.TemporaryDirectory(prefix="gc-timeout-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            (out / "bin").mkdir()
            (out / "bin/jcmd").symlink_to(Path(sys.executable).resolve())
            runtime = {"jcmd_sha256": common.digest(out / "bin/jcmd")}
            def start_owned_child(_command, **kwargs):
                child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                children.append(child)
                return child
            try:
                with mock.patch.object(es7_api, "owned_java", return_value={"pid": os.getpid()}):
                    with mock.patch.object(es7.subprocess, "Popen", side_effect=start_owned_child):
                        worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), Path("config"),
                                                  {"pid": os.getpid()}, out, runtime, out, 1)
                        worker.start()
                        worker.request_sent()
                        report = worker.finish()
                self.assertEqual(report["status"], "failed")
                self.assertIn("timed out", report["error"])
                self.assertTrue(report["forced_cleanup"])
                self.assertTrue(report["owned_processes_exited"])
                self.assertTrue(children and all(child.poll() is not None for child in children))
            finally:
                for child in children:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=5)

    def test_gc_success_text_does_not_hide_a_leftover_descendant(self):
        common.SCRATCH.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        previous = processes.set_subreaper(True)
        worker = None
        with tempfile.TemporaryDirectory(prefix="gc-descendant-unit-", dir=common.SCRATCH) as temporary:
            out = Path(temporary)
            (out / "bin").mkdir()
            (out / "bin/jcmd").symlink_to(Path(sys.executable).resolve())
            runtime = {"jcmd_sha256": common.digest(out / "bin/jcmd")}
            source = ("import os,time; child=os.fork();"
                      "\nif child==0: time.sleep(60); os._exit(0)"
                      "\nprint('Command executed successfully',flush=True); os._exit(0)")
            def start_owned_child(_command, **kwargs):
                return real_popen([sys.executable, "-c", source], **kwargs)
            try:
                with mock.patch.object(es7_api, "owned_java", return_value={"pid": os.getpid()}):
                    with mock.patch.object(es7.subprocess, "Popen", side_effect=start_owned_child):
                        worker = gc_support.GCInvocation(SimpleNamespace(pid=os.getpid()), Path("config"),
                                                  {"pid": os.getpid()}, out, runtime, out, 2)
                        worker.start()
                        worker.request_sent()
                        report = worker.finish()
                self.assertEqual(report["status"], "failed")
                self.assertTrue(report["forced_cleanup"])
                self.assertTrue(report["owned_processes_exited"])
            finally:
                if worker is not None:
                    worker._terminate_child()
                processes.set_subreaper(previous)

    def test_wrong_start_identity_cannot_signal_group(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        try:
            self.assertFalse(processes.signal_owned_group(child.pid, {child.pid: "incorrect"}, signal.SIGTERM))
            self.assertIsNone(child.poll())
            ticks = processes.process_start_ticks(child.pid)
            self.assertTrue(processes.signal_owned_group(child.pid, {child.pid: ticks}, signal.SIGTERM))
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)

    def test_subreaper_finds_child_after_launcher_exit(self):
        previous = processes.set_subreaper(True)
        source = ("import os,sys,time; pid=os.fork(); "
                  "\nif pid==0: time.sleep(60); os._exit(0)"
                  "\nprint(pid,flush=True); sys.stdin.read(1); os._exit(0)")
        child = subprocess.Popen([sys.executable, "-c", source], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, text=True, start_new_session=True)
        identities = {child.pid: processes.process_start_ticks(child.pid)}
        try:
            grandchild = int(child.stdout.readline())
            child.stdin.write("x")
            child.stdin.flush()
            child.wait(timeout=5)
            processes.refresh_owned(child.pid, identities)
            self.assertIn(grandchild, identities)
            self.assertTrue(processes.signal_owned_group(child.pid, identities, signal.SIGTERM))
            deadline = time.monotonic() + 5
            remaining = processes.remaining_owned(child.pid, identities, child.pid)
            while remaining and time.monotonic() < deadline:
                time.sleep(0.01)
                remaining = processes.remaining_owned(child.pid, identities, child.pid)
            self.assertEqual(remaining, {})
        finally:
            processes.refresh_owned(child.pid, identities)
            processes.signal_owned_group(child.pid, identities, signal.SIGKILL)
            child.wait(timeout=5)
            processes.remaining_owned(child.pid, identities, child.pid)
            child.stdin.close()
            child.stdout.close()
            processes.set_subreaper(previous)


if __name__ == "__main__":
    unittest.main()
