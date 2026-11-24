"""Optional genuine-JVM checks.

JAVA4SHELL_TEST_PROFILE selects 17 or 21 (default).
JAVA4SHELL_TEST_NATIVE_BUILD selects an in-repository candidate build.
JAVA4SHELL_TEST_KEEP_EVIDENCE=1 retains the owned helper reports.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from java4shell import common, processes, es7 as es7_api
from java4shell import command



ROOT = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get("JAVA4SHELL_TEST_PROFILE", "21")
JDK = ROOT / ".validation-local/runtimes" / ("temurin" + PROFILE)
BUILD = Path(os.environ.get("JAVA4SHELL_TEST_NATIVE_BUILD",
                            str(ROOT / ".validation-local/native-command"))).resolve()
AVAILABLE = (sys.platform == "linux" and PROFILE in {"17", "21"}
             and (JDK / "bin/javac").is_file() and (BUILD / "build.json").is_file())
MARKER_TEXT = "harmless owned marker\n"


DRIVER = r'''import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FilePermission;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.security.MessageDigest;
import java.security.Permission;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommandClassFixture {
    private static final String TEXT = "harmless owned marker\n";
    private static Method method(Class<?> type, String name, Class<?>... parameters) throws Exception {
        Method value = type.getDeclaredMethod(name, parameters);
        value.setAccessible(true);
        return value;
    }
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static void write(SeekableByteChannel channel, byte[] bytes) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0, "Write made no progress");
    }
    private static void filter(Path library, Path directory) throws Exception {
        Class<?> bridge = Class.forName("org.elasticsearch.painless.OwnedNativeCommand");
        try (SeekableByteChannel channel = (SeekableByteChannel)bridge
                .getMethod("openAnonymous", String.class).invoke(null, directory.toString())) {
            write(channel, Files.readAllBytes(library));
            method(bridge, "ensureLoaded", SeekableByteChannel.class).invoke(null, channel);
        }
        method(bridge, "installFilterForTest0").invoke(null);
    }
    private static String invoke(String type, String path) throws Exception {
        return (String)Class.forName(type).getMethod("run", String.class, String.class)
            .invoke(null, path, TEXT);
    }
    private static void audit(Path trace) throws Exception {
        Pattern identity = Pattern.compile("\"dev\":([0-9]+),\"ino\":([0-9]+)");
        Set<String> originals = new HashSet<>();
        for (String line : Files.readAllLines(trace)) {
            if (!line.contains("\"event\":\"anonymous_open\"") || !line.contains("\"result\":0,")) continue;
            Matcher match = identity.matcher(line);
            check(match.find(), "Anonymous event has no identity");
            originals.add(match.group(1) + ":" + match.group(2));
        }
        try (var entries = Files.list(Path.of("/proc/self/fd"))) {
            for (Path entry : entries.toList()) {
                try {
                    long dev = ((Number)Files.getAttribute(entry, "unix:dev")).longValue();
                    long ino = ((Number)Files.getAttribute(entry, "unix:ino")).longValue();
                    check(!originals.contains(Long.toUnsignedString(dev) + ":" + Long.toUnsignedString(ino)),
                          "Anonymous library descriptor remains open: " + entry);
                } catch (NoSuchFileException closed) {
                    // A JVM helper thread may close its unrelated descriptor.
                }
            }
        }
        System.out.println("FD_AUDIT:" + originals.size());
    }
    @SuppressWarnings("removal")
    private static final class ProbeManager extends SecurityManager {
        final String path;
        final boolean deny;
        int checks;
        ProbeManager(String path, boolean deny) { this.path = path; this.deny = deny; }
        @Override public void checkPermission(Permission permission) {}
        @Override public void checkWrite(String file) {
            if (file.equals(path)) {
                ++checks;
                if (deny) throw new AccessControlException("access denied (owned probe)",
                    new FilePermission(path, "write"));
            }
        }
    }
    @SuppressWarnings("removal")
    private static void probe(String type, String path, String mode) throws Exception {
        ProbeManager manager = mode.equals("absent") ? null : new ProbeManager(path, mode.equals("deny"));
        SecurityManager previous = System.getSecurityManager();
        check(previous == null, "Unexpected initial SecurityManager");
        if (manager != null) System.setSecurityManager(manager);
        Throwable failure = null;
        try { invoke(type, path); }
        catch (InvocationTargetException error) { failure = error.getCause(); }
        finally { if (manager != null) System.setSecurityManager(previous); }
        check(failure != null, "Permission probe unexpectedly returned");
        System.out.println("PROBE:" + failure.getClass().getName() + ":"
            + (manager == null ? 0 : manager.checks) + ":"
            + Base64.getEncoder().encodeToString(failure.toString().getBytes(StandardCharsets.UTF_8)));
    }
    public static void main(String[] args) throws Exception {
        if (args[0].equals("argv")) {
            String[] values = (String[])method(Class.forName(args[1]), "argv").invoke(null);
            ByteArrayOutputStream encoded = new ByteArrayOutputStream();
            try (DataOutputStream stream = new DataOutputStream(encoded)) {
                stream.writeInt(values.length);
                for (String value : values) {
                    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                    stream.writeInt(bytes.length); stream.write(bytes);
                }
            }
            System.out.println("ARGV:" + values.length + ":" + encoded.size() + ":"
                + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray())));
            return;
        }
        Path path = Path.of(args[2]);
        Path trace = Path.of(args[4]);
        if (args[0].equals("probe")) probe(args[1], args[2], args[5]);
        else {
            if (args[5].equals("filtered")) filter(Path.of(args[3]), path.getParent());
            System.out.println("RESULT:" + invoke(args[1], args[2]));
            if (args[0].equals("reuse"))
                System.out.println("RESULT:" + invoke(args[6], args[2] + "-second"));
        }
        audit(trace);
    }
}
'''


@unittest.skipUnless(AVAILABLE, "Requires this repository's pinned Linux JDK and native build")
class GeneratedCommandJavaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        processes.require_pidfd_support()
        pins = json.loads((ROOT / "elasticsearch/releases.json").read_text())
        cls.runtime = es7_api.runtime_identity(JDK, pins["runtimes"][PROFILE]["affected"])
        cls.manifest = json.loads((BUILD / "build.json").read_text())
        bridge = (BUILD / cls.manifest["bridge_class"]).read_bytes()
        cls.library_path = BUILD / cls.manifest["native_library"]
        library = cls.library_path.read_bytes()
        if (hashlib.sha256(bridge).hexdigest() != cls.manifest["bridge_class_sha256"]
                or hashlib.sha256(library).hexdigest() != cls.manifest["native_library_sha256"]):
            raise AssertionError("The native build differs from its manifest")
        compiler = Path(cls.manifest["compiler"]["command"][0])
        if not compiler.is_file():
            raise unittest.SkipTest("Requires the native build's C compiler for the owned syscall interceptor")
        cls.root = Path(tempfile.mkdtemp(prefix="command-java-test-", dir=ROOT / ".validation-local"))
        if os.environ.get("JAVA4SHELL_TEST_KEEP_EVIDENCE") != "1":
            cls.addClassCleanup(shutil.rmtree, cls.root)
        else:
            print("GeneratedCommandJavaTests evidence: " + str(cls.root), file=sys.stderr)
        cls.classes = cls.root / "classes"
        cls.classes.mkdir()
        common = {"build_id": cls.manifest["bridge_build_id"]}
        cls.client = command.render_request_class(bridge, library, ["/usr/bin/id", "-u"], 1,
            "71" * 12, create_marker=False, **common)
        cls.second = command.render_request_class(bridge, library, ["/usr/bin/id", "-u"], 1,
            "73" * 12, create_marker=False, **common)
        cls.comparison = command.render_request_class(bridge, library, ["/usr/bin/id", "-u"], 1,
            "74" * 12, **common)
        cls.argv = ["/usr/bin/printf"] + [letter * 32768 for letter in "xyz"]
        remainder = 131072 - sum(len(arg.encode()) + 1 for arg in cls.argv) - 1
        cls.argv.append("w" * remainder)
        cls.large = command.render_request_class(bridge, library, cls.argv, 1,
            "72" * 12, create_marker=False, **common)
        sources = []
        for marker in (cls.client, cls.second, cls.comparison, cls.large):
            source = cls.root / (marker["simple_name"] + ".java")
            source.write_text(marker["source"])
            sources.append(str(source))
        driver = cls.root / "CommandClassFixture.java"
        driver.write_text(DRIVER)
        result = processes.run_bounded_command([str(JDK / "bin/javac"), "--release", "17", "-g:none",
            "-d", str(cls.classes), *sources, str(driver)], cls.root, 180, cls.root / "compile.json")
        if result.returncode:
            raise AssertionError("Generated request classes did not compile: " + result.stderr)
        cls.swap_library = cls.root / "libcommand-file-swap.so"
        result = processes.run_bounded_command([str(compiler), "-std=gnu11", "-O2", "-Wall",
            "-Wextra", "-Werror", "-fPIC", "-shared", str(ROOT / "tests/command_file_swap.c"),
            "-ldl", "-o", str(cls.swap_library)], cls.root, 60, cls.root / "compile-swap.json")
        if result.returncode:
            raise AssertionError("Owned anonymous-file fixture did not compile: " + result.stderr)
        (cls.root / "inputs.json").write_text(json.dumps({
            "profile": PROFILE, "runtime": cls.runtime,
            "build_manifest_sha256": hashlib.sha256((BUILD / "build.json").read_bytes()).hexdigest(),
            "native_library_sha256": cls.manifest["native_library_sha256"],
            "bridge_class_sha256": cls.manifest["bridge_class_sha256"],
            "request_source_sha256": {m["simple_name"]: m["source_sha256"]
                for m in (cls.client, cls.second, cls.comparison, cls.large)},
            "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "interceptor_source_sha256": hashlib.sha256((ROOT / "tests/command_file_swap.c").read_bytes()).hexdigest(),
            "interceptor_sha256": hashlib.sha256(cls.swap_library.read_bytes()).hexdigest(),
        }, indent=2) + "\n")

    def case(self, name):
        case = self.root / name
        case.mkdir()
        directory = case / "request"
        directory.mkdir()
        trace = case / "trace.jsonl"
        trace.touch()
        return case, directory / "proof", trace

    def invoke(self, case, marker, path, trace, *, action="invoke", filtered=False,
               limited=False, environment=None, permission_mode=None, second=None):
        env = {"LD_PRELOAD": str(self.swap_library), "JAVA4SHELL_TRACE_PATH": str(trace),
               "JAVA4SHELL_ANON_DIRECTORY": str(path.parent),
               "JAVA4SHELL_SWAP_PATH": str(path) + ".native.so"}
        env.update(environment or {})
        arguments = [action, marker["binary_name"], str(path), str(self.library_path),
                     str(trace), permission_mode or ("filtered" if filtered else "plain")]
        if second is not None:
            arguments.append(second["binary_name"])
        invocation = [str(JDK / "bin/java"), "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash",
            "-XX:ErrorFile=" + str(case / "hs_err_pid%p.log")]
        if action == "probe":
            invocation.append("-Djava.security.manager=allow")
        invocation += ["-cp", os.pathsep.join((str(self.classes), str(BUILD / "classes"))),
                       "CommandClassFixture", *arguments]
        wrapper = ("import json,os,resource,signal,sys; "
                   "os.environ.update(json.loads(sys.argv[1])); ")
        if limited:
            wrapper += ("signal.signal(signal.SIGXFSZ,signal.SIG_IGN); "
                        "resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096)); ")
        wrapper += "os.execv(sys.argv[2],sys.argv[2:])"
        result = processes.run_bounded_command([sys.executable, "-c", wrapper, json.dumps(env), *invocation],
                                         case, 30, case / "process.json")
        (case / "stdout").write_text(result.stdout)
        (case / "stderr").write_text(result.stderr)
        report = json.loads((case / "process.json").read_text())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(report["owned_processes_exited"])
        self.assertFalse(report["forced_cleanup"])
        self.assertEqual(report["remaining_owned_pids"], [])
        self.assertIsNone(processes.process_start_ticks(report["launcher_pid"]))
        if action == "probe":
            self.assertTrue(all(line.startswith("WARNING:") for line in result.stderr.splitlines()),
                            result.stderr)
        else:
            self.assertEqual(result.stderr, "")
        events = [json.loads(line) for line in trace.read_text().splitlines()]
        opened = [row for row in events if row["event"] == "anonymous_open"]
        for row in opened:
            self.assertEqual(row["result"], 0)
            self.assertTrue(row["stat"])
            self.assertEqual(row["nlink"], 0)
            self.assertEqual(row["flags"] & (os.O_TMPFILE | os.O_EXCL), os.O_TMPFILE | os.O_EXCL)
        self.assertFalse([row for row in events if row["event"].startswith("named_")], events)
        lines = result.stdout.splitlines()
        identity_count = len({(row["dev"], row["ino"]) for row in opened})
        self.assertEqual(lines[-1], "FD_AUDIT:" + str(identity_count))
        decoded = []
        expected = [marker] + ([second] if second is not None else [])
        for line, selected in zip([line for line in lines if line.startswith("RESULT:")], expected):
            document = command.decode_result(line.removeprefix("RESULT:"), selected["marker_return"])
            decoded.append(document)
            for key in ("supervisor_pid", "child_pid"):
                pid = document.get("metadata", {}).get(key)
                if pid is not None and pid > 0:
                    self.assertIsNone(processes.process_start_ticks(pid), str(pid))
        return decoded, events, lines

    def assert_command(self, result, *, marker_created=False, filtered=True):
        self.assertEqual(result["state"], "completed")
        self.assertTrue(result["library_anonymous"])
        self.assertTrue(result["library_descriptor_closed"])
        self.assertEqual(result["marker_file_created"], marker_created)
        self.assertEqual(result["stdout"], (str(os.getuid()) + "\n").encode())
        self.assertEqual(result["stderr"], b"")
        metadata = result["metadata"]
        self.assertEqual(metadata["status"], "completed")
        self.assertEqual(metadata["exit_code"], 0)
        self.assertTrue(metadata["cleanup_complete"])
        if filtered:
            self.assertEqual(metadata["no_new_privs"], 1)
            self.assertEqual(metadata["seccomp"], 2)

    def test_markerless_filtered_execution_and_same_jvm_reuse(self):
        case, path, trace = self.case("reuse")
        results, events, _ = self.invoke(case, self.client, path, trace, action="reuse",
                                         filtered=True, second=self.second)
        self.assertEqual(len(results), 2)
        for result in results:
            self.assert_command(result)
        self.assertEqual(len([row for row in events if row["event"] == "anonymous_open"]), 3)
        self.assertEqual(list(path.parent.iterdir()), [])

    def test_controlled_comparison_retains_exact_create_new_marker(self):
        case, path, trace = self.case("comparison")
        results, events, _ = self.invoke(case, self.comparison, path, trace, filtered=True)
        self.assertEqual(len(results), 1)
        self.assert_command(results[0], marker_created=True)
        self.assertEqual(path.read_text(), MARKER_TEXT)
        self.assertEqual(list(path.parent.iterdir()), [path])
        self.assertEqual(len([row for row in events if row["event"] == "anonymous_open"]), 2)

    def test_controlled_comparison_refuses_an_existing_marker_before_preparation(self):
        case, path, trace = self.case("existing-comparison")
        path.write_bytes(b"unrelated existing marker\n")
        identity = (path.stat().st_dev, path.stat().st_ino)
        results, events, lines = self.invoke(case, self.comparison, path, trace,
                                             action="probe", permission_mode="absent")
        self.assertEqual(results, [])
        self.assertEqual(events, [])
        self.assertTrue(any(line.startswith("PROBE:java.nio.file.FileAlreadyExistsException:0:")
                            for line in lines))
        self.assertEqual(path.read_bytes(), b"unrelated existing marker\n")
        self.assertEqual((path.stat().st_dev, path.stat().st_ino), identity)
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_markerless_execution_preserves_existing_marker_and_library_fifo(self):
        import stat
        case, path, trace = self.case("existing-client-paths")
        path.write_bytes(b"unrelated existing marker\n")
        fifo = Path(str(path) + ".native.so")
        os.mkfifo(fifo)
        identity = (fifo.stat().st_dev, fifo.stat().st_ino)
        results, _, _ = self.invoke(case, self.client, path, trace, filtered=True)
        self.assertEqual(len(results), 1)
        self.assert_command(results[0])
        self.assertEqual(path.read_bytes(), b"unrelated existing marker\n")
        self.assertEqual((fifo.stat().st_dev, fifo.stat().st_ino), identity)
        self.assertTrue(stat.S_ISFIFO(fifo.stat().st_mode))
        self.assertEqual(set(path.parent.iterdir()), {path, fifo})

    def test_real_partial_library_write_closes_its_anonymous_descriptor(self):
        case, path, trace = self.case("partial")
        results, events, _ = self.invoke(case, self.client, path, trace, limited=True)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["state"], "error")
        self.assertIn("File too large", result["error"])
        self.assertTrue(result["library_anonymous"])
        self.assertTrue(result["library_descriptor_closed"])
        self.assertFalse(result["marker_file_created"])
        self.assertEqual(len([row for row in events if row["event"] == "anonymous_open"]), 1)
        self.assertEqual(list(path.parent.iterdir()), [])

    def test_real_loader_failure_closes_its_anonymous_descriptor(self):
        case, path, trace = self.case("load-failure")
        results, events, _ = self.invoke(case, self.client, path, trace,
                                         environment={"JAVA4SHELL_LOAD_FAILURE": "1"})
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["state"], "error")
        self.assertIn("UnsatisfiedLinkError", result["error"])
        self.assertTrue(result["library_anonymous"])
        self.assertTrue(result["library_descriptor_closed"])
        self.assertFalse(result["marker_file_created"])
        self.assertTrue([row for row in events if row["event"] == "anonymous_load"])
        self.assertEqual(list(path.parent.iterdir()), [])

    def test_atomic_replacement_and_fifo_sentinels_are_never_opened_or_unlinked(self):
        for stage, kind in (("open", "regular"), ("unlink", "regular"), ("read-open", "fifo")):
            with self.subTest(stage=stage, kind=kind):
                case, path, trace = self.case("sentinel-" + stage)
                replacement = path.parent / "replacement"
                witness = path.parent / "replacement-witness"
                if kind == "fifo":
                    os.mkfifo(replacement)
                else:
                    replacement.write_bytes(b"unrelated owned sentinel\n")
                os.link(replacement, witness)
                identity = (replacement.stat().st_dev, replacement.stat().st_ino)
                results, _, _ = self.invoke(case, self.client, path, trace, filtered=True,
                    environment={"JAVA4SHELL_SWAP_STAGE": stage,
                                 "JAVA4SHELL_SWAP_REPLACEMENT": str(replacement)})
                self.assertEqual(len(results), 1)
                self.assert_command(results[0])
                self.assertEqual((replacement.stat().st_dev, replacement.stat().st_ino), identity)
                self.assertEqual((witness.stat().st_dev, witness.stat().st_ino), identity)
                self.assertEqual(witness.stat().st_nlink, 2)
                if kind == "fifo":
                    import stat
                    self.assertTrue(stat.S_ISFIFO(replacement.stat().st_mode))
                else:
                    self.assertEqual(replacement.read_bytes(), b"unrelated owned sentinel\n")
                self.assertEqual(set(path.parent.iterdir()), {replacement, witness})

    def test_denied_and_unexpectedly_allowed_probes_have_no_file_side_effects(self):
        for name, marker, suffix, permission, expected, checks in (
                ("denied-client", self.client, ".denied", "deny", "java.security.AccessControlException", 1),
                ("permissive-probe", self.client, ".denied", "allow", "java.lang.IllegalStateException", 1),
                ("missing-manager", self.client, ".denied", "absent", "java.lang.IllegalStateException", 0),
                ("guarded-client", self.client, "", "allow", "java.lang.IllegalStateException", None),
                ("denied-comparison", self.comparison, ".denied", "deny",
                 "java.security.AccessControlException", 1)):
            with self.subTest(name=name):
                case, path, trace = self.case(name)
                path = Path(str(path) + suffix)
                results, events, lines = self.invoke(case, marker, path, trace, action="probe",
                                                     permission_mode=permission)
                self.assertEqual(results, [])
                self.assertEqual(events, [])
                probe = [line for line in lines if line.startswith("PROBE:")]
                self.assertEqual(len(probe), 1)
                parts = probe[0].split(":", 3)
                self.assertEqual(parts[1], expected)
                if checks is not None:
                    self.assertEqual(int(parts[2]), checks)
                self.assertEqual(list(path.parent.iterdir()), [])

    def test_maximum_advertised_argv_compiles_and_round_trips(self):
        encoded = command._encoded_argv(self.argv)
        self.assertEqual(sum(len(arg.encode()) + 1 for arg in self.argv), 131072)
        result = processes.run_bounded_command([str(JDK / "bin/java"), "-cp", str(self.classes),
            "CommandClassFixture", "argv", self.large["binary_name"]],
            self.root, 30, self.root / "argv-process.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.strip(), "ARGV:" + str(len(self.argv)) + ":"
                         + str(len(encoded)) + ":" + hashlib.sha256(encoded).hexdigest())


if __name__ == "__main__":
    unittest.main()
