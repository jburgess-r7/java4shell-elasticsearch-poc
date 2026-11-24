"""Optional descriptor-bound JNI loader regressions on the pinned Linux JDKs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from java4shell import processes, es7 as es7_api



ROOT = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get("JAVA4SHELL_TEST_PROFILE", "21")
JDK = ROOT / ".validation-local/runtimes" / ("temurin" + PROFILE)
BUILD = Path(os.environ.get("JAVA4SHELL_TEST_NATIVE_BUILD",
                            str(ROOT / ".validation-local/native-command"))).resolve()
AVAILABLE = (sys.platform == "linux" and PROFILE in {"17", "21"}
             and BUILD.is_relative_to(ROOT) and (JDK / "bin/javac").is_file()
             and (BUILD / "build.json").is_file())


DRIVER = r'''import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class NativeLibraryFixture {
    private static native void installFilter0();
    private static native boolean checkFilter0();
    private static final String NAME = "org.elasticsearch.painless.OwnedNativeCommand";
    private static final class Isolated extends ClassLoader {
        Isolated() { super(NativeLibraryFixture.class.getClassLoader()); }
        Class<?> bridge(byte[] bytes) { return defineClass(NAME, bytes, 0, bytes.length); }
    }
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static Method method(Class<?> type, String name, Class<?>... parameters) throws Exception {
        Method value = type.getDeclaredMethod(name, parameters);
        value.setAccessible(true);
        return value;
    }
    private static Object call(Method method, Object... arguments) throws Throwable {
        try { return method.invoke(null, arguments); }
        catch (InvocationTargetException error) { throw error.getCause(); }
    }
    private static SeekableByteChannel open(Class<?> bridge, Path directory) throws Throwable {
        return (SeekableByteChannel)call(bridge.getMethod("openAnonymous", String.class), directory.toString());
    }
    private static void write(SeekableByteChannel channel, byte[] bytes) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0, "Write made no progress");
    }
    private static long[] identity(Class<?> bridge, SeekableByteChannel channel) throws Throwable {
        int fd = (Integer)call(method(bridge, "descriptor", SeekableByteChannel.class), channel);
        Path path = Path.of("/proc/self/fd/" + fd);
        check(((Number)Files.getAttribute(path, "unix:nlink")).longValue() == 0, "Anonymous inode has a name");
        return new long[] {fd, ((Number)Files.getAttribute(path, "unix:dev")).longValue(),
                              ((Number)Files.getAttribute(path, "unix:ino")).longValue()};
    }
    private static String name(Class<?> bridge, long[] identity) throws Throwable {
        String name = (String)call(method(bridge, "loadName", long[].class), (Object)identity);
        check(Files.isSameFile(Path.of(name), Path.of("/proc/self/fd/" + identity[0])),
              "Raw load alias resolves to another file");
        return name;
    }
    private static byte[][] run(Class<?> bridge, SeekableByteChannel channel) throws Throwable {
        return (byte[][])call(bridge.getMethod("run", SeekableByteChannel.class, String[].class, int.class),
            channel, new String[] {"/usr/bin/id", "-u"}, 5);
    }
    private static void audit(long[]... identities) throws Exception {
        Set<String> originals = new HashSet<>();
        for (long[] id : identities) if (id != null) originals.add(id[1] + ":" + id[2]);
        try (var entries = Files.list(Path.of("/proc/self/fd"))) {
            for (Path entry : entries.toList()) {
                try {
                    String id = Files.getAttribute(entry, "unix:dev") + ":" + Files.getAttribute(entry, "unix:ino");
                    check(!originals.contains(id), "Owned anonymous descriptor remains open: " + entry);
                } catch (NoSuchFileException closed) {
                    // An unrelated JVM helper can close its descriptor.
                }
            }
        }
    }
    public static void main(String[] args) throws Throwable {
        byte[] bridgeBytes = Files.readAllBytes(Path.of(args[0]));
        byte[] library = Files.readAllBytes(Path.of(args[1]));
        byte[] alternate = Files.readAllBytes(Path.of(args[2]));
        Path directory = Path.of(args[3]);
        String mode = args[4], expected = args[5] + "\n";
        System.load(args[2]);
        installFilter0();
        check(checkFilter0(), "Independent syscall filter is inactive");
        Class<?> first = new Isolated().bridge(bridgeBytes);
        Class<?> second = new Isolated().bridge(bridgeBytes);
        call(first.getMethod("buildId"));
        call(second.getMethod("buildId"));
        long[] firstId = null, secondId = null;
        if (mode.startsWith("poison")) {
            try (SeekableByteChannel channel = open(first, directory)) {
                firstId = identity(first, channel);
                write(channel, mode.equals("poison-elf") ? new byte[] {1, 2, 3, 4} : library);
                Throwable failure = null;
                try { call(method(first, "ensureLoaded", SeekableByteChannel.class), channel); }
                catch (Throwable error) { failure = error; }
                check(mode.equals("poison-elf") ? failure instanceof UnsatisfiedLinkError
                    : failure instanceof SecurityException && failure.getMessage().contains("changed during loading"),
                    "First load did not fail at the expected boundary: " + failure);
            }
            try (SeekableByteChannel channel = open(first, directory)) {
                secondId = identity(first, channel);
                write(channel, library);
                Throwable failure = null;
                try { call(method(first, "ensureLoaded", SeekableByteChannel.class), channel); }
                catch (Throwable error) { failure = error; }
                check(failure instanceof SecurityException
                    && failure.getMessage().contains("Previous native library load did not complete verification"),
                    "Unverified first load was retried: " + failure);
            }
            audit(firstId, secondId);
            System.out.println("{\"mode\":\"" + mode + "\",\"poisoned\":true,\"fd_audit\":true}");
        } else {
            String firstName;
            byte[][] one;
            try (SeekableByteChannel channel = open(first, directory)) {
                firstId = identity(first, channel);
                firstName = name(first, firstId);
                write(channel, library);
                one = run(first, channel);
                check(new String(one[1], StandardCharsets.UTF_8).equals(expected) && one[2].length == 0,
                      "The genuine command returned unexpected streams");
            }
            if (mode.equals("cache")) {
                try (SeekableByteChannel channel = open(second, directory)) {
                    secondId = identity(second, channel);
                    check(firstId[0] == secondId[0], "Fixture did not reuse the descriptor number");
                    check(firstId[1] != secondId[1] || firstId[2] != secondId[2], "Fixture reused the inode");
                    check(!firstName.equals(name(second, secondId)), "Different inodes share a JNI cache key");
                    write(channel, alternate);
                    byte[][] two = run(second, channel);
                    check(new String(two[1], StandardCharsets.UTF_8).equals("different-image\n")
                          && two[2].length == 0, "The second JNI image was not actually loaded");
                }
            }
            audit(firstId, secondId);
            System.out.println("{\"mode\":\"" + mode + "\",\"first_identity\":" + Arrays.toString(firstId)
                + ",\"second_identity\":" + Arrays.toString(secondId) + ",\"fd_audit\":true,\"metadata\":"
                + new String(one[0], StandardCharsets.UTF_8) + "}");
        }
        try (var entries = Files.list(directory)) { check(entries.findAny().isEmpty(), "Test directory is not empty"); }
    }
}
'''


@unittest.skipUnless(AVAILABLE, "Requires this repository's pinned Linux JDK and native build")
class NativeLibraryJavaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        processes.require_pidfd_support()
        pins = json.loads((ROOT / "elasticsearch/releases.json").read_text())
        cls.runtime = es7_api.runtime_identity(JDK, pins["runtimes"][PROFILE]["affected"])
        cls.manifest = json.loads((BUILD / "build.json").read_text())
        if "SeekableByteChannel" not in cls.manifest.get("api", ""):
            raise unittest.SkipTest("Requires a native build with the anonymous-channel API")
        cls.bridge = BUILD / cls.manifest["bridge_class"]
        cls.library = BUILD / cls.manifest["native_library"]
        for path, key in ((cls.bridge, "bridge_class_sha256"), (cls.library, "native_library_sha256")):
            if hashlib.sha256(path.read_bytes()).hexdigest() != cls.manifest[key]:
                raise AssertionError("The native build differs from its manifest")
        compiler = Path(cls.manifest["compiler"]["command"][0])
        if not compiler.is_file():
            raise unittest.SkipTest("Requires the native build's C compiler")
        cls.root = Path(tempfile.mkdtemp(prefix="native-library-test-", dir=ROOT / ".validation-local"))
        if os.environ.get("JAVA4SHELL_TEST_KEEP_EVIDENCE") != "1":
            cls.addClassCleanup(shutil.rmtree, cls.root)
        else:
            print("NativeLibraryJavaTests evidence: " + str(cls.root), file=sys.stderr)
        cls.classes = cls.root / "classes"
        cls.classes.mkdir()
        driver = cls.root / "NativeLibraryFixture.java"
        driver.write_text(DRIVER)
        result = processes.run_bounded_command([str(JDK / "bin/javac"), "--release", "17", "-g:none",
            "-d", str(cls.classes), str(driver)], cls.root, 120, cls.root / "compile.json")
        if result.returncode:
            raise AssertionError("Native library fixture did not compile: " + result.stderr)
        cls.fixture = cls.root / "libnative-library-fixture.so"
        result = processes.run_bounded_command([str(compiler), "-std=gnu11", "-O2", "-Wall", "-Wextra",
            "-Werror", "-fPIC", "-shared", "-I" + str(JDK / "include"),
            "-I" + str(JDK / "include/linux"), str(ROOT / "tests/native_library_fixture.c"),
            "-ldl", "-o", str(cls.fixture)], cls.root, 60, cls.root / "compile-fixture.json")
        if result.returncode:
            raise AssertionError("Native JNI fixture did not compile: " + result.stderr)
        (cls.root / "inputs.json").write_text(json.dumps({
            "profile": PROFILE, "runtime": cls.runtime,
            "build_manifest_sha256": hashlib.sha256((BUILD / "build.json").read_bytes()).hexdigest(),
            "bridge_class_sha256": cls.manifest["bridge_class_sha256"],
            "native_library_sha256": cls.manifest["native_library_sha256"],
            "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "fixture_source_sha256": hashlib.sha256((ROOT / "tests/native_library_fixture.c").read_bytes()).hexdigest(),
            "fixture_sha256": hashlib.sha256(cls.fixture.read_bytes()).hexdigest(),
        }, indent=2) + "\n")

    def bounded(self, case, arguments, *, environment=None, success=True):
        wrapper = ("import json,os,sys; os.environ.update(json.loads(sys.argv[1])); "
                   "os.execv(sys.argv[2],sys.argv[2:])")
        command = [str(JDK / "bin/java"), "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash",
            "-XX:ErrorFile=" + str(case / "hs_err_pid%p.log"), *arguments]
        result = processes.run_bounded_command([sys.executable, "-c", wrapper,
            json.dumps(environment or {}), *command], case, 30, case / "process.json")
        (case / "stdout").write_text(result.stdout)
        (case / "stderr").write_text(result.stderr)
        report = json.loads((case / "process.json").read_text())
        self.assertEqual(result.returncode == 0, success, result.stderr)
        self.assertTrue(report["owned_processes_exited"])
        self.assertFalse(report["forced_cleanup"])
        self.assertEqual(report["remaining_owned_pids"], [])
        self.assertIsNone(processes.process_start_ticks(report["launcher_pid"]))
        return result

    def invoke(self, mode, *, mutate=False):
        case = self.root / mode
        case.mkdir()
        directory = case / "anonymous"
        directory.mkdir()
        environment = ({"LD_PRELOAD": str(self.fixture), "JAVA4SHELL_NATIVE_MUTATE_LOAD": "1"}
                       if mutate else None)
        result = self.bounded(case, ["-cp", str(self.classes), "NativeLibraryFixture",
            str(self.bridge), str(self.library), str(self.fixture), str(directory), mode,
            str(os.getuid())], environment=environment)
        row = json.loads(result.stdout)
        self.assertTrue(row["fd_audit"])
        self.assertEqual(list(directory.iterdir()), [])
        if "metadata" in row:
            metadata = row["metadata"]
            self.assertEqual(metadata["status"], "completed")
            self.assertEqual(metadata["exit_code"], 0)
            self.assertTrue(metadata["cleanup_complete"])
            self.assertTrue(metadata["supervisor_reaped"])
            self.assertEqual(metadata["no_new_privs"], 1)
            self.assertEqual(metadata["seccomp"], 2)
            for pid in (metadata["supervisor_pid"], metadata["child_pid"]):
                self.assertIsNone(processes.process_start_ticks(pid))
        return row

    def test_fresh_load_under_active_filter(self):
        self.invoke("fresh")

    def test_distinct_image_after_descriptor_number_reuse(self):
        row = self.invoke("cache")
        self.assertEqual(row["first_identity"][0], row["second_identity"][0])
        self.assertNotEqual(row["first_identity"][1:], row["second_identity"][1:])

    def test_failed_elf_load_poisoned(self):
        self.assertTrue(self.invoke("poison-elf")["poisoned"])

    def test_failed_post_load_hash_poisoned(self):
        self.assertTrue(self.invoke("poison-mutation", mutate=True)["poisoned"])

    def test_standalone_zero_progress_write_rejected(self):
        case = self.root / "zero-progress"
        case.mkdir()
        source = case / "library.so"
        shutil.copyfile(self.library, source)
        result = self.bounded(case, ["-cp", str(BUILD / "classes"),
            "org.elasticsearch.painless.OwnedNativeCommand", str(source), "--filtered", "1",
            "/usr/bin/id", "-u"], environment={"LD_PRELOAD": str(self.fixture),
            "JAVA4SHELL_NATIVE_ZERO_WRITE": "1"}, success=False)
        self.assertEqual(result.stdout, "")
        self.assertIn("Anonymous library write made no progress", result.stderr)

    def test_standalone_fifo_source_rejected_without_writer(self):
        case = self.root / "fifo-source"
        case.mkdir()
        source = case / "library.so"
        os.mkfifo(source)
        result = self.bounded(case, ["-cp", str(BUILD / "classes"),
            "org.elasticsearch.painless.OwnedNativeCommand", str(source), "--filtered", "1",
            "/usr/bin/id", "-u"], success=False)
        self.assertEqual(result.stdout, "")
        self.assertIn("Source library must be a regular file", result.stderr)
