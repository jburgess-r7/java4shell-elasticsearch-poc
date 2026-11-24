import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_probe as probe


class GuardedProbeRunnerTests(unittest.TestCase):
    def test_version_comparison_retains_every_numeric_component(self):
        self.assertEqual(probe.version_numbers("17.0.21.0.3+1"), (17, 0, 21, 0, 3))
        self.assertFalse(probe.at_least(probe.version_numbers("17.0.21.0.3+1"), probe.FIXED[17]))
        self.assertTrue(probe.at_least(probe.version_numbers("21.0.13.1+2-LTS"), probe.FIXED[21]))
        for value in ("21.0.13.1-ea+1", "garbage", "21.0.13.1+1 extra"):
            self.assertIsNone(probe.version_numbers(value))

    def test_full_runtime_build_must_match_selected_release(self):
        declared = probe.version_numbers("21.0.13+9-LTS")
        metadata = {"JAVA_RUNTIME_VERSION": "21.0.13+9-LTS"}
        self.assertEqual(probe.verify_running_version("21.0.13+9-LTS", declared, metadata), "full-runtime-version")
        with self.assertRaises(probe.ProbeFailure):
            probe.verify_running_version("21.0.13+8-LTS", declared, metadata)
        self.assertEqual(probe.verify_running_version("21.0.13+9-LTS", declared, {}), "numeric-release-only")

    def test_runtime_image_paths_cover_platform_layouts(self):
        home = Path("selected-jdk")
        for system, library in (("linux", home / "lib/server/libjvm.so"),
                                ("darwin", home / "lib/server/libjvm.dylib"),
                                ("win32", home / "bin/server/jvm.dll")):
            with self.subTest(system=system):
                self.assertEqual(probe.runtime_image_paths(home, system),
                                 {"modules": home / "lib/modules", "jvm_library": library})

    def test_cpu_fixture_does_not_confuse_vbmi2_with_vbmi(self):
        line = "[0.001s][info][os,cpu] CPU: avx512f avx512bw avx512_vbmi2 bmi2"
        with mock.patch.object(probe, "command", return_value=(0, line, "")):
            evidence = probe.cpu_evidence(Path("java"), None, Path("."), {}, 1)
        self.assertFalse(evidence["eligible"])
        self.assertEqual(evidence["missing"], ["avx512vbmi"])
        with mock.patch.object(probe, "command", return_value=(0, line + " avx512_vbmi", "")):
            self.assertTrue(probe.cpu_evidence(Path("java"), None, Path("."), {}, 1)["eligible"])

    def test_duplicate_probe_fields_are_rejected(self):
        self.assertEqual(probe.parse_probe("runtime=21.0.13+9-LTS\nresult=NO_GUARD_OVERWRITE\n")["result"],
                         "NO_GUARD_OVERWRITE")
        with self.assertRaises(probe.ProbeFailure):
            probe.parse_probe("result=NO_GUARD_OVERWRITE\nresult=GUARD_OVERWRITE\n")

    def test_explicit_sde_does_not_add_jvm_feature_overrides(self):
        options = probe.BASE_FLAGS + ["-version"]
        java = Path("jdk") / "bin" / "java"
        sde = Path("approved") / "sde64"
        self.assertEqual(probe.java_command(java, options, None), [str(java)] + options)
        self.assertEqual(probe.java_command(java, options, sde),
                         [str(sde), "-icx", "--", str(java)] + options)
        self.assertFalse(any("UseAVX=" in value or "UseBASE64Intrinsics" in value for value in probe.BASE_FLAGS))

    def test_jvm_environment_injection_is_removed(self):
        names = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
                 "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "BASH_ENV", "ENV")
        with mock.patch.dict(os.environ, {name: "injected" for name in names}):
            clean = probe.clean_environment()
            for name in names:
                self.assertNotIn(name, clean)
                self.assertEqual(os.environ[name], "injected")

    def test_private_directory_rejects_files_and_links(self):
        with tempfile.TemporaryDirectory(prefix="probe-path-unit-", dir=probe.private_directory()) as temporary:
            base = Path(temporary)
            repository = base / "repo"
            repository.mkdir()
            private = repository / ".validation-local"
            private.write_text("not a directory", encoding="utf-8")
            with self.assertRaises(probe.Unavailable):
                probe.private_directory(repository)
            private.unlink()
            outside = base / "outside"
            outside.mkdir()
            inside = repository / "inside"
            inside.mkdir()
            for target in (outside, inside):
                try:
                    private.symlink_to(target, target_is_directory=True)
                except OSError as exc:
                    self.skipTest("Cannot create a directory symlink: " + type(exc).__name__)
                if not os.path.lexists(private):
                    self.skipTest("The Windows/filesystem directory-symlink facility did not create a link")
                with self.assertRaises(probe.Unavailable):
                    probe.private_directory(repository)
                private.unlink()
            self.assertEqual(probe.private_directory(repository), private.resolve())

    def test_witness_verifier_rejects_claims_not_supported_by_bytes(self):
        expected, capacity = probe.trigger_bytes(128, "=")
        private = probe.private_directory()
        with tempfile.TemporaryDirectory(prefix="probe-unit-", dir=private) as temporary:
            directory = Path(temporary)
            witness = bytearray(b"Z" * (capacity + 128))
            witness[capacity:capacity + 2] = b"\x00\x00"
            (directory / "base64-input.bin").write_bytes(expected)
            (directory / "base64-witness.bin").write_bytes(witness)
            fields = {"guard_first": str(capacity), "guard_last": str(capacity + 1), "guard_bytes": "0000"}
            self.assertEqual(probe.verify_witness(directory, fields, expected, capacity)["changed_bytes"], 2)
            with self.assertRaises(probe.ProbeFailure):
                probe.verify_witness(directory, dict(fields, guard_last=str(capacity + 3)), expected, capacity)
            (directory / "base64-witness.bin").write_bytes(b"Z" * len(witness))
            with self.assertRaises(probe.ProbeFailure):
                probe.verify_witness(directory, fields, expected, capacity)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group cleanup")
    def test_cleanup_stops_only_an_owned_session(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            probe.stop_owned(child)
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group cleanup")
    def test_cleanup_stops_descendant_when_launcher_exits_first(self):
        descendant = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready',flush=True); time.sleep(60)"
        launcher = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-u','-c'," + repr(descendant) + "]); time.sleep(60)"
        child = subprocess.Popen([sys.executable, "-u", "-c", launcher], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            probe.stop_owned(child)
            # The descendant inherits this pipe; EOF proves that it also died.
            child.communicate(timeout=2)
            self.assertIsNotNone(child.poll())
        finally:
            probe.stop_owned(child)


if __name__ == "__main__":
    unittest.main()
