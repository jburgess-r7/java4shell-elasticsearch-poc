#!/usr/bin/env python3
"""Manually exercise native cleanup with real harmless child processes."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--sde", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    root = Path.cwd().resolve()
    native = Path(__file__).resolve().parents[1]
    if not (root / "run_es7.py").is_file():
        parser.error("Run this manual test from the repository root")
    sys.path.insert(0, str(root))
    from java4shell import common, processes
    from java4shell.command import validate_native_metadata

    build, jdk = args.build.resolve(strict=True), args.jdk.resolve(strict=True)
    sde = args.sde.resolve(strict=True) if args.sde else None
    out = args.output.resolve()
    scratch = root / ".validation-local"
    if not out.is_relative_to(scratch) or out == scratch:
        parser.error("--output must be a new directory below .validation-local")
    out.mkdir(parents=True, exist_ok=False)
    evidence, binaries = out / "evidence", out / "test-build"
    evidence.mkdir()
    binaries.mkdir()
    manifest = json.loads((build / "build.json").read_text())
    recorded_sources = {entry["path"]: entry["sha256"] for entry in manifest["sources"]}
    summary = {"status": "running", "records": [],
               "build_manifest_sha256": digest(build / "build.json"),
               "source_sha256": digest(native / "native_command.c"),
               "native_sources_sha256": {name: digest(native / name) for name in
                   ("native_command.c", "elf_loader.c", "process_supervisor.c", "command_internal.h")},
               "java_sha256": digest(jdk / "bin/java"),
               "sde_sha256": digest(sde) if sde else None,
               "test_source_sha256": {name: digest(native / "tests" / name)
                                      for name in ("test_cleanup.py", "paused_children.c", "partial_scan.c",
                                                   "input_preparation.c", "preparation_delay.c")}}

    def command(label, command_argv, cwd=evidence, timeout=180):
        result = processes.run_bounded_command(command_argv, cwd, timeout,
                                         evidence / (label + "-process.json"))
        (evidence / (label + ".stdout")).write_text(result.stdout)
        (evidence / (label + ".stderr")).write_text(result.stderr)
        return result

    def clean(meta):
        return (meta["cleanup_complete"] and meta["supervisor_reaped"]
                and meta["supervisor_status"] == 0 and meta["no_new_privs"] == 1
                and meta["seccomp"] == 2)

    code = 1
    previous = None
    with processes.managed_signals():
        try:
            processes.require_pidfd_support()
            previous = processes.set_subreaper(True)
            common.require(all(digest(native / name) == recorded_sources["source/" + name]
                               for name in summary["native_sources_sha256"]),
                        "The selected build and current native source differ")
            canonical = build / manifest["native_library"]
            bridge = build / manifest["bridge_class"]
            common.require(digest(canonical) == manifest["native_library_sha256"]
                        and digest(bridge) == manifest["bridge_class_sha256"],
                        "The selected build artifacts differ from their manifest")
            summary.update(bridge_class_sha256=digest(bridge), native_library_sha256=digest(canonical))
            compiler = manifest["compiler"]["command"][0]
            base = manifest["compiler"]["command"][:-2]
            batch_library = binaries / "libbatch-two.so"
            missing_library = binaries / "libmissing-children.so"
            wait_library = binaries / "libunsupported-wait.so"
            missing_path = evidence / "does-not-exist-children"
            for label, path, defines in (
                ("compile-batch", batch_library, ["-DJAVA4SHELL_CHILD_BATCH_SIZE=2"]),
                ("compile-missing", missing_library,
                 ['-DJAVA4SHELL_CHILDREN_PATH="' + str(missing_path) + '"']),
                ("compile-unsupported-wait", wait_library, ["-DPIDFD_IDTYPE=999"]),
            ):
                result = command(label, base + defines + ["-o", str(path)])
                common.require(result.returncode == 0, label + " failed: " + result.stderr)

            fixture, scan = binaries / "paused-children", binaries / "partial-scan"
            preparation = binaries / "input-preparation"
            delay_library = binaries / "libpreparation-delay.so"
            fifo, fifo_link = evidence / "no-writer-fifo", evidence / "symlink-to-fifo"
            os.mkfifo(fifo, 0o600)
            fifo_link.symlink_to(fifo)
            fifo_interpreter = binaries / "fifo-interpreter"
            cc = [compiler, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie"]
            for label, source, output, extra in (
                ("compile-fixture", native / "tests/paused_children.c", fixture, []),
                ("compile-scan", native / "tests/partial_scan.c", scan,
                 ["-I" + str(jdk / "include"), "-I" + str(jdk / "include/linux")]),
                ("compile-preparation", native / "tests/input_preparation.c", preparation,
                 ["-I" + str(jdk / "include"), "-I" + str(jdk / "include/linux")]),
                ("compile-fifo-interpreter", native / "tests/paused_children.c", fifo_interpreter,
                 ["-Wl,--dynamic-linker=" + str(fifo)]),
            ):
                result = command(label, cc + extra + [str(source), "-o", str(output)])
                common.require(result.returncode == 0, label + " failed: " + result.stderr)
            result = command("compile-preparation-delay", [compiler, "-std=gnu11", "-O2", "-Wall",
                "-Wextra", "-Werror", "-fPIC", "-shared", str(native / "tests/preparation_delay.c"),
                "-o", str(delay_library)])
            common.require(result.returncode == 0, "Preparation-delay fixture failed: " + result.stderr)

            scan_dir = evidence / "partial-scan-work"
            scan_dir.mkdir()
            result = command("partial-scan", [str(scan)], scan_dir, 30)
            parsed = json.loads(result.stdout)
            common.require(result.returncode == 0 and parsed == {
                "partial_entries_retained": True, "error_preserved": True,
                "cleanup_complete": True, "descendants_reaped": 2},
                "Partial enumeration did not preserve and reap the verified child")
            summary["records"].append({"label": "partial-scan", "pass": True, "parsed": parsed})

            preparation_dir = evidence / "preparation-work"
            preparation_dir.mkdir()
            original, renamed = preparation_dir / "selected", preparation_dir / "saved"
            shutil.copy2("/usr/bin/id", original)
            result = command("input-preparation", [str(preparation), str(original), str(renamed)],
                             preparation_dir, 30)
            parsed = json.loads(result.stdout)
            common.require(result.returncode == 0 and parsed["path_replaced_with_fifo"] is True
                        and parsed["original_inode_or_refusal"] is True
                        and parsed["stage"] in ("none", "file_changed"),
                        "Replacing the selected path defeated the descriptor-bound read")
            summary["records"].append({"label": "input-preparation", "pass": True, "parsed": parsed})

            delayed = ["/usr/bin/env", "LD_PRELOAD=" + str(delay_library),
                "JAVA4SHELL_PREPARE_DELAY_FILE=/usr/bin/id", str(jdk / "bin/java"),
                "-XX:ErrorFile=" + str(evidence / "hs_err_pid%p.log"), "-cp", str(build / "classes"),
                "org.elasticsearch.painless.OwnedNativeCommand", str(canonical),
                "--filtered", "1", "/usr/bin/id", "-u"]
            started = time.monotonic()
            result = command("preparation-timeout", delayed, timeout=15)
            elapsed = time.monotonic() - started
            parsed = json.loads(result.stdout)
            meta = parsed["metadata"]
            validate_native_metadata(meta)
            common.require(result.returncode == 0 and not result.stderr
                and meta["status"] == "timeout" and meta["stage"] == "timeout"
                and meta["error_errno"] == 110 and meta["timeout"] is True
                and meta["supervisor_pid"] == -1 and meta["child_pid"] == -1
                and not meta["supervisor_reaped"] and not parsed["stdout_base64"]
                and not parsed["stderr_base64"] and elapsed < 10,
                "ELF preparation did not consume the native command deadline")
            summary["records"].append({"label": "preparation-timeout", "pass": True,
                                       "elapsed_seconds": elapsed, "parsed": parsed})

            uid = (str(os.getuid()) + "\n").encode()
            for emulated in ((False, True) if sde else (False,)):
                mode = "sde" if emulated else "native"
                prefix = [str(sde), "-icx", "--"] if emulated else []
                missing_marker = evidence / (mode + "-missing-must-not-launch")
                wait_marker = evidence / (mode + "-wait-must-not-launch")
                cases = (
                    (mode + "-id", canonical, 15, ["/usr/bin/id", "-u"], "id"),
                    (mode + "-timeout", canonical, 1, ["/usr/bin/sleep", "4"], "timeout"),
                    (mode + "-default-descendants", canonical, 10, [str(fixture), "5"], "descendants"),
                    (mode + "-batch-two", batch_library, 10, [str(fixture), "5"], "descendants"),
                    (mode + "-missing-preflight", missing_library, 10,
                     [str(fixture), "marker", str(missing_marker)], "missing"),
                    (mode + "-unsupported-wait", wait_library, 10,
                     [str(fixture), "marker", str(wait_marker)], "wait"),
                    (mode + "-fifo", canonical, 1, [str(fifo)], "nonregular"),
                    (mode + "-symlink-fifo", canonical, 1, [str(fifo_link)], "nonregular"),
                    (mode + "-directory", canonical, 1, [str(evidence)], "nonregular"),
                    (mode + "-fifo-interpreter", canonical, 1, [str(fifo_interpreter)], "nonregular"),
                )
                for label, library, timeout, command_argv, kind in cases:
                    summary["active_case"] = label
                    invocation = prefix + [str(jdk / "bin/java"),
                        "-XX:ErrorFile=" + str(evidence / "hs_err_pid%p.log"), "-cp", str(build / "classes"),
                        "org.elasticsearch.painless.OwnedNativeCommand", str(library),
                        "--filtered", str(timeout)] + command_argv
                    started = time.monotonic()
                    outer_timeout = (90 if emulated else 15) if kind == "nonregular" else 180
                    result = command(label, invocation, timeout=outer_timeout)
                    elapsed = time.monotonic() - started
                    parsed = json.loads(result.stdout)
                    meta = parsed["metadata"]
                    validate_native_metadata(meta)
                    stdout = base64.b64decode(parsed["stdout_base64"], validate=True)
                    stderr = base64.b64decode(parsed["stderr_base64"], validate=True)
                    common.require(result.returncode == 0 and not result.stderr and not stderr,
                                label + " JVM/output failure")
                    identities = []
                    if kind == "nonregular":
                        common.require(meta["status"] == "unsupported" and meta["stage"] == "elf"
                            and meta["error_errno"] == 8 and meta["supervisor_pid"] == -1
                            and meta["child_pid"] == -1 and not meta["supervisor_reaped"]
                            and not meta["timeout"] and not stdout,
                            label + " non-regular file reached command launch")
                    elif kind == "wait":
                        common.require(meta["status"] == "unsupported" and meta["stage"] == "kernel"
                            and meta["error_errno"] == 22 and meta["supervisor_pid"] == -1
                            and meta["child_pid"] == -1 and not meta["supervisor_reaped"]
                            and not stdout and not wait_marker.exists(), "Unsupported wait API launched a process")
                    else:
                        common.require(clean(meta), label + " cleanup/sandbox proof failed")
                    if kind == "id":
                        common.require(meta["status"] == "completed" and meta["exit_code"] == 0
                                    and stdout == uid, label + " output differs")
                    elif kind == "timeout":
                        common.require(meta["status"] == "timeout" and meta["timeout"]
                                    and meta["term_signal"] == 9, label + " timeout was not enforced")
                    elif kind == "descendants":
                        common.require(meta["status"] == "completed" and meta["exit_code"] == 0
                                    and meta["descendants_reaped"] == 5, label + " descendant count differs")
                        for line in stdout.decode("ascii").splitlines():
                            pid, ticks = line.split(":")
                            common.require(pid.isdigit() and ticks.isdigit(), "Malformed fixture process identity")
                            common.require(processes.process_start_ticks(int(pid)) != ticks,
                                        label + " left an original descendant alive")
                            identities.append({"pid": int(pid), "start_ticks": ticks, "identity_absent": True})
                        common.require(len(identities) == 5, label + " fixture identity count differs")
                    elif kind == "missing":
                        common.require(meta["status"] == "unsupported" and meta["stage"] == "descendants"
                            and meta["error_errno"] == 2 and meta["child_pid"] == -1
                            and meta["exit_code"] == -1 and meta["descendants_reaped"] == 0
                            and not stdout and not missing_marker.exists(), "Unavailable enumeration launched the command")
                    summary["records"].append({"label": label, "pass": True, "parsed": parsed,
                        "library_sha256": digest(library), "child_identities": identities,
                        "elapsed_seconds": elapsed})
                    print(json.dumps({"label": label, "status": meta["status"], "pass": True}), flush=True)
            processes.cancellation_checkpoint()
            summary["status"] = "passed"
            code = 0
        except KeyboardInterrupt as error:
            summary.update(status="interrupted", error=str(error),
                           interruption=processes.interruption_details(error))
            code = 128 + summary["interruption"]["signal"]
        except Exception as error:
            summary.update(status="failed", error=type(error).__name__ + ": " + str(error))
        finally:
            if previous is not None:
                processes.set_subreaper(previous)
            (out / "validation.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"status": summary["status"], "passed": len(summary["records"]),
                      "report": str(out / "validation.json"), "error": summary.get("error")}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
