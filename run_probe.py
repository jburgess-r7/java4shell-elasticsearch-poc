#!/usr/bin/env python3
"""Run the guarded Base64 reproducer with explicitly selected genuine JDK controls."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "poc" / "Base64TailProbe.java"
# Published OpenJDK CSPU release floors; vendor backport status is established
# by the observed control, not inferred from an unrelated package revision.
FIXED = {17: (17, 0, 21, 1), 21: (21, 0, 13, 1),
         25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
REQUIRED_CPU = {"avx512f", "avx512bw", "avx512vbmi", "bmi2"}
BASE_FLAGS = ["-Xbatch", "-XX:+UnlockDiagnosticVMOptions"]


class Unavailable(Exception):
    pass


class ProbeFailure(Exception):
    pass


def sha256(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def version_numbers(value):
    match = re.fullmatch(r"(\d+(?:\.\d+){0,5})(?:\+\d+(?:-[A-Za-z0-9._-]+)?|-LTS)?", value)
    return tuple(map(int, match.group(1).split("."))) if match else None


def at_least(version, floor):
    width = max(len(version), len(floor))
    return version + (0,) * (width - len(version)) >= floor + (0,) * (width - len(floor))


def runtime_image_paths(home, platform_name=None):
    platform_name = sys.platform if platform_name is None else platform_name
    library = (home / "bin" / "server" / "jvm.dll" if platform_name == "win32" else
               home / "lib" / "server" / ("libjvm.dylib" if platform_name == "darwin" else "libjvm.so"))
    return {"modules": home / "lib" / "modules", "jvm_library": library}


def runtime(home):
    """Classify a selected genuine JDK and record its runtime-image hashes."""
    home = Path(home).expanduser().resolve()
    suffix = ".exe" if os.name == "nt" else ""
    paths = {name: home / "bin" / (name + suffix) for name in ("java", "javac")}
    if not all(path.is_file() and os.access(path, os.X_OK) for path in paths.values()):
        raise Unavailable("Selected JDK must contain executable java and javac: " + str(home))
    try:
        text = (home / "release").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise Unavailable("Selected JDK release metadata is unavailable: " + str(home)) from exc
    keys = {"JAVA_VERSION", "JAVA_RUNTIME_VERSION", "FULL_VERSION", "IMPLEMENTOR", "IMPLEMENTOR_VERSION", "OS_ARCH"}
    metadata = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator and name in keys:
            metadata[name] = value.strip().strip('"')
    declared = metadata.get("JAVA_RUNTIME_VERSION") or metadata.get("FULL_VERSION") or metadata.get("JAVA_VERSION", "")
    numbers = version_numbers(declared)
    if not numbers or numbers[0] not in FIXED:
        raise Unavailable("Selected JDK has no supported stable upstream release identity: " + declared)
    if metadata.get("OS_ARCH", "").lower() not in ("amd64", "x86_64", "x64"):
        raise Unavailable("Selected JDK must identify an x86-64 runtime")
    images = runtime_image_paths(home)
    if not all(path.is_file() for path in images.values()):
        raise Unavailable("Selected JDK must contain lib/modules and its platform JVM library: " + str(home))
    evidence = {"home": str(home), "release": metadata, "declared_version": declared,
                "release_sha256": sha256(home / "release"),
                "tools": {name: {"path": str(path), "sha256": sha256(path)} for name, path in paths.items()},
                "runtime_images": {name: {"path": str(path), "sha256": sha256(path)} for name, path in images.items()}}
    return paths, numbers, evidence


def clean_environment():
    environment = os.environ.copy()
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
                 "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "BASH_ENV", "ENV"):
        environment.pop(name, None)
    return environment


def private_directory(repository_root=ROOT):
    repository_root = Path(repository_root).resolve()
    private = repository_root / ".validation-local"
    try:
        private.mkdir(mode=0o700, exist_ok=True)
        metadata = private.lstat()
        linked = stat.S_ISLNK(metadata.st_mode) or bool(
            getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        resolved = private.resolve(strict=True)
        if linked or not stat.S_ISDIR(metadata.st_mode) or resolved.parent != repository_root:
            raise Unavailable("Private evidence directory must be a direct, unlinked directory inside this repository")
        return resolved
    except OSError as exc:
        raise Unavailable("Private evidence directory is unavailable: " + type(exc).__name__) from exc


def stop_owned(process):
    """Stop and reap this standalone JVM and its owned platform process group."""
    if os.name == "posix":
        # start_new_session created this group for this command alone.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    else:
        if process.poll() is not None:
            return
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name != "posix":
            process.kill()
    if os.name == "posix":
        # A launcher can exit on SIGTERM while its traced JVM remains in the
        # session. Reap the entire owned group even after its leader exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=5)


def command(argv, directory, name, environment, timeout):
    stdout_path, stderr_path = directory / (name + ".stdout"), directory / (name + ".stderr")
    process = None
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen([str(value) for value in argv], stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, env=environment, cwd=directory,
                                       shell=False, start_new_session=os.name == "posix")
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                stop_owned(process)
                raise ProbeFailure("Owned command timed out: " + name) from exc
    except OSError as exc:
        raise Unavailable("Selected command could not start: " + name + ":" + type(exc).__name__) from exc
    finally:
        if process is not None and process.poll() is None:
            stop_owned(process)
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    return code, stdout, stderr


def java_command(java, options, sde):
    return ([str(sde), "-icx", "--"] if sde else []) + [str(java)] + list(options)


def cpu_evidence(java, sde, directory, environment, timeout, name="cpu"):
    # Query the selected JVM itself. Under SDE, the guest-visible capabilities
    # are the relevant CPU input to intrinsic selection, rather than the host's
    # /proc/cpuinfo. Runtime flags and compilation still matter.
    code, stdout, stderr = command(java_command(java, ["-Xlog:os+cpu=info", "-version"], sde),
                                   directory, name, environment, timeout)
    rows = [line for line in (stdout + "\n" + stderr).splitlines() if "[os,cpu]" in line and "CPU:" in line]
    features = [{token.replace("_", "").replace("-", "").replace(".", "")
                 for token in re.findall(r"[a-z][a-z0-9_.-]*", row.lower())} for row in rows]
    common = set.intersection(*features) if features else set()
    return {"source": "selected Java CPU diagnostic", "execution": "intel-sde-icx" if sde else "native",
            "diagnostic_exit_code": code, "required": sorted(REQUIRED_CPU),
            "present": sorted(common & REQUIRED_CPU), "missing": sorted(REQUIRED_CPU - common),
            "eligible": code == 0 and REQUIRED_CPU <= common}


def parse_probe(text):
    result = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            if name in result:
                raise ProbeFailure("Duplicate field in owned probe output: " + name)
            result[name] = value
    return result


def trigger_bytes(prefix, tail):
    data = b"A" * prefix + tail.encode("ascii")
    padding = 1 if data.endswith(b"=") else 0
    if data.endswith(b"=="):
        padding += 1
    return data, 3 * ((len(data) + 3) // 4) - padding


def verify_witness(directory, fields, expected, capacity):
    # Recompute the overwrite from saved bytes outside Java's reported result.
    # The guard begins at the destination capacity calculated for this input.
    """Read the saved input/destination and check the exact guard-byte differences."""
    input_path, witness_path = directory / "base64-input.bin", directory / "base64-witness.bin"
    actual, witness = input_path.read_bytes(), witness_path.read_bytes()
    if actual != expected or len(witness) != max(0, capacity) + 128:
        raise ProbeFailure("Guard witness does not match the selected trigger and allocation")
    changed = [index for index in range(max(0, capacity), len(witness)) if witness[index] != 0x5a]
    if (not changed or fields.get("guard_first") != str(changed[0])
            or fields.get("guard_last") != str(changed[-1])
            or fields.get("guard_bytes") != witness[changed[0]:changed[-1] + 1].hex()):
        raise ProbeFailure("Guard witness bytes do not support the reported overwrite")
    return {"first_changed_offset": changed[0], "last_changed_offset": changed[-1],
            "changed_bytes": len(changed), "input_sha256": sha256(input_path),
            "destination_sha256": sha256(witness_path)}


def verify_running_version(actual, declared, metadata):
    if version_numbers(actual) != declared:
        raise ProbeFailure("Owned JVM release differs from the selected JDK metadata")
    exact = metadata.get("JAVA_RUNTIME_VERSION") or metadata.get("FULL_VERSION")
    if exact and actual != exact:
        raise ProbeFailure("Owned JVM full build differs from the selected JDK metadata")
    return "full-runtime-version" if exact else "numeric-release-only"


def run_case(name, paths, declared, metadata, classes, root, extra, mode, sde, environment, args):
    # Only the affected case may report corruption. An exception, crash, or
    # missing witness is never substituted for the expected guard overwrite.
    """Run one guarded decoder case and reconcile the saved witness with its output."""
    directory = root / name
    directory.mkdir()
    options = BASE_FLAGS + extra + ["-cp", str(classes), "Base64TailProbe", str(args.prefix), args.tail, mode]
    code, stdout, stderr = command(java_command(paths["java"], options, sde), directory,
                                   "probe", environment, args.timeout)
    fields = parse_probe(stdout)
    result = {"name": name, "requested_flags": BASE_FLAGS + extra, "exit_code": code, "probe": fields}
    if code == 77 and fields.get("result") == "SKIP":
        result.update(status="unavailable", reason=fields.get("reason", "Probe prerequisite unavailable"))
        return result
    result["running_build_identity"] = verify_running_version(fields.get("runtime", ""), declared, metadata)
    if not re.search(r"HotSpot|OpenJDK .*Server VM", fields.get("vm", "")):
        raise Unavailable(name + " did not identify HotSpot")
    if fields.get("architecture", "").lower() not in ("amd64", "x86_64", "x64"):
        raise Unavailable(name + " did not start an x86-64 JVM")
    expected_input, capacity = trigger_bytes(args.prefix, args.tail)
    if (fields.get("input_sha256") != hashlib.sha256(expected_input).hexdigest()
            or fields.get("input_length") != str(len(expected_input))
            or fields.get("nominal_capacity") != str(capacity)):
        raise ProbeFailure(name + " did not use the selected trigger")
    expected_code, expected_result = (42, "GUARD_OVERWRITE") if name == "affected" else (0, "NO_GUARD_OVERWRITE")
    result["status"] = "passed" if code == expected_code and fields.get("result") == expected_result else "failed"
    if result["status"] == "failed":
        result["reason"] = "Expected " + expected_result + " with exit " + str(expected_code)
    elif name == "affected":
        result["witness_verification"] = verify_witness(directory, fields, expected_input, capacity)
    elif any((directory / filename).exists() for filename in ("base64-input.bin", "base64-witness.bin")):
        raise ProbeFailure(name + " unexpectedly produced an overwrite witness")
    for witness in ("base64-input.bin", "base64-witness.bin"):
        path = directory / witness
        if path.is_file():
            result.setdefault("witness_sha256", {})[witness] = sha256(path)
    return result


def write_result(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--affected-jdk", required=True, help="Explicitly trusted genuine affected HotSpot JDK home")
    parser.add_argument("--fixed-jdk", required=True, help="Explicitly trusted genuine fixed HotSpot JDK home on the same Java major")
    parser.add_argument("--sde", help="Explicitly trusted Intel SDE executable on POSIX; use its Ice Lake (-icx) CPU model")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds for each owned command")
    parser.add_argument("--prefix", type=int, default=128)
    parser.add_argument("--tail", default="=")
    parser.add_argument("--output", help="Also write a private JSON result to this new file")
    args = parser.parse_args(argv)
    if args.timeout < 1 or not 0 <= args.prefix <= 1048576 or not re.fullmatch(r"[A=]{0,16}", args.tail):
        parser.error("positive timeout, prefix 0..1048576, and tail of at most 16 A/= characters are required")
    if args.output and os.path.lexists(Path(args.output).expanduser()):
        parser.error("Output already exists")
    result = {"schema_version": 1, "status": "failed", "success": False, "cases": [],
              "source_sha256": sha256(SOURCE),
              "runner_sha256": sha256(Path(__file__).resolve()),
              "trigger": {"prefix": args.prefix, "tail": args.tail}}
    try:
        directory = Path(tempfile.mkdtemp(prefix="probe-", dir=private_directory()))
    except (Unavailable, OSError) as exc:
        result.update(status="unavailable", reason=str(exc))
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 77
    result["evidence_directory"] = str(directory)
    exit_code = 1
    try:
        affected, affected_version, result["affected_runtime"] = runtime(args.affected_jdk)
        fixed, fixed_version, result["fixed_runtime"] = runtime(args.fixed_jdk)
        floor = FIXED[affected_version[0]]
        if affected_version[0] != fixed_version[0] or at_least(affected_version, floor) or not at_least(fixed_version, floor):
            raise Unavailable("Select an affected/fixed pair on one supported Java major around its published fix floor")
        if affected_version[0] == 17 and not at_least(affected_version, (17, 0, 6)):
            raise Unavailable("Selected Java 17 build predates the affected upstream release line")
        sde = Path(args.sde).expanduser().resolve() if args.sde else None
        if sde and (not sde.is_file() or not os.access(sde, os.X_OK)):
            raise Unavailable("Explicitly selected Intel SDE executable is unavailable")
        if sde and os.name != "posix":
            raise Unavailable("Intel SDE mode currently requires POSIX owned-process-group cleanup")
        result["execution"] = {"kind": "intel-sde" if sde else "native"}
        if sde:
            result["execution"].update(path=str(sde), sha256=sha256(sde), model="icx")
        environment = clean_environment()
        result["cpu"] = cpu_evidence(affected["java"], sde, directory, environment, args.timeout)
        if not result["cpu"]["eligible"]:
            raise Unavailable("Selected execution environment does not establish AVX-512/VBMI/BMI2 eligibility")
        result["fixed_cpu"] = cpu_evidence(fixed["java"], sde, directory, environment, args.timeout, "fixed-cpu")
        if not result["fixed_cpu"]["eligible"]:
            raise Unavailable("Fixed control does not establish the same required guest-visible CPU features")
        classes = directory / "classes"
        classes.mkdir()
        code, _, _ = command([affected["javac"], "--release", "17", "-d", classes, SOURCE],
                             directory, "javac", environment, args.timeout)
        if code:
            raise ProbeFailure("Selected genuine javac failed")
        result["class_sha256"] = sha256(classes / "Base64TailProbe.class")
        for name, paths, version, metadata, extra, mode in (
                ("affected", affected, affected_version, result["affected_runtime"]["release"], [], "enabled"),
                ("disabled-intrinsic", affected, affected_version, result["affected_runtime"]["release"], ["-XX:-UseBASE64Intrinsics"], "disabled"),
                ("fixed", fixed, fixed_version, result["fixed_runtime"]["release"], [], "enabled")):
            result["cases"].append(run_case(name, paths, version, metadata, classes, directory, extra,
                                             mode, sde, environment, args))
        if any(case["status"] == "failed" for case in result["cases"]):
            result["status"] = "failed"
        elif any(case["status"] == "unavailable" for case in result["cases"]):
            result["status"], exit_code = "unavailable", 77
        else:
            result.update(status="passed", success=True)
            exit_code = 0
    except Unavailable as exc:
        result.update(status="unavailable", reason=str(exc))
        exit_code = 77
    except (ProbeFailure, OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(status="failed", reason=str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    write_result(directory / "result.json", rendered)
    if args.output:
        try:
            write_result(Path(args.output).expanduser(), rendered)
        except OSError as exc:
            print("Result write failed: " + type(exc).__name__, file=sys.stderr)
            return 2
    sys.stdout.write(rendered)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
