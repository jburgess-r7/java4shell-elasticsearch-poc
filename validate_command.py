#!/usr/bin/env python3
"""Run genuine disabled, fixed and affected ES7 command comparisons."""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import run_es7 as es7
from java4shell import common, processes, es7 as es7_api
from java4shell.bytecode import class_internal_name
from java4shell.command import checked_payload, decode_result, render_request_class

ROOT = Path(__file__).resolve().parent


def prepare_comparison(args, command, out, report):
    """Authenticate local releases, compile one request class and check both JVM profiles."""
    runtimes = ROOT / ".validation-local/runtimes"
    affected, fixed = runtimes / ("temurin" + str(args.major)), runtimes / ("corretto" + str(args.major))
    server = runtimes / "elasticsearch-7.17.29"
    sde = runtimes / "sde-external-10.13.1-2026-07-28-lin/sde64"
    common.require(common.digest(sde) == "257872adf7e5cb0855c6774539590587238302bdcd90ddfccca074e9c4c4a3f5",
                "Selected SDE executable differs")
    pins = json.loads((common.ASSETS / "releases.json").read_text())
    pair = pins["runtimes"][str(args.major)]
    # Unlike the public client's API profile check, this owned-node
    # comparison verifies the selected runtime and distribution files
    # against the release pins before launching anything.
    report["runtimes"] = {"affected": es7_api.runtime_identity(affected, pair["affected"]),
                          "fixed": es7_api.runtime_identity(fixed, pair["fixed"])}
    report["server"] = es7_api.verify_server(server, pins["elasticsearch"])
    report["sde_sha256"] = common.digest(sde)
    build = args.build.resolve(strict=True)
    bridge = build / "classes/org/elasticsearch/painless/OwnedNativeCommand.class"
    library = build / "libowned-native-command.so"
    manifest = json.loads((build / "build.json").read_text())
    report["native_build_manifest_sha256"] = common.digest(build / "build.json")
    common.require(common.digest(bridge) == manifest["bridge_class_sha256"]
                and common.digest(library) == manifest["native_library_sha256"],
                "Frozen command artifacts changed")
    # Compile one request-specific class and send the same class bytes,
    # token and Painless source to all three cases. The runtime,
    # intrinsic setting and isolated case paths vary between nodes.
    generated = render_request_class(bridge.read_bytes(), library.read_bytes(), command, args.timeout,
                              build_id=manifest["bridge_build_id"])
    source_dir = out / "source/org/elasticsearch/painless"
    source_dir.mkdir(parents=True)
    source = source_dir / (generated["simple_name"] + ".java")
    source.write_text(generated["source"])
    classes = out / "classes"
    classes.mkdir()
    compiled = processes.run_bounded_command([str(affected / "bin/javac"), "--release", "17", "-g:none",
                 "-d", str(classes), str(source)], out, 600, out / "javac-process.json")
    (out / "javac.stdout").write_text(compiled.stdout)
    (out / "javac.stderr").write_text(compiled.stderr)
    common.require(compiled.returncode == 0, "Command request class did not compile")
    class_path = classes / (generated["binary_name"].replace(".", "/") + ".class")
    class_bytes = class_path.read_bytes()
    common.require(class_internal_name(class_bytes) == generated["binary_name"].replace(".", "/"),
                "Command request class identity differs")
    marker = {"binary_name": generated["binary_name"],
              "internal_name": generated["binary_name"].replace(".", "/"),
              "marker_return": generated["marker_return"], "bytes": class_bytes,
              "sha256": hashlib.sha256(class_bytes).hexdigest()}
    report["marker"] = {k: v for k, v in generated.items() if k != "source"}
    report["marker"]["class_sha256"] = marker["sha256"]
    original = (common.ASSETS / ("payload-java" + str(args.major) + ".painless")).read_text()
    payload = checked_payload(original, pair["payload_sha256"], generated["nonce"])
    (out / "payload.painless").write_text(payload)
    report["original_payload_sha256"] = pair["payload_sha256"]
    report["sent_payload_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
    report["preflight"] = {"affected": es7_api.preflight_flags(affected, sde, out / "affected-flags", 600),
                           "fixed": es7_api.preflight_flags(fixed, sde, out / "fixed-flags", 600)}
    return SimpleNamespace(affected=affected, fixed=fixed, server=server, sde=sde,
                           payload=payload, marker=marker)


def check_case_result(case, case_dir, role, marker, expected_stdout, report, report_path):
    """Record the raw case, then require exact command output or an unchanged control."""
    raw = json.loads((case_dir / "trigger.json").read_text())
    fields = es7_api.parse_java_map(es7_api.result(raw))
    common.require(not (case_dir / "execution-marker.native.so").exists()
                and not (case_dir / "execution-marker.denied.native.so").exists(),
                "A named command library exists")
    if role == "affected":
        result = decode_result(fields.get("command_result"), marker["marker_return"])
        meta = result.get("metadata", {})
        case["command_result"] = {k: v for k, v in result.items() if k not in ("stdout", "stderr")}
        report["cases"].append(case)
        common.write_json(report_path, report)
        # This owned comparison also checks a newly created marker
        # file. The public client omits that file and relies on the
        # same class/token and native-result contract.
        common.require(result.get("state") == "completed"
                    and result.get("library_anonymous") is True
                    and result.get("library_descriptor_closed") is True
                    and result.get("marker_file_created") is True,
                    "The supplied command class did not complete")
        common.require(meta.get("status") == "completed"
                    and meta.get("cleanup_complete") is True and meta.get("supervisor_reaped") is True
                    and meta.get("exit_code") == 0 and meta.get("term_signal") == 0
                    and meta.get("error_errno") == 0 and meta.get("timeout") is False
                    and meta.get("stdout_truncated") is False and meta.get("stderr_truncated") is False
                    and meta.get("no_new_privs") == 1 and meta.get("seccomp") == 2,
                    "The native command did not complete cleanly under the genuine sandbox")
        # A successful exit alone cannot prove which command ran.
        # Require the caller's exact stdout bytes and empty stderr.
        common.require(result.get("stdout") == expected_stdout and result.get("stderr") == b"",
                    "The exact expected command output differs")
        print(result["stdout"].decode("utf-8", "backslashreplace"), end="", flush=True)
    else:
        # Both genuine controls must stop at the unchanged first
        # decoder witness, before the supplied class can execute.
        common.require("command_result" not in fields, "A control returned command output")
        report["cases"].append(case)
    common.write_json(report_path, report)


def run_comparison(args, command, expected_stdout, out, report, report_path):
    """Send identical bytes to both controls and the affected node, each owned by run_case()."""
    lab = prepare_comparison(args, command, out, report)
    case_args = SimpleNamespace(gc_stress=False, requests_per_node=1,
                                startup_timeout=1800, request_timeout=600, gc_timeout=120)
    common.write_json(report_path, report)
    for index, (role, home) in enumerate((("disabled", lab.affected), ("fixed", lab.fixed), ("affected", lab.affected)), 1):
        processes.cancellation_checkpoint()
        case_dir = out / f"{index:02d}-{role}"
        runtime = report["runtimes"]["fixed" if role == "fixed" else "affected"]
        report["active_case"] = role
        common.write_json(report_path, report)
        # run_case owns the node's process tree, verifies the first
        # corruption witness and restoration checks, and shuts the node
        # down before returning its comparison result.
        case = es7.run_case(case_dir, lab.server, home, role, args.major, lab.sde, lab.payload,
                            [lab.marker], runtime, case_args)
        check_case_result(case, case_dir, role, lab.marker, expected_stdout, report, report_path)


def main(argv=None):
    """Compare identical command bytes on owned affected, intrinsic-disabled and fixed nodes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", type=int, choices=(17, 21), required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-stdout-base64", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    expected_stdout = base64.b64decode(args.expect_stdout_base64, validate=True)
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / ".validation-local") or out == ROOT / ".validation-local":
        parser.error("--output must be a new directory below .validation-local")
    out.mkdir(parents=True, exist_ok=False)
    report = {"status": "running", "started": datetime.now(timezone.utc).isoformat(),
              "java_major": args.major, "argv": command, "cases": [],
              "expected_stdout_base64": base64.b64encode(expected_stdout).decode("ascii"),
              "comparison_sha256": common.digest(__file__),
              "command_payload_sha256": common.digest(ROOT / "java4shell/command.py"),
              "support_sha256": {str(path.relative_to(ROOT)): common.digest(path)
                                 for path in sorted((ROOT / "java4shell").rglob("*"))
                                 if path.is_file() and path.suffix in (".py", ".template")},
              "reviewed_runner_sha256": common.digest(ROOT / "run_es7.py")}
    report_path = out / "report.json"
    previous = None
    code = 1
    with processes.managed_signals():
        try:
            common.require(report["reviewed_runner_sha256"] == "b5928611369aebea444f7e9a7dd26841f0775d321ae111c00b8d4779588c9887",
                        "Reviewed application runner changed")
            processes.require_pidfd_support()
            previous = processes.set_subreaper(True)
            common.require(os.geteuid() != 0, "Elasticsearch requires a non-root account")
            run_comparison(args, command, expected_stdout, out, report, report_path)
            report["status"] = "passed"
            code = 0
        except KeyboardInterrupt as error:
            report.update(status="interrupted", error=str(error), interruption=processes.interruption_details(error))
            code = 128 + report["interruption"]["signal"]
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            report.update(status="failed", error=type(error).__name__ + ": " + str(error))
            code = 1
        finally:
            if previous is not None:
                processes.set_subreaper(previous)
            report["finished"] = datetime.now(timezone.utc).isoformat()
            common.write_json(report_path, report)
    print(json.dumps({"status": report["status"], "report": str(report_path),
                      "error": report.get("error")}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
