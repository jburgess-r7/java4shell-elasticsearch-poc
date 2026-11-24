#!/usr/bin/env python3
"""Compare the bytecode PoC on owned affected, disabled-intrinsic and fixed JVMs.

Flow: authenticate local releases -> prepare one isolated node -> warm up ->
send the same supplied class -> check exact proof and fresh scripts -> shut down.
run_case() is also used by validate_command.py for its command comparison.
The public existing-target client is exploit.py and does not import this runner.

Process ownership lives in java4shell.processes; optional GC work lives in
java4shell.gc. See docs/code-guide.md for the source map and failure contracts.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

from java4shell import bytecode, common, es7, gc, processes


def post_request_checks(endpoint, process, conf, identity, label, out):
    """Run fresh allowed/forbidden scripts against the same owned node.

    These are behavioral checks, not a read-back of every modified JVM field."""
    prefix = "// independent post-trigger check " + label + "\n"
    post = {"allowed": endpoint.execute(prefix + es7.SMALL),
            "string": endpoint.execute(prefix + "return 'post-restore'.substring(5);"),
            "denied": endpoint.execute(prefix + es7.DENIED),
            "root": endpoint.request("GET", "/"),
            "security": endpoint.request("GET", "/_xpack/usage?filter_path=security.enabled,security.available"),
            "process": es7.owned_java(process.pid, conf, identity)}
    common.write_json(out / "post-checks.json", post)
    common.require(es7.result(post["allowed"]) == "3" and es7.result(post["string"]) == "restore",
            "Fresh allowed Painless scripts failed after the trigger")
    common.require(post["denied"]["status"] == 400 and
            "cannot resolve symbol [Runtime]" in json.dumps(post["denied"]["body"]),
            "Fresh forbidden Painless script was not rejected")
    common.require(post["root"]["status"] == 200 and
            post["root"]["body"].get("version", {}).get("build_hash") == es7.REVISION,
            "The genuine server did not remain available")
    common.require(post["security"]["body"].get("security", {}).get("enabled") is False,
            "The licensed security state changed")
    common.require(post["process"]["pid"] == identity["pid"] and
            post["process"]["linux_sandbox"] == identity["linux_sandbox"],
            "The server process or Linux sandbox changed")
    return post


def gc_counters(endpoint, expected_node_id=None):
    response = endpoint.request("GET", "/_nodes/_local/stats/jvm")
    common.require(response["status"] == 200, "The owned node's JVM statistics are unavailable")
    return gc.extract_local_gc_counters(response["body"], expected_node_id)


def logged_gc_overlap(case_out, identity, started, finished):
    cycles = gc.parse_completed_mark_cycles((case_out / "gc.log").read_text(errors="replace"),
                                         identity["pid"])
    return gc.overlapping_mark_cycles(cycles, started, finished)


def exercise_request(out, case_out, endpoint, process, conf, identity, home,
                     runtime, role, payload, marker_spec, ordinal, args):
    """Send one supplied class and verify its exact proof.

    out holds this request; case_out holds the node. Finalize any GC worker
    even when HTTP, timing or report operations fail. Preserve the original
    request error separately from cleanup errors and never turn either into a pass."""
    # Repeated requests need distinct compiled scripts as well as distinct
    # marker classes; otherwise a cached call site can retain an earlier class.
    source = bytecode.fresh_script_source(payload, ordinal) if args.requests_per_node > 1 else payload
    marker = out / "execution-marker"
    params = {"marker_path": str(marker), "marker_text": es7.MARKER_TEXT.decode(),
              "marker_return": marker_spec["marker_return"],
              "marker_class": base64.b64encode(marker_spec["bytes"]).decode()}
    report = {"ordinal": ordinal, "status": "running",
              "request_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "server_pid": identity["pid"], "server_start_ticks": identity["start_ticks"],
              "marker_class": marker_spec["binary_name"],
              "marker_class_sha256": marker_spec["sha256"],
              "marker_return": marker_spec["marker_return"]}
    common.write_json(out / "request.json", report)
    try:
        common.require(not marker.exists() and not Path(str(marker) + ".denied").exists(),
                "A marker already exists before execution")
        before = gc_counters(endpoint)
        report["gc_before"] = before
        collector = (gc.GCInvocation(process, conf, identity, home, runtime, out,
                                  args.gc_timeout)
                     if args.gc_stress and ordinal > 1 else None)

        def sent():
            report["http_request_sent"] = common.utc_now()
            report["http_request_sent_monotonic_ns"] = time.monotonic_ns()
            common.write_json(out / "request.json", report)
            if collector is not None:
                collector.request_sent()

        report["trigger_started"] = common.utc_now()
        common.write_json(out / "request.json", report)
        trigger_error = None
        timing_error = None
        cleanup_error = None

        def cleanup_failed(error):
            nonlocal cleanup_error
            if cleanup_error is None:
                cleanup_error = error
            text = type(error).__name__ + ": " + str(error)
            report.setdefault("gc_cleanup_errors", []).append(text)
            report.setdefault("gc_cleanup_error", text)

        try:
            processes.cancellation_checkpoint()
            if collector is not None:
                collector.start()
            trigger = endpoint.execute(source, params, args.request_timeout, on_sent=sent)
        except BaseException as error:
            trigger_error = error
            report["trigger_error"] = type(error).__name__ + ": " + str(error)
        finally:
            try:
                report["trigger_finished"] = common.utc_now()
                report["trigger_finished_monotonic_ns"] = time.monotonic_ns()
            except BaseException as error:
                timing_error = error
                report["timing_error"] = type(error).__name__ + ": " + str(error)
            finally:
                # Once start has been attempted, finalization is mandatory.
                # Even timestamp/reporting failures must not skip this worker.
                if collector is not None:
                    try:
                        if (trigger_error is not None or timing_error is not None or
                                processes.cancellation_pending() is not None):
                            collector.cancel()
                    except BaseException as error:
                        cleanup_failed(error)
                    finally:
                        try:
                            report["gc_command"] = collector.finish()
                        except BaseException as error:
                            cleanup_failed(error)
                        finally:
                            report.setdefault("gc_command", dict(collector.report))
        if trigger_error is not None:
            raise trigger_error
        if timing_error is not None:
            raise timing_error
        if cleanup_error is not None:
            raise cleanup_error
        processes.cancellation_checkpoint()
        common.write_json(out / "request.json", report)
        common.write_json(out / "trigger.json", trigger)
        marker_data = marker.read_bytes() if marker.exists() else None
        report["proof"] = es7.validate_result(es7.result(trigger), role, marker_data,
                                           Path(str(marker) + ".denied").exists(),
                                           marker_spec["marker_return"],
                                           marker_spec["binary_name"])
        after = gc_counters(endpoint, before["node_id"])
        report["gc_after"] = after
        report["gc_delta"] = gc.gc_counter_deltas(before, after)
        report["request_timing"] = gc.validate_request_timing(
            report["http_request_sent"], report["trigger_finished"],
            report["http_request_sent_monotonic_ns"],
            report["trigger_finished_monotonic_ns"])
        report["concurrent_mark_overlap"] = logged_gc_overlap(
            case_out, identity, report["http_request_sent"], report["trigger_finished"])
        # This establishes overlap with the HTTP request window. It does not
        # measure GC activity inside every temporary metadata-corruption window.
        if collector is not None:
            common.require(report["gc_command"]["status"] == "passed",
                    "The concurrent-GC diagnostic command failed")
            if role == "affected":
                common.require(bool(report["concurrent_mark_overlap"]),
                        "A completed concurrent mark cycle did not overlap the affected request")
        post_request_checks(endpoint, process, conf, identity,
                            case_out.name + "-" + str(ordinal), out)
        report.update(status="passed", post_checks_passed=True)
    except BaseException as error:
        report.update(status="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                      error=type(error).__name__ + ": " + str(error))
        if isinstance(error, KeyboardInterrupt):
            report["interruption"] = processes.interruption_details(error)
        raise
    finally:
        common.write_json(out / "request.json", report)
    return {"ordinal": ordinal, "status": "passed", "proof": report["proof"],
            "post_checks_passed": True, "gc_delta": report["gc_delta"],
            "concurrent_mark_overlap": report["concurrent_mark_overlap"],
            "report": str(out / "request.json"),
            "report_sha256": common.digest(out / "request.json")}


def prepare_case(out, server, home, role, sde, port, gc_stress=False):
    """Copy stock configuration into a new case directory and bind a loopback node.

    Return configuration, environment, launcher argv and JVM options. Only the
    disabled control changes UseBASE64Intrinsics; no Painless policy is relaxed."""
    # Each case gets fresh data and configuration. Keep the publisher's
    # security defaults while configuring an isolated loopback node and the
    # JVM options required by the selected comparison.
    out.mkdir()
    conf = out / "config"
    shutil.copytree(server / "config", conf)
    for name in ("data", "logs", "tmp"):
        (out / name).mkdir()
    original = (conf / "elasticsearch.yml").read_text()
    common.require(not re.search(r"(?m)^\s*xpack\.security\.enabled\s*:", original),
            "Publisher configuration contains an unexpected explicit security setting")
    with (conf / "elasticsearch.yml").open("a") as stream:
        stream.write("\ncluster.name: base64-es7-lab\nnode.name: base64-es7-lab\n"
                     "network.host: 127.0.0.1\nhttp.port: " + str(port) +
                     "\ntransport.port: 0\ndiscovery.type: single-node\npath.data: " +
                     str(out / "data") + "\npath.logs: " + str(out / "logs") + "\n")
    options = es7.common_jvm_options(out, gc_stress)
    if role == "disabled":
        options.append("-XX:-UseBASE64Intrinsics")
    env = common.clean_environment()
    env.update(ES_JAVA_HOME=str(home), ES_PATH_CONF=str(conf),
               ES_JAVA_OPTS=" ".join(options), ES_TMPDIR=str(out / "tmp"))
    command = [str(server / "bin/elasticsearch")]
    if sde:
        command = [str(sde), "-icx", "-follow-subprocess", "--", "/bin/bash", *command]
    return conf, env, command, options


def run_case(out, server, home, role, major, sde, payload, markers, runtime, args):
    """Own the entire node lifetime, including cancellation during launch/shutdown."""
    with processes.managed_signals():
        return _run_case(out, server, home, role, major, sde, payload, markers, runtime, args)


def _run_case(out, server, home, role, major, sde, payload, markers, runtime, args):
    """Start one node, verify its identity, exercise requests and always shut it down.

    A successful return requires both proof verification and ordinary cleanup.
    Reports retain the primary failure and any separate cleanup failure. The
    caller owns the subreaper setting; this function owns the node and pidfds."""
    processes.cancellation_checkpoint()
    port = es7.unused_port()
    conf, env, command, options = prepare_case(out, server, home, role, sde, port,
                                               args.gc_stress)
    report = {"role": role, "status": "running", "port": port, "command": command,
              "jvm_options": options, "authorization_header_sent": False,
              "explicit_security_setting": False, "runtime": runtime,
              "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
              "requests": [], "requests_per_node": len(markers),
              "gc_profile": "explicit-concurrent" if args.gc_stress else "ordinary",
              "marker_classes": [{key: value for key, value in marker.items() if key != "bytes"}
                                 for marker in markers]}
    common.write_json(out / "report.json", report)
    failure = None
    interrupted = None
    actual = None
    process = None
    identities, cleanup_errors = processes.OwnedProcesses(), []
    report.update(returncode_before_shutdown=None, returncode=None,
                  forced_cleanup=False, owned_processes_exited=True,
                  remaining_owned_pids=[])
    print("Starting " + out.name, flush=True)
    with (out / "stdout.log").open("wb") as stdout, (out / "stderr.log").open("wb") as stderr:
        try:
            processes.cancellation_checkpoint()
            process = subprocess.Popen(command, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            report.update(launcher_pid=process.pid, owned_processes_exited=False,
                          remaining_owned_pids=None)
            identities.remember(process.pid, processes.process_start_ticks(process.pid), process.pid)
            processes.cancellation_checkpoint()
            processes.refresh_owned(process.pid, identities)
            common.write_json(out / "report.json", report)
            deadline = time.monotonic() + args.startup_timeout
            while time.monotonic() < deadline:
                processes.cancellation_checkpoint()
                processes.refresh_owned(process.pid, identities)
                common.require(process.poll() is None, "Elasticsearch exited during startup")
                try:
                    actual = es7.owned_java(process.pid, conf)
                    common.require(actual["executable_sha256"] == runtime["java_sha256"],
                            "The owned server uses an unexpected Java executable")
                    if not es7.owns_listener(actual["pid"], port):
                        raise es7.NotReady("Owned HTTP listener is not ready")
                    endpoint = es7.OwnedEndpoint(process, conf, actual, port)
                    root = endpoint.request("GET", "/", timeout=15)
                    if root["status"] == 200:
                        break
                    common.require(root["status"] != 401, "The stock endpoint requires authentication")
                except (es7.NotReady, OSError, http.client.HTTPException):
                    pass
                time.sleep(0.25)
            else:
                raise RuntimeError("Owned Elasticsearch did not become ready")
            version = root["body"].get("version", {})
            common.require(version.get("number") == es7.VERSION and version.get("build_hash") == es7.REVISION,
                    "The HTTP service is not the pinned publisher release")
            security_args = [value for value in actual["argv"] if value.startswith("-Djava.security.manager")]
            expected_security_args = [] if major == 17 else ["-Djava.security.manager=allow"]
            common.require(security_args == expected_security_args, "Publisher launcher SecurityManager policy differs")
            common.require(actual["linux_sandbox"].get("Seccomp") == "2", "The genuine process has no seccomp filter")
            report["server_process"] = actual
            report["root"] = root
            report["cluster_settle"] = es7.wait_for_cluster(endpoint, out, args.startup_timeout)
            license_deadline = time.monotonic() + 120
            while True:
                license_reply = endpoint.request("GET", "/_license")
                if license_reply["status"] != 404 or time.monotonic() >= license_deadline:
                    break
                time.sleep(0.5)
            security = endpoint.request("GET", "/_xpack/usage?filter_path=security.enabled,security.available")
            common.require(license_reply["body"].get("license", {}).get("type") == "basic",
                    "Expected a fresh Basic license")
            common.require(security["body"].get("security", {}).get("enabled") is False,
                    "The actual default licensed security state differs")
            common.require(es7.result(endpoint.execute(es7.SMALL)) == "3", "Valid Base64 control failed")
            denied = endpoint.execute(es7.DENIED)
            common.require(denied["status"] == 400 and "cannot resolve symbol [Runtime]" in json.dumps(denied["body"]),
                    "The normal Painless host-operation control was not denied")
            report["preconditions"] = {"license": license_reply, "security": security,
                                       "denied_host_operation": denied, "listener_owned": True}
            common.write_json(out / "report.json", report)
            for _ in range(20):
                common.require(es7.result(endpoint.execute(es7.WARMUP, timeout=args.request_timeout)) == "288750",
                        "Decoder warmup result differs")
            for ordinal, marker_spec in enumerate(markers, 1):
                request_out = out if len(markers) == 1 else out / f"request-{ordinal:03d}"
                if request_out != out:
                    request_out.mkdir()
                report["active_request"] = ordinal
                report["trigger_started"] = common.utc_now()
                common.write_json(out / "report.json", report)
                request_report = exercise_request(request_out, out, endpoint, process,
                                                  conf, actual, home, runtime, role,
                                                  payload, marker_spec, ordinal, args)
                report["requests"].append(request_report)
                report["proof"] = request_report["proof"]
                common.write_json(out / "report.json", report)
                print(out.name + ": request " + str(ordinal) + " passed", flush=True)
            report["post_checks_passed"] = True
        except KeyboardInterrupt as error:
            interrupted = error
            failure = str(error) or "Interrupted by SIGINT"
        except Exception as error:
            failure = type(error).__name__ + ": " + str(error)
        finally:
            if process is not None:
                if actual is not None:
                    try:
                        identities.remember(actual["pid"], actual["start_ticks"], process.pid)
                    except KeyboardInterrupt as error:
                        interrupted = error
                        if failure is None:
                            failure = str(error) or "Interrupted by SIGINT"
                    except Exception as error:
                        cleanup_errors.append("Server identity: " + type(error).__name__ + ": " + str(error))
                try:
                    processes.shutdown_case(process, identities, report, cleanup_errors)
                except KeyboardInterrupt as error:
                    interrupted = error
                    report["cleanup_interruption"] = str(error) or "Interrupted by SIGINT"
                    if failure is None:
                        failure = report["cleanup_interruption"]
                except Exception as error:
                    cleanup_failure = "Cleanup " + type(error).__name__ + ": " + str(error)
                    failure = failure + "; " + cleanup_failure if failure else cleanup_failure
            identities.close()
    if interrupted is None and processes.cancellation_pending() is not None:
        interrupted = processes.StopRequested(processes.cancellation_pending())
        if failure is None:
            failure = str(interrupted)
    if interrupted is not None:
        report["interruption"] = processes.interruption_details(interrupted)
    report["fatal_logs"] = [p.relative_to(out).as_posix()
                            for p in out.rglob("*hs_err_pid*.log")]
    if failure is None and (report["returncode_before_shutdown"] is not None or
                            report["forced_cleanup"] or cleanup_errors or report["fatal_logs"] or
                            not report["owned_processes_exited"]):
        failure = "The server did not survive through ordinary owned cleanup"
    report["status"] = "failed" if failure else "passed"
    if failure:
        report["error"] = failure
    common.write_json(out / "report.json", report)
    print(out.name + ": " + report["status"], flush=True)
    if interrupted is not None:
        raise interrupted
    if failure:
        raise RuntimeError(failure)
    return {"role": role, "status": "passed", "proof": report["proof"],
            "requests": report["requests"],
            "post_checks_passed": True, "report": str(out / "report.json"),
            "report_sha256": common.digest(out / "report.json")}


def main(argv=None):
    with processes.managed_signals() as cancellation:
        try:
            code = _main(argv)
            signum = processes.cancellation_pending()
            if signum is not None and code != 128 + signum:
                processes.cancellation_checkpoint()
        except KeyboardInterrupt as error:
            details = processes.interruption_details(error)
            print(json.dumps({"status": "interrupted", "report": None,
                              "reason": str(error) or "Interrupted by SIGINT",
                              "interruption": details}), flush=True)
            code = 128 + details["signal"]
    # The final report and terminal output still run under the record-only
    # handlers. Honor a signal received there before discarding their state.
    if cancellation.first_signum is not None:
        return 128 + cancellation.first_signum
    return code


def _main(argv=None):
    """Verify local prerequisites, compile the marker and run controls before positives."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--affected-jdk", type=Path, required=True,
                        help="Extracted pinned affected JDK home")
    parser.add_argument("--fixed-jdk", type=Path, required=True,
                        help="Extracted pinned fixed JDK home on the same Java major")
    parser.add_argument("--elasticsearch", type=Path, required=True,
                        help="Unmodified Elasticsearch 7.17.29 Linux x86-64 directory")
    parser.add_argument("--sde", type=Path, help="Explicit Intel SDE executable; uses the ICX model")
    parser.add_argument("--enabled-runs", type=int, default=2, choices=range(1, 11),
                        help="Number of fresh affected-runtime nodes, after both controls")
    parser.add_argument("--requests-per-node", type=int, default=1, metavar="N",
                        help="Sequential payload requests in each retained JVM (1–100)")
    parser.add_argument("--gc-stress", action="store_true",
                        help="Request concurrent G1 collection during requests after the first")
    parser.add_argument("--gc-timeout", type=int, default=120,
                        help="Timeout in seconds for each GC.run command")
    parser.add_argument("--startup-timeout", type=int, default=1800,
                        help="Timeout in seconds for each server startup phase")
    parser.add_argument("--request-timeout", type=int, default=600,
                        help="Timeout in seconds for each compilation or payload request")
    parser.add_argument("--preflight-only", action="store_true",
                        help="Check pinned releases and JVM settings without starting Elasticsearch")
    parser.add_argument("--output", type=Path, help="New evidence directory under .validation-local")
    args = parser.parse_args(argv)
    if min(args.startup_timeout, args.request_timeout, args.gc_timeout) <= 0:
        parser.error("Timeouts must be positive")
    if not 1 <= args.requests_per_node <= 100:
        parser.error("--requests-per-node must be between 1 and 100")
    if args.gc_stress and args.requests_per_node < 2:
        parser.error("--gc-stress requires --requests-per-node of at least 2")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    if common.SCRATCH.is_symlink():
        parser.error(".validation-local must not be a symlink")
    try:
        common.SCRATCH.mkdir(mode=0o700, exist_ok=True)
    except OSError as error:
        print(json.dumps({"status": "failed", "report": None,
                          "reason": type(error).__name__ + ": " + str(error)}), flush=True)
        return 1
    if not common.SCRATCH.is_dir() or common.SCRATCH.resolve().parent != common.ROOT:
        parser.error(".validation-local must be a directory inside this repository")
    out = (args.output or common.SCRATCH / ("es7-" + stamp)).resolve()
    if not out.is_relative_to(common.SCRATCH) or out == common.SCRATCH:
        parser.error("--output must be below this repository's .validation-local directory")
    if any(character.isspace() for character in str(out)):
        parser.error("The evidence path must not contain whitespace")
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error("--output must name a new directory: " + str(out))
    except OSError as error:
        print(json.dumps({"status": "failed", "report": None,
                          "reason": type(error).__name__ + ": " + str(error)}), flush=True)
        return 1
    report = {"cve": "CVE-2026-114938", "status": "running", "cases": [],
              "runner_sha256": common.digest(__file__), "evidence": str(out),
              "support_sha256": {name: common.digest(common.ROOT / name)
                                 for name in ("java4shell/common.py", "java4shell/processes.py",
                                              "java4shell/es7.py", "java4shell/bytecode.py",
                                              "java4shell/gc.py")},
              "requests_per_node": args.requests_per_node,
              "gc_profile": "explicit-concurrent" if args.gc_stress else "ordinary"}
    previous_subreaper = None
    try:
        processes.cancellation_checkpoint()
        if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
            raise common.Unavailable("The application proof currently supports Linux x86-64")
        if os.geteuid() == 0:
            raise common.Unavailable("Elasticsearch must be started by a non-root account")
        affected, fixed, server = (p.resolve(strict=True) for p in
                                   (args.affected_jdk, args.fixed_jdk, args.elasticsearch))
        sde = args.sde.resolve(strict=True) if args.sde else None
        processes.require_pidfd_support()
        previous_subreaper = processes.set_subreaper(True)
        flags = es7.cpu_flags()
        report["execution"] = {"mode": "intel-sde-icx" if sde else "native",
                               "host_missing_cpu_flags": sorted(es7.CPU_FLAGS - flags),
                               "sde_sha256": common.digest(sde) if sde else None}
        if not sde and not es7.CPU_FLAGS <= flags:
            raise common.Unavailable("Host lacks required CPU flags: " + ", ".join(sorted(es7.CPU_FLAGS - flags)))
        print("Checking pinned Java and Elasticsearch releases...", flush=True)
        pins = json.loads((common.ASSETS / "releases.json").read_text())
        major = int(es7.release_values(affected)["JAVA_VERSION"].split(".", 1)[0])
        if str(major) not in pins["runtimes"]:
            raise common.Unavailable("Only the pinned Java 17 and 21 pairs are supported")
        pair = pins["runtimes"][str(major)]
        report["java_major"] = major
        report["runtimes"] = {"affected": es7.runtime_identity(affected, pair["affected"]),
                              "fixed": es7.runtime_identity(fixed, pair["fixed"])}
        report["server"] = es7.verify_server(server, pins["elasticsearch"])
        payload_path = common.ASSETS / ("payload-java" + str(major) + ".painless")
        common.require(common.digest(payload_path) == pair["payload_sha256"], "Audited payload hash changed")
        source = common.ASSETS / "marker/org/elasticsearch/painless/OwnedBase64Marker.java"
        common.require(common.digest(source) == pins["marker_source_sha256"], "Marker source hash changed")
        classes = out / "classes"
        classes.mkdir()
        compilation = processes.run_bounded_command(
            [str(affected / "bin/javac"), "--release", str(major),
             "-g:none", "-d", str(classes), str(source)],
            out, args.request_timeout, out / "javac-process.json")
        (out / "javac.stdout").write_text(compilation.stdout)
        (out / "javac.stderr").write_text(compilation.stderr)
        common.require(compilation.returncode == 0, "Could not compile the request-supplied marker class")
        class_path = classes / "org/elasticsearch/painless/OwnedBase64Marker.class"
        common.require(common.digest(class_path) == pair["marker_class_sha256"], "Compiled marker class differs from the reviewed build")
        base_class = class_path.read_bytes()
        if args.requests_per_node == 1:
            markers = [{"binary_name": es7.MARKER_CLASS_NAME,
                        "internal_name": es7.MARKER_CLASS_NAME.replace(".", "/"),
                        "marker_return": es7.MARKER_RETURN, "bytes": base_class,
                        "sha256": pair["marker_class_sha256"]}]
        else:
            markers = [bytecode.derive_marker_class(base_class, pair["marker_class_sha256"], index)
                       for index in range(1, args.requests_per_node + 1)]
        print("Checking effective JVM settings...", flush=True)
        report["preflight"] = {
            "affected": es7.preflight_flags(affected, sde, out / "affected-flags", args.request_timeout, args.gc_stress),
            "fixed": es7.preflight_flags(fixed, sde, out / "fixed-flags", args.request_timeout, args.gc_stress)}
        common.write_json(out / "report.json", report)
        if args.preflight_only:
            processes.cancellation_checkpoint()
            report["status"] = "preflight-ok"
        else:
            payload = payload_path.read_text()
            # Run both negative controls first, with the same source and class
            # bytes, before counting any affected-runtime result as a success.
            jobs = [("disabled", affected), ("fixed", fixed)]
            jobs += [("affected", affected)] * args.enabled_runs
            for index, (role, home) in enumerate(jobs, 1):
                processes.cancellation_checkpoint()
                label = f"{index:02d}-{role}"
                runtime = report["runtimes"]["fixed" if role == "fixed" else "affected"]
                case = run_case(out / label, server, home, role, major, sde, payload,
                                markers, runtime, args)
                report["cases"].append(case)
                common.write_json(out / "report.json", report)
            report["status"] = "passed"
        code = 0
    except KeyboardInterrupt as error:
        details = processes.interruption_details(error)
        report.update(status="interrupted", reason=str(error) or "Interrupted by SIGINT",
                      interruption=details)
        code = 128 + details["signal"]
    except common.Unavailable as error:
        report.update(status="skipped", reason=str(error))
        code = 77
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=type(error).__name__ + ": " + str(error))
        code = 1
    finally:
        if previous_subreaper is not None:
            processes.set_subreaper(previous_subreaper)
    if processes.cancellation_pending() is not None and report["status"] != "interrupted":
        error = processes.StopRequested(processes.cancellation_pending())
        report.update(status="interrupted", reason=str(error),
                      interruption=processes.interruption_details(error))
        code = 128 + error.signum
    common.write_json(out / "report.json", report)
    print(json.dumps({"status": report["status"], "report": str(out / "report.json"),
                      "reason": report.get("reason", report.get("error"))}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
