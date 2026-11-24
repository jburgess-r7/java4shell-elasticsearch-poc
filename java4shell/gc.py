"""Optional G1 stress worker and strict GC-log interpretation.

GCInvocation owns one jcmd child. start() arms it, request_sent() releases it
after the HTTP body is sent, and finish() must always join and clean it up.
The parsing functions establish completed-cycle overlap with a request, not
collection during every temporary corruption window.
"""
from datetime import datetime, timezone
from decimal import Decimal
import re
import signal
import subprocess
import threading
import time

from . import common, es7, processes


class GcEvidenceError(ValueError):
    """The supplied evidence is incomplete, contradictory, or malformed."""


_ISO_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})"
)
_LOG_HEADER = re.compile(
    r"^\[(?P<time>[^\]]+)\]\[(?P<pid>\d+)\]"
    r"\[(?P<level>[^\]]+)\]\[(?P<tags>[^\]]+)\] (?P<message>.*)$"
)
_EVENT = re.compile(r"GC\((?P<id>\d+)\) Concurrent Mark (?P<kind>Cycle|Abort)(?P<suffix>.*)")
_DURATION = re.compile(r" (?P<millis>\d+(?:\.\d{1,3})?)ms")
_MARK_CYCLE_CLOCK_TOLERANCE_MICROSECONDS = 250000
_COUNTER_FIELDS = ("collection_count", "collection_time_in_millis")
_COLLECTORS = ("young", "old")
_OPTIONAL_COLLECTORS = ("G1 Concurrent GC",)


def _require(condition, message):
    if not condition:
        raise GcEvidenceError(message)


def _nonnegative_integer(value, label):
    _require(type(value) is int and value >= 0, label + " must be a nonnegative integer")
    return value


def _utc_datetime(value, label):
    if isinstance(value, str):
        _require(_ISO_TIME.fullmatch(value) is not None, label + " must be an aware ISO timestamp")
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        if re.search(r"[+-]\d{4}$", normalized):
            normalized = normalized[:-2] + ":" + normalized[-2:]
        try:
            value = datetime.fromisoformat(normalized)
        except ValueError as error:
            raise GcEvidenceError(label + " is not a valid timestamp") from error
    _require(isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None,
             label + " must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso_utc(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _microseconds(delta):
    return ((delta.days * 86400 + delta.seconds) * 1_000_000) + delta.microseconds


def _validate_mark_cycle_durations(elapsed, reported):
    _require(abs(elapsed - reported) <= _MARK_CYCLE_CLOCK_TOLERANCE_MICROSECONDS,
             "GC cycle UTC and reported durations differ by more than 250000 microseconds")


def validate_request_timing(request_start, request_end, monotonic_start_ns,
                            monotonic_end_ns, max_difference_microseconds=250000):
    """Validate a request's UTC interval against its monotonic clock interval.

    UTC elapsed time and both nanosecond values are exact integers. The
    whole-microsecond clock difference is rounded upward; the acceptance
    threshold is checked using the exact nanosecond difference. Monotonic
    clock readings may have either sign because their reference is undefined.
    """
    request_start = _utc_datetime(request_start, "request start")
    request_end = _utc_datetime(request_end, "request end")
    _require(request_end >= request_start, "Request end precedes its start")
    _require(type(monotonic_start_ns) is int and type(monotonic_end_ns) is int,
             "Monotonic clock readings must be integers")
    _require(monotonic_end_ns >= monotonic_start_ns, "Monotonic clock moved backwards")
    limit = _nonnegative_integer(max_difference_microseconds, "Maximum clock difference")
    elapsed = _microseconds(request_end - request_start)
    monotonic_elapsed = monotonic_end_ns - monotonic_start_ns
    difference = abs(elapsed * 1000 - monotonic_elapsed)
    _require(difference <= limit * 1000,
             "UTC and monotonic request durations differ beyond the allowed tolerance")
    return {"elapsed_microseconds": elapsed,
            "monotonic_elapsed_nanoseconds": monotonic_elapsed,
            "clock_difference_nanoseconds": difference,
            "clock_difference_microseconds": (difference + 999) // 1000}


def interval_overlap_microseconds(start, end, window_start, window_end):
    """Return the exact positive intersection of two aware, half-open intervals."""
    start, end = _utc_datetime(start, "interval start"), _utc_datetime(end, "interval end")
    window_start = _utc_datetime(window_start, "window start")
    window_end = _utc_datetime(window_end, "window end")
    _require(end >= start, "Interval end precedes its start")
    _require(window_end >= window_start, "Window end precedes its start")
    return max(0, _microseconds(min(end, window_end) - max(start, window_start)))


def parse_completed_mark_cycles(log_text, expected_pid):
    """Pair this PID's G1 mark-cycle boundaries, excluding unpaired edges.

    The UTC decorations determine each bounded log interval. HotSpot's
    separately reported duration is retained. Their absolute difference must
    be at most 250000 microseconds, limiting evidence distorted by wall-clock
    changes. A matching logged abort marks the interval as aborted; absence
    of that event does not prove coverage of every marking phase. Supply
    rotated logs in chronological order.
    """
    _require(isinstance(log_text, str), "GC log must be text")
    _require(type(expected_pid) is int and expected_pid > 0, "Expected PID must be a positive integer")
    pending, seen_starts, seen_ends, seen_aborts, completed = {}, set(), set(), set(), []
    previous_time = None
    for line_number, line in enumerate(log_text.splitlines(), 1):
        if "Concurrent Mark Cycle" not in line and "Concurrent Mark Abort" not in line:
            continue
        header = _LOG_HEADER.fullmatch(line)
        if header is None:
            if "[" + str(expected_pid) + "]" in line:
                raise GcEvidenceError(f"Malformed mark-cycle header on line {line_number}")
            continue
        if int(header["pid"]) != expected_pid:
            continue
        event = _EVENT.fullmatch(header["message"])
        _require(event is not None, f"Malformed mark-cycle event on line {line_number}")
        tags = {tag.strip() for tag in header["tags"].split(",")}
        allowed_tags = ({"gc"}, {"gc", "marking"}) if event["kind"] == "Abort" else ({"gc"},)
        _require(header["level"].strip() == "info" and tags in allowed_tags,
                 f"Unexpected mark-cycle decorators on line {line_number}")
        stamp = _utc_datetime(header["time"], f"GC timestamp on line {line_number}")
        _require(previous_time is None or stamp >= previous_time,
                 f"GC timestamps moved backwards on line {line_number}")
        previous_time = stamp
        gc_id, suffix = int(event["id"]), event["suffix"]
        if event["kind"] == "Abort":
            _require(not suffix, f"Malformed GC({gc_id}) abort")
            _require(gc_id not in seen_aborts and gc_id not in seen_ends,
                     f"Duplicate or out-of-order GC({gc_id}) abort")
            seen_aborts.add(gc_id)
            continue
        if not suffix:
            _require(gc_id not in seen_starts and gc_id not in seen_ends and gc_id not in seen_aborts,
                     f"Duplicate or out-of-order GC({gc_id}) start")
            seen_starts.add(gc_id)
            pending[gc_id] = stamp
            continue
        duration = _DURATION.fullmatch(suffix)
        _require(duration is not None, f"Malformed GC({gc_id}) end duration")
        _require(gc_id not in seen_ends, f"Duplicate GC({gc_id}) end")
        seen_ends.add(gc_id)
        if gc_id not in pending:
            # Its start may have been in a discarded rotated log. An end by
            # itself cannot establish overlap with a request.
            continue
        start = pending.pop(gc_id)
        _require(stamp >= start, f"GC({gc_id}) ended before its start")
        elapsed = _microseconds(stamp - start)
        reported = int(Decimal(duration["millis"]) * 1000)
        _validate_mark_cycle_durations(elapsed, reported)
        completed.append({
            "pid": expected_pid,
            "gc_id": gc_id,
            "start_utc": _iso_utc(start),
            "end_utc": _iso_utc(stamp),
            "elapsed_microseconds": elapsed,
            "reported_duration_microseconds": reported,
            "aborted": gc_id in seen_aborts,
        })
    return completed


def overlapping_mark_cycles(cycles, request_start, request_end, include_aborted=False):
    """Return completed cycle intervals with their exact request intersection.

    Each cycle's UTC and HotSpot-reported duration must agree within 250000
    microseconds, including records supplied directly by the caller.
    """
    request_start = _utc_datetime(request_start, "request start")
    request_end = _utc_datetime(request_end, "request end")
    _require(request_end >= request_start, "Request end precedes its start")
    _require(type(include_aborted) is bool, "include_aborted must be a boolean")
    _require(isinstance(cycles, (list, tuple)), "Completed cycles must be a sequence")
    seen, previous_start, result = set(), None, []
    for cycle in cycles:
        _require(isinstance(cycle, dict), "Completed cycle must be an object")
        pid = _nonnegative_integer(cycle.get("pid"), "Cycle PID")
        _require(pid > 0, "Cycle PID must be positive")
        gc_id = _nonnegative_integer(cycle.get("gc_id"), "GC id")
        key = (pid, gc_id)
        _require(key not in seen, "Duplicate completed cycle")
        seen.add(key)
        start = _utc_datetime(cycle.get("start_utc"), "cycle start")
        end = _utc_datetime(cycle.get("end_utc"), "cycle end")
        _require(end >= start, "Cycle end precedes its start")
        _require(previous_start is None or start >= previous_start, "Completed cycles are out of order")
        previous_start = start
        elapsed = _nonnegative_integer(cycle.get("elapsed_microseconds"), "Cycle elapsed time")
        _require(elapsed == _microseconds(end - start), "Cycle elapsed time differs from its timestamps")
        reported = _nonnegative_integer(cycle.get("reported_duration_microseconds"),
                                        "Reported cycle duration")
        _validate_mark_cycle_durations(elapsed, reported)
        _require(type(cycle.get("aborted")) is bool, "Cycle aborted state must be a boolean")
        overlap_start, overlap_end = max(start, request_start), min(end, request_end)
        if overlap_end > overlap_start and (include_aborted or not cycle["aborted"]):
            result.append(dict(cycle,
                               overlap_start_utc=_iso_utc(overlap_start),
                               overlap_end_utc=_iso_utc(overlap_end),
                               overlap_microseconds=_microseconds(overlap_end - overlap_start)))
    return result


def _validated_snapshot(snapshot):
    _require(isinstance(snapshot, dict), "GC snapshot must be an object")
    node_id = snapshot.get("node_id")
    _require(isinstance(node_id, str) and bool(node_id), "GC snapshot needs a node id")
    collectors = snapshot.get("collectors")
    _require(isinstance(collectors, dict) and set(_COLLECTORS) <= set(collectors)
             <= set(_COLLECTORS + _OPTIONAL_COLLECTORS),
             "Expected the supported G1 collectors")
    values = {}
    for name in _COLLECTORS + _OPTIONAL_COLLECTORS:
        if name not in collectors:
            continue
        current = collectors[name]
        _require(isinstance(current, dict), name + " collector must be an object")
        values[name] = {field: _nonnegative_integer(current.get(field), name + "." + field)
                        for field in _COUNTER_FIELDS}
    return {"node_id": node_id,
            "timestamp": _nonnegative_integer(snapshot.get("timestamp"), "JVM timestamp"),
            "uptime_in_millis": _nonnegative_integer(snapshot.get("uptime_in_millis"), "JVM uptime"),
            "collectors": values}


def extract_local_gc_counters(nodes_stats_body, expected_node_id=None):
    """Validate a decoded ``/_nodes/_local/stats/jvm`` response body."""
    _require(isinstance(nodes_stats_body, dict), "Nodes stats body must be an object")
    summary = nodes_stats_body.get("_nodes")
    _require(isinstance(summary, dict), "Nodes stats response has no node summary")
    for key, expected in (("total", 1), ("successful", 1), ("failed", 0)):
        _require(_nonnegative_integer(summary.get(key), "_nodes." + key) == expected,
                 "Nodes stats response is not one successful local node")
    if "failures" in summary:
        _require(isinstance(summary["failures"], list) and not summary["failures"],
                 "Nodes stats response contains node failures")
    nodes = nodes_stats_body.get("nodes")
    _require(isinstance(nodes, dict) and len(nodes) == 1, "Expected one local node's stats")
    node_id, node = next(iter(nodes.items()))
    _require(isinstance(node_id, str) and bool(node_id), "Nodes stats response has an invalid node id")
    if expected_node_id is not None:
        _require(isinstance(expected_node_id, str) and bool(expected_node_id), "Expected node id is invalid")
        _require(node_id == expected_node_id, "Nodes stats response came from a different node")
    _require(isinstance(node, dict) and isinstance(node.get("jvm"), dict), "Local node has no JVM stats")
    jvm = node["jvm"]
    _require(isinstance(jvm.get("gc"), dict), "Local node has no JVM GC stats")
    return _validated_snapshot({"node_id": node_id, "timestamp": jvm.get("timestamp"),
                                "uptime_in_millis": jvm.get("uptime_in_millis"),
                                "collectors": jvm["gc"].get("collectors")})


def gc_counter_deltas(before, after):
    """Calculate deltas only for the same node and nondecreasing snapshots."""
    before, after = _validated_snapshot(before), _validated_snapshot(after)
    _require(before["node_id"] == after["node_id"], "GC snapshots belong to different nodes")
    _require(before["collectors"].keys() == after["collectors"].keys(), "GC collector set changed")
    result = {"node_id": before["node_id"], "collectors": {}}
    for field, output in (("timestamp", "timestamp_delta_millis"),
                          ("uptime_in_millis", "uptime_delta_millis")):
        delta = after[field] - before[field]
        _require(delta >= 0, field + " moved backwards")
        result[output] = delta
    for name in before["collectors"]:
        result["collectors"][name] = {}
        for field in _COUNTER_FIELDS:
            delta = after["collectors"][name][field] - before["collectors"][name][field]
            _require(delta >= 0, name + "." + field + " moved backwards")
            result["collectors"][name][field] = delta
    return result


class GCInvocation:
    """Issue one bounded diagnostic command to the attested local JVM."""

    def __init__(self, process, conf, identity, home, runtime, out, timeout):
        self.process, self.conf, self.identity = process, conf, identity
        self.home, self.runtime, self.out, self.timeout = home, runtime, out, timeout
        self.gate, self.sent = threading.Event(), threading.Event()
        self.cancelled, self.entered = threading.Event(), threading.Event()
        self.finished = threading.Event()
        self.lock = threading.Lock()
        self.child, self.child_identities = None, processes.OwnedProcesses()
        self._identities_closed = False
        self.cleanup_errors = []
        self.termination_requested = False
        self.start_attempted = False
        self.report = {"status": "waiting", "target_pid": identity["pid"]}
        self.thread = threading.Thread(target=self._run, name="owned-jvm-gc", daemon=True)

    def start(self):
        common.require(not self._identities_closed, "The GC.run worker was already finalized")
        self.start_attempted = True
        try:
            self.thread.start()
        except BaseException:
            self.cancelled.set()
            self.gate.set()
            raise

    def request_sent(self):
        # Release GC.run only after the complete HTTP request has been sent.
        # The GC log later establishes whether a completed cycle overlapped it.
        self.sent.set()
        self.gate.set()

    def cancel(self):
        self.cancelled.set()
        self.gate.set()

    def _terminate_child(self):
        with self.lock:
            if self._identities_closed:
                common.require(self.thread.ident is None or
                        (self.finished.is_set() and not self.thread.is_alive()),
                        "GC.run process handles closed before worker cleanup")
                return
            if self.child is not None:
                self.termination_requested = True
                processes.signal_owned_or_child(self.child, self.child_identities, signal.SIGKILL,
                                      self.cleanup_errors)

    def _close_identities(self):
        with self.lock:
            if (not self._identities_closed and
                    (self.thread.ident is None or
                     (self.finished.is_set() and not self.thread.is_alive()))):
                self.child_identities.close()
                self._identities_closed = True

    def _wait_finished(self, timeout):
        deadline = time.monotonic() + timeout
        terminated = False
        while not self.finished.is_set():
            if not terminated and (self.cancelled.is_set() or processes.cancellation_pending() is not None):
                self.cancel()
                self._terminate_child()
                terminated = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self.finished.wait(min(0.1, remaining))
        return True

    def _cancel_and_join(self):
        self.cancel()
        self._terminate_child()
        if self.thread.ident is None:
            return
        common.require(self._wait_finished(35), "The interrupted GC.run worker did not finish cleanup")
        self.thread.join(5)
        common.require(not self.thread.is_alive(), "The interrupted GC.run worker did not stop")

    def _run(self):
        self.entered.set()
        try:
            self._run_command()
        finally:
            self.finished.set()

    def _run_command(self):
        self.gate.wait()
        if not self.sent.is_set() or self.cancelled.is_set() or processes.cancellation_pending() is not None:
            self.report["status"] = "not-started"
            return
        stdout_path, stderr_path = self.out / "jcmd.stdout", self.out / "jcmd.stderr"
        forced = False
        try:
            current = es7.owned_java(self.process.pid, self.conf, self.identity)
            common.require(current["pid"] > 0, "Invalid diagnostic target PID")
            executable = self.home / "bin/jcmd"
            common.require(common.digest(executable) == self.runtime["jcmd_sha256"],
                    "The selected jcmd executable changed")
            command = [str(executable), "-J-XX:-CreateCoredumpOnCrash",
                       "-J-XX:-HeapDumpOnOutOfMemoryError",
                       "-J-XX:ErrorFile=" + str(self.out / "jcmd_hs_err_pid%p.log"),
                       str(current["pid"]), "GC.run"]
            self.report.update(command=command, started=common.utc_now(),
                               jcmd_sha256=self.runtime["jcmd_sha256"])
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                with self.lock:
                    common.require(not self.cancelled.is_set() and processes.cancellation_pending() is None,
                            "The GC.run command was cancelled")
                    self.child = subprocess.Popen(command, cwd=self.out, env=common.clean_environment(),
                                                  stdin=subprocess.DEVNULL, stdout=stdout,
                                                  stderr=stderr, start_new_session=True)
                    self.child_identities.remember(self.child.pid,
                                                   processes.process_start_ticks(self.child.pid), self.child.pid)
                    processes.refresh_owned(self.child.pid, self.child_identities)
                try:
                    self.child.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    forced = True
                    self._terminate_child()
                    self.child.wait(timeout=30)
                    raise RuntimeError("The owned GC.run command timed out")
            self.report["returncode"] = self.child.returncode
            common.require(self.child.returncode == 0 and
                    "Command executed successfully" in stdout_path.read_text(errors="replace"),
                    "The owned GC.run command did not succeed")
            self.report["status"] = "passed"
        except Exception as error:
            self.report.update(status="failed", error=type(error).__name__ + ": " + str(error))
        finally:
            if self.child is not None:
                try:
                    if self.child.poll() is None:
                        forced = True
                        self._terminate_child()
                        self.child.wait(timeout=30)
                    with self.lock:
                        remaining = processes.remaining_owned_or_unknown(self.child, self.child_identities,
                                                               self.cleanup_errors)
                    if remaining is None or remaining:
                        forced = True
                        self._terminate_child()
                        deadline = time.monotonic() + 5
                        while remaining and time.monotonic() < deadline:
                            time.sleep(0.05)
                            with self.lock:
                                remaining = processes.remaining_owned_or_unknown(
                                    self.child, self.child_identities, self.cleanup_errors)
                        if remaining is None:
                            with self.lock:
                                remaining = processes.remaining_owned_or_unknown(
                                    self.child, self.child_identities, self.cleanup_errors)
                    self.report["owned_processes_exited"] = remaining is not None and not remaining
                    common.require(self.report["owned_processes_exited"],
                            "An owned GC.run descendant did not exit or could not be checked")
                except Exception as error:
                    self.report.update(status="failed", cleanup_error=type(error).__name__ + ": " + str(error))
                self.report["returncode"] = self.child.returncode
            forced = forced or self.termination_requested
            self.report["forced_cleanup"] = forced
            if self.cleanup_errors:
                self.report["cleanup_errors"] = self.cleanup_errors
            if self.report["status"] == "passed" and (
                    forced or self.cleanup_errors or
                    self.report.get("owned_processes_exited") is not True):
                self.report.update(status="failed",
                                   error="GC.run did not finish through ordinary owned cleanup")
            self.report["finished"] = common.utc_now()
            for path in (stdout_path, stderr_path):
                if not path.exists():
                    path.write_text("")
            self.report["stdout_sha256"] = common.digest(stdout_path)
            self.report["stderr_sha256"] = common.digest(stderr_path)
            common.write_json(self.out / "jcmd.json", self.report)

    def finish(self):
        try:
            if not self.sent.is_set():
                self.cancel()
            self.gate.set()
            if not self.start_attempted or self.thread.ident is None:
                self.report["status"] = "not-started"
                processes.cancellation_checkpoint()
                return self.report
            if not self.entered.wait(5):
                self.cancel()
                raise RuntimeError("The GC.run worker did not start")
            if not self._wait_finished(self.timeout + 5):
                self._cancel_and_join()
            common.require(self.finished.is_set(), "The owned GC.run worker did not finish cleanup")
            self.thread.join(5)
            common.require(not self.thread.is_alive(), "The owned GC.run worker did not stop")
            common.require(self.report["status"] == "not-started" or
                    (self.out / "jcmd.json").is_file(), "The GC.run evidence is incomplete")
            processes.cancellation_checkpoint()
            return self.report
        except BaseException:
            self._cancel_and_join()
            raise
        finally:
            self._close_identities()
