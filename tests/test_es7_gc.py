import copy
from datetime import datetime, timedelta, timezone
import unittest

from java4shell import gc



def event(stamp, gc_id, suffix="", pid=1980171):
    return f"[{stamp}][{pid}][info][gc] GC({gc_id}) Concurrent Mark Cycle{suffix}"


def abort(stamp, gc_id, pid=1980171):
    return f"[{stamp}][{pid}][info][gc,marking] GC({gc_id}) Concurrent Mark Abort"


def nodes_stats(node_id="local-id", timestamp=1700000000000, uptime=10000):
    return {"_nodes": {"total": 1, "successful": 1, "failed": 0},
            "nodes": {node_id: {"jvm": {
                "timestamp": timestamp, "uptime_in_millis": uptime,
                "gc": {"collectors": {
                    "young": {"collection_count": 10, "collection_time_in_millis": 500},
                    "old": {"collection_count": 2, "collection_time_in_millis": 100},
                }},
            }}}}


class RequestTimingTests(unittest.TestCase):
    def test_exact_elapsed_and_conservative_microsecond_difference(self):
        result = gc.validate_request_timing("2026-11-18T13:00:00+01:00",
                                            "2026-11-18T12:00:01.000001Z",
                                            10**20, 10**20 + 1_000_000_999)
        self.assertEqual(result, {"elapsed_microseconds": 1_000_001,
                                  "monotonic_elapsed_nanoseconds": 1_000_000_999,
                                  "clock_difference_nanoseconds": 1,
                                  "clock_difference_microseconds": 1})
        self.assertEqual(gc.validate_request_timing("2026-11-18T12:00:00Z",
                                                    "2026-11-18T12:00:00Z",
                                                    -1, -1, 0)["elapsed_microseconds"], 0)

    def test_exact_threshold_and_one_nanosecond_excess(self):
        start, end = "2026-11-18T12:00:00Z", "2026-11-18T12:00:01Z"
        for duration in (750_000_000, 1_250_000_000):
            with self.subTest(duration=duration):
                self.assertEqual(gc.validate_request_timing(start, end, 0, duration)
                                 ["clock_difference_microseconds"], 250000)
        for duration in (749_999_999, 1_250_000_001):
            with self.subTest(duration=duration), self.assertRaises(gc.GcEvidenceError):
                gc.validate_request_timing(start, end, 0, duration)

    def test_rejects_naive_reversed_or_malformed_clock_values(self):
        start, end = "2026-11-18T12:00:00Z", "2026-11-18T12:00:01Z"
        invalid = [("2026-11-18T12:00:00", end, 0, 1_000_000_000, 250000),
                   (end, start, 0, 1_000_000_000, 250000),
                   (start, end, 1, 0, 250000),
                   (start, end, True, 1_000_000_000, 250000),
                   (start, end, 0, "1000000000", 250000),
                   (start, end, 0, 1_000_000_000.0, 250000),
                   (start, end, 0, 1_000_000_000, -1),
                   (start, end, 0, 1_000_000_000, True)]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(gc.GcEvidenceError):
                gc.validate_request_timing(*args)


class MarkCycleTests(unittest.TestCase):
    def test_pairs_genuine_format_and_retains_both_time_measurements(self):
        text = "\n".join([
            event("2026-11-18T11:44:05.000+0000", 10, " 10.000ms"),
            event("2026-11-18T11:44:05.592+0000", 11),
            "[2026-11-18T11:44:05.700+0000][1980171][info][gc] GC(12) Pause Young 5.123ms",
            event("not-a-time", 11, " malformed", pid=22),
            event("2026-11-18T11:44:06.535+0000", 11, " 941.298ms"),
            event("2026-11-18T11:44:07.000+0000", 13),
        ])
        cycles = gc.parse_completed_mark_cycles(text, 1980171)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0], {"pid": 1980171, "gc_id": 11,
                                    "start_utc": "2026-11-18T11:44:05.592000Z",
                                    "end_utc": "2026-11-18T11:44:06.535000Z",
                                    "elapsed_microseconds": 943000,
                                    "reported_duration_microseconds": 941298,
                                    "aborted": False})

    def test_cycle_clock_difference_boundary_and_excess(self):
        start = event("2026-11-18T12:00:00.000000Z", 1)
        for reported in (750000, 1250000):
            suffix = f" {reported // 1000}.{reported % 1000:03}ms"
            with self.subTest(reported=reported):
                cycle = gc.parse_completed_mark_cycles(
                    start + "\n" + event("2026-11-18T12:00:01.000000Z", 1, suffix),
                    1980171)[0]
                self.assertEqual(cycle["elapsed_microseconds"], 1000000)
                self.assertEqual(cycle["reported_duration_microseconds"], reported)
                overlap = gc.overlapping_mark_cycles([cycle], "2026-11-18T12:00:00Z",
                                                     "2026-11-18T12:00:01Z")
                self.assertEqual(overlap[0]["overlap_microseconds"], 1000000)
        for reported in (749999, 1250001):
            suffix = f" {reported // 1000}.{reported % 1000:03}ms"
            with self.subTest(parser_reported=reported), self.assertRaises(gc.GcEvidenceError):
                gc.parse_completed_mark_cycles(
                    start + "\n" + event("2026-11-18T12:00:01.000000Z", 1, suffix),
                    1980171)
            forged = dict(cycle, reported_duration_microseconds=reported)
            with self.subTest(overlap_reported=reported), self.assertRaises(gc.GcEvidenceError):
                gc.overlapping_mark_cycles([forged], "2026-11-18T12:00:00Z",
                                           "2026-11-18T12:00:01Z")

    def test_duplicate_malformed_and_backwards_events_are_rejected(self):
        start = event("2026-11-18T12:00:00.000+0000", 1)
        end = event("2026-11-18T12:00:00.010+0000", 1, " 10.000ms")
        invalid = [start + "\n" + start,
                   start + "\n" + end + "\n" + end,
                   end + "\n" + event("2026-11-18T12:00:00.020+0000", 1),
                   start + "\n" + event("2026-11-18T11:59:59.999+0000", 1, " 1ms"),
                   start + "\n" + event("2026-11-18T12:00:00.010+0000", 1, " -1ms"),
                   start + "\n" + event("2026-11-18T12:00:00.010+0000", 1, " NaNms"),
                   start + "\n" + event("2026-11-18T12:00:00.010+0000", 1, " 1.0001ms"),
                   event("2026-11-18T12:00:00", 1),
                   start.replace("[info]", "[debug]"),
                   start.replace("GC(1)", "GC(?)")]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(gc.GcEvidenceError):
                gc.parse_completed_mark_cycles(text, 1980171)
        for pid in (0, -1, True, "1980171"):
            with self.subTest(pid=pid), self.assertRaises(gc.GcEvidenceError):
                gc.parse_completed_mark_cycles(start, pid)

    def test_logged_abort_is_retained_and_excluded_by_default(self):
        start = event("2026-11-18T12:00:00.000Z", 1)
        aborted = abort("2026-11-18T12:00:00.005Z", 1)
        end = event("2026-11-18T12:00:00.010Z", 1, " 10.000ms")
        cycles = gc.parse_completed_mark_cycles("\n".join([start, aborted, end]), 1980171)
        self.assertTrue(cycles[0]["aborted"])
        window = ("2026-11-18T12:00:00.003Z", "2026-11-18T12:00:00.009Z")
        self.assertEqual(gc.overlapping_mark_cycles(cycles, *window), [])
        included = gc.overlapping_mark_cycles(cycles, *window, include_aborted=True)
        self.assertEqual(included[0]["overlap_microseconds"], 6000)
        for text in ("\n".join([start, aborted, aborted, end]),
                     "\n".join([start, end, abort("2026-11-18T12:00:00.020Z", 1)]),
                     "\n".join([start, aborted + " trailing", end])):
            with self.subTest(text=text), self.assertRaises(gc.GcEvidenceError):
                gc.parse_completed_mark_cycles(text, 1980171)

    def test_exact_overlap_and_endpoint_touch(self):
        cycles = gc.parse_completed_mark_cycles("\n".join([
            event("2026-11-18T12:00:00.000+0000", 1),
            event("2026-11-18T12:00:00.010+0000", 1, " 10.000ms"),
            event("2026-11-18T12:00:00.020+0000", 2),
            event("2026-11-18T12:00:00.030+0000", 2, " 10.000ms"),
        ]), 1980171)
        overlaps = gc.overlapping_mark_cycles(cycles, "2026-11-18T12:00:00.009999Z",
                                              "2026-11-18T12:00:00.025001Z")
        self.assertEqual([x["gc_id"] for x in overlaps], [1, 2])
        self.assertEqual([x["overlap_microseconds"] for x in overlaps], [1, 5001])
        self.assertEqual(gc.overlapping_mark_cycles(cycles, "2026-11-18T12:00:00.010Z",
                                                   "2026-11-18T12:00:00.020Z"), [])
        self.assertEqual(gc.interval_overlap_microseconds("2026-11-18T13:00:00+01:00",
                                                          "2026-11-18T13:00:01+01:00",
                                                          "2026-11-18T12:00:00.999999Z",
                                                          "2026-11-18T12:00:02Z"), 1)

    def test_windows_require_aware_monotonic_values(self):
        aware = datetime(2026, 11, 18, tzinfo=timezone.utc)
        for start, end in ((aware.replace(tzinfo=None), aware),
                           (aware + timedelta(seconds=1), aware),
                           ("2026-11-18T12:00:00", aware)):
            with self.subTest(start=start, end=end), self.assertRaises(gc.GcEvidenceError):
                gc.overlapping_mark_cycles([], start, end)
        self.assertEqual(gc.interval_overlap_microseconds(aware, aware, aware, aware), 0)

    def test_completed_cycle_objects_cannot_forge_duration_or_duplicates(self):
        cycle = gc.parse_completed_mark_cycles("\n".join([
            event("2026-11-18T12:00:00.000Z", 1),
            event("2026-11-18T12:00:00.010Z", 1, " 10ms"),
        ]), 1980171)[0]
        for cycles in ([cycle, cycle], [dict(cycle, elapsed_microseconds=9)],
                       [dict(cycle, reported_duration_microseconds=-1)],
                       [dict(cycle, aborted="false")]):
            with self.subTest(cycles=cycles), self.assertRaises(gc.GcEvidenceError):
                gc.overlapping_mark_cycles(cycles, "2026-11-18T12:00:00Z", "2026-11-18T12:00:01Z")


class GcCounterTests(unittest.TestCase):
    def test_extracts_exact_local_g1_counters_and_nonnegative_deltas(self):
        before = gc.extract_local_gc_counters(nodes_stats())
        after_body = nodes_stats(timestamp=1700000000100, uptime=10100)
        after_body["nodes"]["local-id"]["jvm"]["gc"]["collectors"]["young"].update(
            collection_count=12, collection_time_in_millis=507)
        after = gc.extract_local_gc_counters(after_body, before["node_id"])
        delta = gc.gc_counter_deltas(before, after)
        self.assertEqual(delta, {"node_id": "local-id", "timestamp_delta_millis": 100,
                                 "uptime_delta_millis": 100,
                                 "collectors": {
                                     "young": {"collection_count": 2, "collection_time_in_millis": 7},
                                     "old": {"collection_count": 0, "collection_time_in_millis": 0}}})
        self.assertEqual(gc.gc_counter_deltas(before, before)["timestamp_delta_millis"], 0)

    def test_rejects_partial_multiple_or_wrong_node_responses(self):
        bodies = []
        for key, value in (("total", 2), ("successful", 0), ("failed", 1), ("failed", False)):
            body = nodes_stats(); body["_nodes"][key] = value; bodies.append(body)
        body = nodes_stats(); body["_nodes"]["failures"] = [{"reason": "unavailable"}]; bodies.append(body)
        body = nodes_stats(); body["_nodes"]["failures"] = {}; bodies.append(body)
        body = nodes_stats(); body["nodes"]["other"] = copy.deepcopy(body["nodes"]["local-id"]); bodies.append(body)
        body = nodes_stats(); body["nodes"] = {}; bodies.append(body)
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(gc.GcEvidenceError):
                gc.extract_local_gc_counters(body)
        with self.assertRaises(gc.GcEvidenceError):
            gc.extract_local_gc_counters(nodes_stats(), "other")

    def test_preserves_the_java21_concurrent_collector(self):
        body = nodes_stats()
        body["nodes"]["local-id"]["jvm"]["gc"]["collectors"]["G1 Concurrent GC"] = {
            "collection_count": 3, "collection_time_in_millis": 17}
        before = gc.extract_local_gc_counters(body)
        after = copy.deepcopy(before)
        after["collectors"]["G1 Concurrent GC"]["collection_count"] += 1
        self.assertEqual(gc.gc_counter_deltas(before, after)["collectors"]["G1 Concurrent GC"],
                         {"collection_count": 1, "collection_time_in_millis": 0})
        with self.assertRaises(gc.GcEvidenceError):
            gc.gc_counter_deltas(gc.extract_local_gc_counters(nodes_stats()), after)

    def test_rejects_missing_unknown_or_noninteger_counters(self):
        for value in (-1, True, 1.5, "1", None):
            body = nodes_stats(); body["nodes"]["local-id"]["jvm"]["gc"]["collectors"]["old"]["collection_count"] = value
            with self.subTest(value=value), self.assertRaises(gc.GcEvidenceError):
                gc.extract_local_gc_counters(body)
        for missing in ("timestamp", "uptime_in_millis", "gc"):
            body = nodes_stats(); del body["nodes"]["local-id"]["jvm"][missing]
            with self.subTest(missing=missing), self.assertRaises(gc.GcEvidenceError):
                gc.extract_local_gc_counters(body)
        body = nodes_stats(); body["nodes"]["local-id"]["jvm"]["gc"]["collectors"]["extra"] = {}
        with self.assertRaises(gc.GcEvidenceError):
            gc.extract_local_gc_counters(body)

    def test_rejects_restart_clock_or_counter_regression(self):
        before = gc.extract_local_gc_counters(nodes_stats())
        for field in ("timestamp", "uptime_in_millis"):
            after = copy.deepcopy(before); after[field] -= 1
            with self.subTest(field=field), self.assertRaises(gc.GcEvidenceError):
                gc.gc_counter_deltas(before, after)
        for name in ("young", "old"):
            for field in ("collection_count", "collection_time_in_millis"):
                after = copy.deepcopy(before); after["collectors"][name][field] -= 1
                with self.subTest(name=name, field=field), self.assertRaises(gc.GcEvidenceError):
                    gc.gc_counter_deltas(before, after)
        after = copy.deepcopy(before); after["node_id"] = "replacement"
        with self.assertRaises(gc.GcEvidenceError):
            gc.gc_counter_deltas(before, after)


if __name__ == "__main__":
    unittest.main()
