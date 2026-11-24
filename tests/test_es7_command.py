"""Command-interface protocol tests; these do not execute the CVE or a JVM."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import exploit
import validate_command

from java4shell import command


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "owned-command-" + "12" * 12
MARKER = {"marker_return": TOKEN,
          "binary_name": "org.elasticsearch.painless.OwnedCommand" + "12" * 12}
REVISIONS = {"7.17.28": "139cb5a961d8de68b8e02c45cc47f5289a3623af",
             "7.17.29": "580aff1a0064ce4c93293aaab6fcc55e22c10d1c"}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def encode_document(document, token=TOKEN):
    return token + ":" + base64.b64encode(json.dumps(document).encode()).decode("ascii")


def completed_document(**updates):
    # Parser fixture only: this is not saved native or exploit evidence.
    document = {"protocol": 2, "token": TOKEN, "state": "completed",
                "library_anonymous": True, "library_descriptor_closed": True,
                "marker_file_created": False,
                "metadata": {"status": "completed", "stage": "none", "error_errno": 0,
                    "supervisor_pid": 101, "supervisor_reaped": True, "supervisor_status": 0,
                    "child_pid": 102, "exit_code": 0, "term_signal": 0, "timeout": False,
                    "cleanup_complete": True, "descendants_reaped": 0,
                    "stdout_truncated": False, "stderr_truncated": False,
                    "no_new_privs": 1, "seccomp": 2, "executable_dev": 1,
                    "executable_ino": 2, "executable_size": 4096},
                "stdout_base64": base64.b64encode(b"out\x00\xff\n").decode("ascii"),
                "stderr_base64": base64.b64encode(b"err\n").decode("ascii")}
    document.update(updates)
    return document


def response_fixture(**updates):
    # The exact Java-map wire grammar is tested independently of execution.
    fields = {
        "stage": "bytecode-marker", "success": "true",
        "bytecode_result": MARKER["marker_return"],
        "marker_class": "class " + MARKER["binary_name"],
        "file_denied": "true", "manager_present_before": "true",
        "security_restored": "true", "security_readback": "true",
        "post_restore_denied": "true", "restored_lookup": "true",
        "restored_heap": "true",
        "last_transaction": "{transaction=24, last_success_transaction=24, prior_unchanged_count=0, decoder_exception_kind=1}",
        "command_result": encode_document(completed_document()),
    }
    fields.update(updates)
    return {"status": 200, "body": {"result": "{" + ", ".join(
        key + "=" + value for key, value in fields.items()) + "}"}}


def profile_responses(major=21, release="7.17.29"):
    version = {17: "17.0.21", 21: "21.0.13"}[major]
    return [
        {"status": 200, "body": {"version": {
            "number": release, "build_hash": REVISIONS[release]}}},
        {"status": 200, "body": {"nodes": {"selected-node": {
            "os": {"name": "Linux", "arch": "amd64"},
            "jvm": {"version": version, "vm_name": "OpenJDK 64-Bit Server VM",
                    "vm_version": version + "+9-LTS", "vm_vendor": "Eclipse Adoptium",
                    "using_compressed_ordinary_object_pointers": "true"}}}}},
    ]


class PayloadTests(unittest.TestCase):
    def test_both_reviewed_payloads_are_pinned_and_only_result_fields_change(self):
        pins = json.loads((ROOT / "elasticsearch/releases.json").read_text())
        for major in (17, 21):
            with self.subTest(major=major):
                original = (ROOT / f"elasticsearch/payload-java{major}.painless").read_text()
                expected = pins["runtimes"][str(major)]["payload_sha256"]
                self.assertEqual(digest(original), expected)
                one = command.checked_payload(original, expected, "12" * 12)
                two = command.checked_payload(original, expected, "34" * 12)
                self.assertNotEqual(one, two)
                restored = one.split("\n", 1)[1].replace(
                    command.COMMAND_SUCCESS_CHECK, command.SUCCESS_CHECK).replace(
                    command.COMMAND_RESULT_FIELD, command.RESULT_FIELD)
                self.assertEqual(restored, original)
                self.assertEqual(one.split("\n", 1)[1], two.split("\n", 1)[1])
                with self.assertRaisesRegex(ValueError, "reviewed hash"):
                    command.checked_payload(original + "\n", expected, "12" * 12)

    def test_changed_or_duplicate_patch_locations_are_rejected(self):
        fixture = command.SUCCESS_CHECK + command.RESULT_FIELD
        for source in (fixture.replace(command.SUCCESS_CHECK, ""),
                       fixture + command.SUCCESS_CHECK, fixture + command.RESULT_FIELD):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "not unique"):
                command.checked_payload(source, digest(source), "12" * 12)
        for nonce in ("12" * 11, "12" * 13, "AA" * 12, "../" + "1" * 21):
            with self.subTest(nonce=nonce), self.assertRaisesRegex(ValueError, "nonce"):
                command.checked_payload(fixture, digest(fixture), nonce)

    def test_marker_identity_and_argv_are_unique_and_binary_safe(self):
        bridge = b"\xca\xfe\xba\xbeunit-class-header"
        library = b"\x7fELFunit-library-header"
        argv = ["/usr/bin/printf", "%s", "literal ; $() \n\u2603"]
        one = command.render_request_class(bridge, library, argv, 9, "12" * 12,
                                    build_id="ab" * 32, create_marker=False)
        two = command.render_request_class(bridge, library, argv, 9, "34" * 12,
                                    build_id="ab" * 32)
        self.assertNotEqual(one["binary_name"], two["binary_name"])
        self.assertNotEqual(one["marker_return"], two["marker_return"])
        self.assertNotEqual(one["source_sha256"], two["source_sha256"])
        self.assertEqual(one["source_sha256"], digest(one["source"]))
        self.assertEqual(one["native_library_sha256"], hashlib.sha256(library).hexdigest())
        self.assertEqual(one["bridge_class_sha256"], hashlib.sha256(bridge).hexdigest())
        self.assertEqual(one["bridge_build_id"], "ab" * 32)
        self.assertIn('getMethod("run", SeekableByteChannel.class, String[].class, int.class)', one["source"])
        self.assertIn('getMethod("openAnonymous", String.class)', one["source"])
        self.assertFalse(one["marker_file_expected"])
        self.assertTrue(two["marker_file_expected"])
        self.assertIn('getMethod("buildId")', one["source"])
        self.assertNotIn("installFilterForTest", one["source"])
        self.assertNotIn("@@", one["source"])
        encoded = command._encoded_argv(argv)
        count = struct.unpack_from(">I", encoded)[0]
        offset, recovered = 4, []
        for _ in range(count):
            length = struct.unpack_from(">I", encoded, offset)[0]
            offset += 4
            recovered.append(encoded[offset:offset + length].decode())
            offset += length
        self.assertEqual(recovered, argv)
        self.assertEqual(offset, len(encoded))

    def test_argv_limits_match_the_native_contract(self):
        command._encoded_argv(["/usr/bin/printf", "x" * 32768])
        cases = ([], ["relative"], ["/bin/true"] * 65, ["/bin/true", "x\0y"],
                 ["/bin/true", "\u00e9" * 16385],
                 ["/bin/true"] + ["x" * 32768] * 4)
        for argv in cases:
            with self.subTest(lengths=[len(a) for a in argv]), self.assertRaises(ValueError):
                command._encoded_argv(argv)


class EnvelopeTests(unittest.TestCase):
    def test_streams_are_returned_as_exact_bytes(self):
        value = command.decode_result(encode_document(completed_document()), TOKEN)
        self.assertEqual(value["stdout"], b"out\x00\xff\n")
        self.assertEqual(value["stderr"], b"err\n")
        self.assertEqual(value["metadata"], completed_document()["metadata"])

    def test_both_token_copies_are_required(self):
        document = completed_document()
        cases = (encode_document(document, "wrong"),
                 encode_document(dict(document, token="wrong")),
                 encode_document(document).replace(TOKEN + ":", TOKEN + "extra:", 1), None)
        for value in cases:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                command.decode_result(value, TOKEN)

    def test_invalid_base64_json_state_and_metadata_are_rejected(self):
        invalid = [TOKEN + ":%%%%", TOKEN + ":" + base64.b64encode(b"not json").decode(),
                   encode_document([]), encode_document(completed_document(protocol=1)),
                   encode_document(completed_document(state="running")),
                   encode_document(completed_document(stdout_base64="%%%%")),
                   encode_document(completed_document(metadata=[]))]
        for value in invalid:
            with self.subTest(value=value[:45]), self.assertRaises(ValueError):
                command.decode_result(value, TOKEN)

    def test_response_and_each_stream_have_independent_limits(self):
        for key in ("stdout_base64", "stderr_base64"):
            with self.subTest(key=key):
                boundary = base64.b64encode(b"x" * 65536).decode()
                self.assertEqual(len(command.decode_result(encode_document(
                    completed_document(**{key: boundary})), TOKEN)[key.removesuffix("_base64")]), 65536)
                overflow = base64.b64encode(b"x" * 65537).decode()
                with self.assertRaisesRegex(ValueError, "size limit|oversized"):
                    command.decode_result(encode_document(completed_document(**{key: overflow})), TOKEN)
        with self.assertRaisesRegex(ValueError, "command response"):
            command.decode_result(TOKEN + ":" + "A" * (512 * 1024 + 1), TOKEN)

    def test_reported_native_error_is_not_reinterpreted_as_completion(self):
        value = command.decode_result(encode_document({"protocol": 2, "token": TOKEN,
            "state": "error", "error": "java.io.IOException: library write",
            "library_anonymous": True, "library_descriptor_closed": True,
            "marker_file_created": False}), TOKEN)
        self.assertEqual(value["state"], "error")
        self.assertNotIn("stdout", value)

    def test_protocol_version_requires_exact_integer_type(self):
        for version in (True, False, 2.0, "2", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                command.decode_result(encode_document(completed_document(protocol=version)), TOKEN)

    def test_duplicate_json_members_are_rejected_at_every_level(self):
        raw = json.dumps(completed_document(), separators=(",", ":"))
        cases = (raw.replace('"protocol":2', '"protocol":1,"protocol":2'),
                 raw.replace('"token":', '"token":"wrong","token":', 1),
                 raw.replace('"cleanup_complete":true',
                             '"cleanup_complete":false,"cleanup_complete":true'))
        for document in cases:
            value = TOKEN + ":" + base64.b64encode(document.encode()).decode("ascii")
            with self.subTest(document=document[:70]), self.assertRaises(ValueError):
                command.decode_result(value, TOKEN)

    def test_nonfinite_json_numbers_are_rejected(self):
        raw = json.dumps(completed_document(), separators=(",", ":"))
        for number in ("NaN", "Infinity", "-Infinity"):
            document = raw[:-1] + ',"unexpected":' + number + "}"
            value = TOKEN + ":" + base64.b64encode(document.encode()).decode("ascii")
            with self.subTest(number=number), self.assertRaises(ValueError):
                command.decode_result(value, TOKEN)

    def test_streams_must_be_present_base64_strings(self):
        for key in ("stdout_base64", "stderr_base64"):
            for wrong in (None, [], {}, 0, False):
                with self.subTest(field=key, wrong=wrong), self.assertRaises(ValueError):
                    command.decode_result(encode_document(completed_document(**{key: wrong})), TOKEN)
            document = completed_document()
            del document[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                command.decode_result(encode_document(document), TOKEN)

    def test_cleanup_results_require_exact_field_types(self):
        documents = (completed_document(), {"protocol": 2, "token": TOKEN,
            "state": "error", "error": "java.io.IOException: library write",
            "library_anonymous": True, "library_descriptor_closed": True,
            "marker_file_created": False})
        for original in documents:
            for key in ("library_anonymous", "library_descriptor_closed", "marker_file_created"):
                for wrong in (None, 0, "true"):
                    with self.subTest(state=original["state"], field=key, wrong=wrong), \
                            self.assertRaises(ValueError):
                        command.decode_result(encode_document(dict(original, **{key: wrong})), TOKEN)
                missing = dict(original)
                del missing[key]
                with self.subTest(state=original["state"], missing=key), self.assertRaises(ValueError):
                    command.decode_result(encode_document(missing), TOKEN)
            for wrong in (None, False, ""):
                with self.subTest(state=original["state"], cleanup_error=wrong), self.assertRaises(ValueError):
                    command.decode_result(encode_document(dict(original, library_cleanup_error=wrong)), TOKEN)
            failed_cleanup = command.decode_result(encode_document(dict(original,
                library_descriptor_closed=False, library_cleanup_error="close failed")), TOKEN)
            self.assertFalse(failed_cleanup["library_descriptor_closed"])
            with self.subTest(state=original["state"], missing_cleanup_error=True), self.assertRaises(ValueError):
                command.decode_result(encode_document(dict(original, library_descriptor_closed=False)), TOKEN)
            for old_field in ("library_removed", "marker_removed", "marker_cleanup_error"):
                with self.subTest(old_field=old_field), self.assertRaises(ValueError):
                    command.decode_result(encode_document(dict(original, **{old_field: True})), TOKEN)

    def test_completed_command_requires_anonymous_library_and_remote_markerless_mode(self):
        with self.assertRaisesRegex(ValueError, "anonymous library"):
            command.decode_result(encode_document(completed_document(library_anonymous=False)), TOKEN)
        with self.assertRaisesRegex(RuntimeError, "marker file"):
            exploit.remote_proof(response_fixture(command_result=encode_document(
                completed_document(marker_file_created=True))), MARKER)

    def test_native_metadata_has_exact_types_and_required_fields(self):
        original = completed_document()["metadata"]
        for key, value in original.items():
            wrong = (0 if type(value) is bool else False if type(value) is int else None)
            metadata = dict(original, **{key: wrong})
            with self.subTest(wrong_type=key), self.assertRaises(ValueError):
                command.decode_result(encode_document(completed_document(metadata=metadata)), TOKEN)
            metadata = dict(original)
            del metadata[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                command.decode_result(encode_document(completed_document(metadata=metadata)), TOKEN)

    def test_contradictory_native_status_cannot_be_completed(self):
        original = completed_document()["metadata"]
        changes = ({"status": "invented"}, {"timeout": True}, {"cleanup_complete": False},
                   {"supervisor_reaped": False}, {"supervisor_status": 1},
                   {"stage": "timeout"}, {"error_errno": 5},
                   {"supervisor_pid": 0}, {"child_pid": 0},
                   {"exit_code": -1, "term_signal": 0},
                   {"exit_code": 0, "term_signal": 9},
                   {"status": "timeout", "timeout": False})
        for change in changes:
            metadata = dict(original, **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                command.decode_result(encode_document(completed_document(metadata=metadata)), TOKEN)

    def test_native_nonzero_exit_and_timeout_remain_distinct_results(self):
        original = completed_document()["metadata"]
        exited = command.decode_result(encode_document(completed_document(
            metadata=dict(original, exit_code=7))), TOKEN)
        self.assertEqual(exited["metadata"]["exit_code"], 7)
        signaled = command.decode_result(encode_document(completed_document(
            metadata=dict(original, exit_code=-1, term_signal=15))), TOKEN)
        self.assertEqual(signaled["metadata"]["term_signal"], 15)
        timed_out = command.decode_result(encode_document(completed_document(
            metadata=dict(original, status="timeout", timeout=True,
                          exit_code=-1, term_signal=9))), TOKEN)
        self.assertEqual(timed_out["metadata"]["status"], "timeout")
        self.assertTrue(timed_out["metadata"]["cleanup_complete"])

    def test_remote_proof_requires_exact_identity_and_all_repair_checks(self):
        result = exploit.remote_proof(response_fixture(), MARKER)
        self.assertEqual(result["stdout"], b"out\x00\xff\n")
        wrong = {"stage": "unchanged", "success": "false", "bytecode_result": "prior-token",
                 "marker_class": "class org.elasticsearch.painless.PriorCommand",
                 "file_denied": "false", "manager_present_before": "false",
                 "security_restored": "false", "security_readback": "false",
                 "post_restore_denied": "false", "restored_lookup": "false",
                 "restored_heap": "false"}
        for key, value in wrong.items():
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                exploit.remote_proof(response_fixture(**{key: value}), MARKER)
        for key, value in (("transaction", "23"), ("last_success_transaction", "23"),
                           ("prior_unchanged_count", "1"), ("decoder_exception_kind", "0")):
            transaction = {"transaction": "24", "last_success_transaction": "24",
                           "prior_unchanged_count": "0", "decoder_exception_kind": "1"}
            transaction[key] = value
            text = "{" + ", ".join(k + "=" + v for k, v in transaction.items()) + "}"
            with self.subTest(transaction=key), self.assertRaises(RuntimeError):
                exploit.remote_proof(response_fixture(last_transaction=text), MARKER)
        with self.assertRaises(ValueError):
            exploit.remote_proof(response_fixture(command_result=encode_document(
                completed_document(token="prior-token"))), MARKER)


    def test_remote_proof_requires_the_tested_syscall_filter(self):
        for field, values in (("no_new_privs", (0,)), ("seccomp", (0, 1))):
            for value in values:
                document = completed_document()
                document["metadata"][field] = value
                response = response_fixture(command_result=encode_document(document))
                with self.subTest(field=field, value=value), \
                        self.assertRaisesRegex(RuntimeError, "syscall-filter state"):
                    exploit.remote_proof(response, MARKER)


class ProfileTests(unittest.TestCase):
    def test_only_recorded_temurin_profiles_are_selected(self):
        for release, major in (("7.17.29", 17), ("7.17.29", 21),
                               ("7.17.28", 17), ("7.17.28", 21)):
            for suffix in ("+9", "+9-LTS"):
                for arch in ("amd64", "x86_64"):
                    for requested in (None, major):
                        with self.subTest(release=release, major=major, suffix=suffix,
                                          arch=arch, requested=requested):
                            replies = profile_responses(major, release)
                            node = replies[1]["body"]["nodes"]["selected-node"]
                            node["os"]["arch"] = arch
                            node["jvm"]["vm_version"] = node["jvm"]["version"] + suffix
                            endpoint = mock.Mock()
                            endpoint.request.side_effect = replies
                            selected = exploit.target_profile(endpoint, requested)
                            self.assertEqual(selected["java_major"], major)
                            self.assertEqual(selected["elasticsearch_version"], release)
                            self.assertEqual(selected["elasticsearch_revision"], REVISIONS[release])
                            self.assertTrue(all(call.args[0] == "GET" for call in endpoint.request.call_args_list))

    def test_nearby_release_rejects_other_java_profiles(self):
        for requested, observed, request_count in ((None, "25.0.1", 2),
                (25, "21.0.13", 1), (17, "21.0.13", 2), (21, "17.0.21", 2)):
            replies = profile_responses(17 if observed == "17.0.21" else 21, "7.17.28")
            replies[1]["body"]["nodes"]["selected-node"]["jvm"]["version"] = observed
            endpoint = mock.Mock()
            endpoint.request.side_effect = replies
            with self.subTest(requested=requested, observed=observed), self.assertRaises(exploit.common.Unavailable):
                exploit.target_profile(endpoint, requested)
            self.assertEqual(endpoint.request.call_count, request_count)

    def test_command_release_pins_match_the_tested_profiles(self):
        pins = json.loads((ROOT / "elasticsearch/releases.json").read_text())
        targets = pins["command_targets"]
        self.assertEqual(set(targets), {"7.17.28", "7.17.29"})
        self.assertEqual(targets["7.17.28"]["java_majors"], [17, 21])
        self.assertEqual(targets["7.17.29"]["java_majors"], [17, 21])
        self.assertEqual({version: row["revision"] for version, row in targets.items()}, REVISIONS)
        for key in ("revision", "url", "archive_sha256", "archive_sha512"):
            self.assertEqual(targets["7.17.29"][key], pins["elasticsearch"][key])
        self.assertEqual((exploit.es7_api.VERSION, exploit.es7_api.REVISION),
                         ("7.17.29", REVISIONS["7.17.29"]))
        self.assertEqual(targets["7.17.28"]["url"],
                         "https://artifacts.elastic.co/downloads/elasticsearch/"
                         "elasticsearch-7.17.28-linux-x86_64.tar.gz")
        self.assertEqual(targets["7.17.28"]["archive_sha256"],
                         "d72adef80b899eb624f6e14aa3b0d8c2ed6597e5fe328bbb1ed9de2c3c14ef28")
        self.assertEqual(targets["7.17.28"]["archive_sha512"],
                         "fb2cc31cfa862862855ecca6d7c56cbf21eaa42dc3c87f18fa1986a334ec4e6d4"
                         "fe570e5220bfeffbc0c57d072cd37b7c4cf125dac3e27108d2bfa396ce660aa")

    def test_mismatching_target_metadata_fails_closed(self):
        changes = (("os", "name", "Windows"), ("os", "arch", "aarch64"),
                   ("jvm", "version", "21.0.13.1"), ("jvm", "vm_name", "OpenJ9 VM"),
                   ("jvm", "vm_version", "21.0.13+8"), ("jvm", "vm_vendor", "Amazon.com Inc."),
                   ("jvm", "using_compressed_ordinary_object_pointers", "false"),
                   ("jvm", "using_compressed_ordinary_object_pointers", True))
        for group, key, value in changes:
            with self.subTest(field=key, value=value):
                replies = profile_responses()
                replies[1]["body"]["nodes"]["selected-node"][group][key] = value
                endpoint = mock.Mock()
                endpoint.request.side_effect = replies
                with self.assertRaises(exploit.common.Unavailable):
                    exploit.target_profile(endpoint)
        endpoint = mock.Mock()
        endpoint.request.side_effect = profile_responses(17)
        with self.assertRaises(exploit.common.Unavailable):
            exploit.target_profile(endpoint, 21)

    def test_release_identity_and_one_local_node_are_required(self):
        identities = (("7.17.28", REVISIONS["7.17.29"]),
                      ("7.17.29", REVISIONS["7.17.28"]),
                      ("7.17.28", "0" * 40), ("7.17.29", "0" * 40),
                      ("7.17.27", REVISIONS["7.17.29"]),
                      ("7.17.30", REVISIONS["7.17.29"]),
                      ("8.19.25", REVISIONS["7.17.29"]),
                      ("9.5.6", REVISIONS["7.17.29"]),
                      (None, REVISIONS["7.17.29"]), ([], REVISIONS["7.17.29"]))
        for release, revision in identities:
            with self.subTest(release=release, revision=revision):
                replies = profile_responses()
                replies[0]["body"]["version"] = {"number": release, "build_hash": revision}
                endpoint = mock.Mock()
                endpoint.request.side_effect = replies
                with self.assertRaises(exploit.common.Unavailable):
                    exploit.target_profile(endpoint)
                self.assertEqual(endpoint.request.call_count, 1)
        for node_count in (0, 2):
            replies = profile_responses()
            node = replies[1]["body"]["nodes"]["selected-node"]
            replies[1]["body"]["nodes"] = {str(i): copy.deepcopy(node) for i in range(node_count)}
            endpoint = mock.Mock()
            endpoint.request.side_effect = replies
            with self.subTest(node_count=node_count), self.assertRaises(exploit.common.Unavailable):
                exploit.target_profile(endpoint)


class EvidenceDirectoryTests(unittest.TestCase):
    def test_client_does_not_overwrite_or_contact_target_for_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = root / ".validation-local/existing"
            out.mkdir(parents=True)
            original = b"previous evidence must survive\n"
            (out / "report.json").write_bytes(original)
            endpoint = mock.Mock()
            with mock.patch.object(exploit, "ROOT", root), \
                    mock.patch.object(exploit, "Target", return_value=endpoint), \
                    mock.patch.object(exploit.processes, "run_bounded_command") as compiler, \
                    mock.patch("sys.stderr", new=io.StringIO()):
                code = exploit.main(["--target", "http://127.0.0.1:1", "--output", str(out),
                                     "--", "/usr/bin/id"])
            self.assertEqual(code, 1)
            endpoint.request.assert_not_called()
            endpoint.execute.assert_not_called()
            compiler.assert_not_called()
            self.assertEqual((out / "report.json").read_bytes(), original)
            self.assertEqual(sorted(path.name for path in out.iterdir()), ["report.json"])

    def test_validator_does_not_overwrite_or_launch_for_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = root / ".validation-local/existing"
            out.mkdir(parents=True)
            original = b"previous comparison evidence\n"
            (out / "report.json").write_bytes(original)
            with mock.patch.object(validate_command, "ROOT", root), \
                    mock.patch.object(validate_command.es7, "run_case") as launch, \
                    mock.patch.object(validate_command.processes, "set_subreaper") as subreaper, \
                    mock.patch("sys.stderr", new=io.StringIO()):
                try:
                    code = validate_command.main(["--major", "21", "--build", str(root / "build"),
                        "--output", str(out), "--expect-stdout-base64", "", "--", "/usr/bin/id"])
                except FileExistsError:
                    code = 1
            self.assertEqual(code, 1)
            launch.assert_not_called()
            subreaper.assert_not_called()
            self.assertEqual((out / "report.json").read_bytes(), original)
            self.assertEqual(sorted(path.name for path in out.iterdir()), ["report.json"])


if __name__ == "__main__":
    unittest.main()
