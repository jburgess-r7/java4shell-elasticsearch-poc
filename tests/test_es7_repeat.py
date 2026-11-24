import hashlib
import struct
import unittest

from java4shell import bytecode as repeat



def utf8(value):
    return b"\x01" + struct.pack(">H", len(value)) + value


def class_file(*extra, name=repeat.MARKER_INTERNAL_NAME, this_class=2, major=61,
               return_literal=repeat.MARKER_RETURN_LITERAL):
    entries = [(utf8(name), 1), (b"\x07\x00\x01", 1),
               (utf8(b"java/lang/Object"), 1), (b"\x07\x00\x03", 1),
               (utf8(return_literal), 1), (b"\x08\x00\x05", 1)]
    entries.extend(extra)
    count = 1 + sum(slots for _, slots in entries)
    header = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, major, count)
    body = struct.pack(">HHHHHHH", 0x21, this_class, 4, 0, 0, 0, 0)
    return header + b"".join(value for value, _ in entries) + body


def sha256(value):
    return hashlib.sha256(value).hexdigest()


class ScriptSourceTests(unittest.TestCase):
    def test_distinct_comment_prefixes_preserve_the_complete_program(self):
        program = "int value = 1;\nreturn value;\n"
        first = repeat.fresh_script_source(program, 1)
        second = repeat.fresh_script_source(program, 2)
        self.assertEqual(first.split("\n", 1)[1], program)
        self.assertEqual(second.split("\n", 1)[1], program)
        self.assertTrue(first.startswith("// "))
        self.assertNotEqual(sha256(first.encode()), sha256(second.encode()))

    def test_rejects_invalid_script_inputs(self):
        for program, ordinal in (("", 1), (None, 1), ("return 1;", True),
                                 ("return 1;", 0), ("return 1;", 100000)):
            with self.subTest(program=program, ordinal=ordinal), self.assertRaises(ValueError):
                repeat.fresh_script_source(program, ordinal)


class MarkerDerivationTests(unittest.TestCase):
    def test_rewrites_only_the_name_and_return_utf8_constants(self):
        other = b"unrelated:" + repeat.MARKER_INTERNAL_NAME
        other_return = b"unrelated:" + repeat.MARKER_RETURN_LITERAL
        for major in (61, 65):
            base = class_file((utf8(other), 1), (utf8(other_return), 1), major=major)
            first = repeat.derive_marker_class(base, sha256(base), 1)
            last = repeat.derive_marker_class(base, sha256(base), 99999)
            expected_name = b"org/elasticsearch/painless/OwnedBase64M00001"
            expected_return = b"owned-bytecode-00000001"
            expected = base.replace(utf8(repeat.MARKER_INTERNAL_NAME), utf8(expected_name), 1)
            expected = expected.replace(utf8(repeat.MARKER_RETURN_LITERAL),
                                        utf8(expected_return), 1)
            self.assertEqual(first["bytes"], expected)
            self.assertIn(other, first["bytes"])
            self.assertIn(other_return, first["bytes"])
            self.assertEqual(len(first["bytes"]), len(base))
            self.assertEqual(first["sha256"], sha256(expected))
            self.assertEqual(first["internal_name"], expected_name.decode())
            self.assertEqual(first["binary_name"], expected_name.decode().replace("/", "."))
            self.assertEqual(first["marker_return"], expected_return.decode())
            self.assertEqual(last["marker_return"], "owned-bytecode-00099999")
            self.assertEqual(repeat.class_internal_name(last["bytes"]),
                             "org/elasticsearch/painless/OwnedBase64M99999")
            self.assertNotEqual(first["sha256"], last["sha256"])

    def test_requires_the_expected_full_class_hash(self):
        base = class_file()
        for pin in ("0" * 64, sha256(base).upper(), "not-a-hash"):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                repeat.derive_marker_class(base, pin, 1)
        with self.assertRaises(ValueError):
            repeat.derive_marker_class(base + b"changed", sha256(base), 1)

    def test_rejects_ambiguous_or_wrong_class_identity(self):
        cases = [class_file((utf8(repeat.MARKER_INTERNAL_NAME), 1)),
                 class_file((utf8(repeat.MARKER_INTERNAL_NAME), 1), name=b"other/Marker"),
                 class_file(this_class=1)]
        for base in cases:
            with self.subTest(base=sha256(base)), self.assertRaises(ValueError):
                repeat.derive_marker_class(base, sha256(base), 1)

    def test_rejects_missing_or_ambiguous_return_literal(self):
        cases = [class_file(return_literal=b"different return value"),
                 class_file((utf8(repeat.MARKER_RETURN_LITERAL), 1))]
        for base in cases:
            with self.subTest(base=sha256(base)), self.assertRaisesRegex(ValueError, "marker-return"):
                repeat.derive_marker_class(base, sha256(base), 1)

    def test_rejects_invalid_ordinals(self):
        base = class_file()
        for ordinal in (True, False, 0, -1, 100000, 1.0, "1", None):
            with self.subTest(ordinal=ordinal), self.assertRaises(ValueError):
                repeat.derive_marker_class(base, sha256(base), ordinal)

    def test_handles_two_slot_constants_and_rejects_truncation(self):
        base = class_file((b"\x05" + b"\0" * 8, 2),
                          (b"\x06" + b"\0" * 8, 2))
        self.assertEqual(repeat.class_internal_name(
            repeat.derive_marker_class(base, sha256(base), 17)["bytes"]),
            "org/elasticsearch/painless/OwnedBase64M00017")
        malformed = [base[:9], base[:12], base[:-10],
                     b"\0" * 4 + base[4:],
                     class_file((b"\xff\0\0", 1)),
                     class_file((b"\x05" + b"\0" * 8, 1)),
                     class_file(major=62)]
        for data in malformed:
            with self.subTest(data=sha256(data)), self.assertRaises(ValueError):
                repeat.derive_marker_class(data, sha256(data), 1)


if __name__ == "__main__":
    unittest.main()
