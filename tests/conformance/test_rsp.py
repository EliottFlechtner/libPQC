import tempfile
import unittest
from pathlib import Path

from tests.conformance.rsp import (
    decode_hex_field,
    group_rsp_records,
    load_rsp_file,
    parse_rsp_text,
)


class TestRspParser(unittest.TestCase):
    def test_parse_rsp_text_groups_records(self):
        text = """# comment
[sample]
count = 0
seed = 00 01 02 03
pk = deadbeef

count = 1
msg = hello
ct = cafe
"""

        records = parse_rsp_text(text)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].section, "sample")
        self.assertEqual(records[0].index, 0)
        self.assertEqual(records[0].fields["count"], "0")
        self.assertEqual(records[0].fields["seed"], "00 01 02 03")
        self.assertEqual(records[1].fields["msg"], "hello")

    def test_decode_hex_field_ignores_whitespace(self):
        self.assertEqual(decode_hex_field("de ad be ef"), bytes.fromhex("deadbeef"))

    def test_load_rsp_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "vectors.rsp"
            path.write_text("[sample]\ncount = 0\nseed = aa55\n", encoding="utf-8")

            records = load_rsp_file(path)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].section, "sample")
        self.assertEqual(records[0].fields["seed"], "aa55")

    def test_group_rsp_records(self):
        records = parse_rsp_text("[a]\ncount = 0\n\n[b]\ncount = 1\n")

        grouped = group_rsp_records(records)

        self.assertEqual(len(grouped["a"]), 1)
        self.assertEqual(len(grouped["b"]), 1)
        self.assertEqual(grouped["a"][0].require("count"), "0")

    def test_rejects_malformed_lines(self):
        with self.assertRaises(ValueError):
            parse_rsp_text("count 0\n")


if __name__ == "__main__":
    unittest.main()
