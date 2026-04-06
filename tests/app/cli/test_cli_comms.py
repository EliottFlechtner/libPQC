import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile

from src.app import cli


class TestCliComms(unittest.TestCase):
    def _run_cli(self, argv):
        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(argv)
        return rc, buffer.getvalue()

    def test_comms_key_agreement_perfect_authenticated(self):
        rc, output = self._run_cli(
            [
                "comms",
                "key-agreement",
                "--channel",
                "perfect",
                "--runs",
                "1",
                "--authenticate-server",
                "--dsa-params",
                "ML-DSA-65",
                "--server-aseed",
                "server-seed-32-bytes-material!!!!",
                "--server-zseed",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                "--server-dsa-aseed",
                "server-dsa-seed-material-32-bytes",
                "--server-signing-rnd",
                "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",
                "--encaps-message-hex",
                (b"m" * 32).hex(),
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["command"], "comms")
        self.assertEqual(payload["protocol"], "secure-key-agreement")
        self.assertEqual(payload["successes"], 1)
        self.assertEqual(payload["failures"], 0)
        self.assertTrue(payload["results"][0]["application_keys_match"])
        self.assertEqual(payload["results"][0]["client_protocol_state"], "active")
        self.assertEqual(payload["results"][0]["server_protocol_state"], "active")

    def test_comms_key_agreement_adversarial_fails(self):
        rc, output = self._run_cli(
            [
                "comms",
                "key-agreement",
                "--channel",
                "adversarial",
                "--runs",
                "1",
                "--server-aseed",
                "server-seed-32-bytes-material!!!!",
                "--server-zseed",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                "--encaps-message-hex",
                (b"m" * 32).hex(),
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["successes"], 0)
        self.assertEqual(payload["failures"], 1)
        self.assertEqual(payload["results"][0]["client_protocol_state"], "failed")
        self.assertEqual(payload["results"][0]["server_protocol_state"], "failed")

    def test_comms_group_key_agreement_perfect(self):
        rc, output = self._run_cli(
            [
                "comms",
                "group-key-agreement",
                "--channel",
                "perfect",
                "--runs",
                "1",
                "--members",
                "3",
                "--group-seed-hex",
                (b"g" * 32).hex(),
                "--member-seed-prefix",
                "group-seed-prefix",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["protocol"], "group-key-agreement")
        self.assertEqual(payload["successes"], 1)
        self.assertEqual(payload["results"][0]["member_count"], 3)
        self.assertTrue(payload["results"][0]["group_key_consensus"])
        self.assertEqual(payload["results"][0]["coordinator_protocol_state"], "active")

    def test_comms_group_key_agreement_noisy_fails(self):
        rc, output = self._run_cli(
            [
                "comms",
                "group-key-agreement",
                "--channel",
                "noisy",
                "--noisy-bit-error-rate",
                "1.0",
                "--runs",
                "1",
                "--members",
                "3",
                "--group-seed-hex",
                (b"g" * 32).hex(),
                "--member-seed-prefix",
                "group-seed-prefix",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["protocol"], "group-key-agreement")
        self.assertEqual(payload["successes"], 0)
        self.assertEqual(payload["failures"], 1)
        self.assertEqual(payload["results"][0]["coordinator_protocol_state"], "failed")

    def test_comms_group_export_and_replay_transcript(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            transcript_path = Path(temp_dir) / "group_transcript.json"

            rc, export_output = self._run_cli(
                [
                    "comms",
                    "group-export-transcript",
                    "--channel",
                    "perfect",
                    "--members",
                    "3",
                    "--group-seed-hex",
                    (b"g" * 32).hex(),
                    "--member-seed-prefix",
                    "group-seed-prefix",
                    "--output",
                    str(transcript_path),
                ]
            )

            self.assertEqual(rc, 0)
            self.assertEqual(export_output, "")
            self.assertTrue(transcript_path.exists())

            rc, replay_output = self._run_cli(
                ["comms", "group-replay-transcript", "--input", str(transcript_path)]
            )
            self.assertEqual(rc, 0)
            replay_payload = json.loads(replay_output)
            self.assertEqual(replay_payload["protocol"], "group-transcript-replay")
            self.assertTrue(replay_payload["valid"])
            self.assertGreater(replay_payload["message_count"], 0)

    def test_comms_group_broadcast(self):
        rc, output = self._run_cli(
            [
                "comms",
                "group-broadcast",
                "--channel",
                "perfect",
                "--members",
                "3",
                "--group-seed-hex",
                (b"g" * 32).hex(),
                "--member-seed-prefix",
                "group-seed-prefix",
                "--message",
                "group-message",
                "--label",
                "notice",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["protocol"], "group-broadcast")
        self.assertEqual(payload["label"], "notice")
        self.assertEqual(len(payload["records"]), 3)
        self.assertTrue(all("tag_hex" in record for record in payload["records"]))

    def test_comms_group_rekey(self):
        rc, output = self._run_cli(
            [
                "comms",
                "group-rekey",
                "--channel",
                "perfect",
                "--members",
                "3",
                "--group-seed-hex",
                (b"g" * 32).hex(),
                "--member-seed-prefix",
                "group-seed-prefix",
                "--add-member",
                "dave",
                "--remove-member",
                "member-3",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["protocol"], "group-rekey")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["member_ids"], ["member-1", "member-2", "dave"])
        self.assertTrue(payload["group_key_consensus"])


if __name__ == "__main__":
    unittest.main()
