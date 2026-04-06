import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

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


if __name__ == "__main__":
    unittest.main()
