import unittest
from contextlib import redirect_stdout
from io import StringIO

from src.app import cli


class TestCliDemoComms(unittest.TestCase):
    def test_demo_comms_selection_runs_comms_demo(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(["demo", "comms"])

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("Comms Secure Key Agreement", output)
        self.assertIn("Comms Demo: Authenticated Success", output)


if __name__ == "__main__":
    unittest.main()
