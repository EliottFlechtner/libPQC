import unittest
from contextlib import redirect_stdout
from io import StringIO

from src.app import cli


class TestCliDemoCommsGroup(unittest.TestCase):
    def test_demo_comms_group_selection_runs_group_demo(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(["demo", "comms-group"])

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("Comms Group Demo: Group Session Utilities", output)
        self.assertIn("Broadcast verified:", output)
        self.assertIn("Rekey session success:", output)


if __name__ == "__main__":
    unittest.main()
