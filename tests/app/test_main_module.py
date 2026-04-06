import runpy
import unittest
from unittest.mock import patch


class TestAppMainModule(unittest.TestCase):
    def test_module_entrypoint_exits_with_main_code(self):
        with patch("src.app.cli.main", return_value=0):
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_module("src.app.__main__", run_name="__main__")
        self.assertEqual(ctx.exception.code, 0)

    def test_module_import_does_not_exit(self):
        runpy.run_module("src.app.__main__", run_name="src.app.__main__")


if __name__ == "__main__":
    unittest.main()
