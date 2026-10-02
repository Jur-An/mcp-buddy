import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import mcp_buddy


class McpBuddyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.store = Path(self.temp_dir.name) / "keys.json"

    def run_cmd(self, *args):
        out = StringIO()
        with patch("sys.stdout", out):
            code = mcp_buddy.main(["--store", str(self.store), *args])
        return code, out.getvalue().strip()

    def test_set_get_reveal_and_export(self):
        code, _ = self.run_cmd("set", "cursor", "OPENAI_API_KEY", "secret")
        self.assertEqual(code, 0)

        code, output = self.run_cmd("get", "cursor", "OPENAI_API_KEY")
        self.assertEqual(code, 0)
        self.assertEqual(output, "***")

        code, output = self.run_cmd("get", "cursor", "OPENAI_API_KEY", "--reveal")
        self.assertEqual(code, 0)
        self.assertEqual(output, "secret")

        code, output = self.run_cmd("export", "cursor")
        self.assertEqual(code, 0)
        self.assertEqual(output, 'export OPENAI_API_KEY="secret"')

    def test_unset_removes_empty_service(self):
        self.run_cmd("set", "mcp", "API_KEY", "value")
        code, output = self.run_cmd("unset", "mcp", "API_KEY")
        self.assertEqual(code, 0)
        self.assertIn("Removed API_KEY", output)

        code, output = self.run_cmd("list")
        self.assertEqual(code, 0)
        self.assertEqual(output, "No keys stored.")


if __name__ == "__main__":
    unittest.main()
