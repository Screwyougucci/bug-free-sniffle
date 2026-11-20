import tempfile
import unittest
from pathlib import Path

from darthscanner.interprocedural_audit import audit_python_project


class InterproceduralPythonTests(unittest.TestCase):
    def test_request_input_crosses_local_helper_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler(request, db):\n"
                "    value = request.args.get('q')\n"
                "    execute_search(value, db)\n"
                "\n"
                "def execute_search(value, db):\n"
                "    db.execute(value)\n",
                encoding="utf-8",
            )
            findings = audit_python_project(root)
            self.assertTrue(any("SQL query" in item.title and item.cwe_ids == ["CWE-89"] for item in findings))

    def test_request_input_crosses_imported_helper_in_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text(
                "def run_query(value, db):\n"
                "    db.execute(value)\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from helpers import run_query\n"
                "def handler(request, db):\n"
                "    value = request.args.get('q')\n"
                "    run_query(value, db)\n",
                encoding="utf-8",
            )
            findings = audit_python_project(root)
            self.assertTrue(any(item.cwe_ids == ["CWE-89"] for item in findings))

    def test_constant_argument_does_not_cross_helper_as_tainted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def run_query(value, db):\n"
                "    db.execute(value)\n"
                "def handler(db):\n"
                "    run_query('SELECT 1', db)\n",
                encoding="utf-8",
            )
            findings = audit_python_project(root)
            self.assertFalse(any(item.cwe_ids == ["CWE-89"] for item in findings))

    def test_unrelated_same_named_helpers_are_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.py").write_text("def helper(value):\n    return value\n", encoding="utf-8")
            (root / "two.py").write_text("def helper(value):\n    return value\n", encoding="utf-8")
            (root / "app.py").write_text(
                "def handler(request):\n"
                "    value = request.args.get('q')\n"
                "    helper(value)\n",
                encoding="utf-8",
            )
            findings = audit_python_project(root)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
