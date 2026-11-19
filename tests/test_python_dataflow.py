import tempfile
import unittest
from pathlib import Path

from darthscanner.python_dataflow import inspect_python_dataflow


class PythonDataflowTests(unittest.TestCase):
    def inspect(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.py"
            path.write_text(source, encoding="utf-8")
            return inspect_python_dataflow(path, source)

    def titles(self, findings):
        return [item.title for item in findings]

    def test_tracks_request_value_through_multiple_aliases_to_sql(self):
        findings = self.inspect(
            "def handler(request, db):\n"
            "    first = request.args.get('name')\n"
            "    second = first\n"
            "    query = 'SELECT * FROM users WHERE name=' + second\n"
            "    db.execute(query)\n"
        )
        self.assertIn("Request-derived data may reach a database query", self.titles(findings))

    def test_tracks_request_value_to_shell_api(self):
        findings = self.inspect(
            "def handler(request):\n"
            "    command = request.form['command']\n"
            "    os.system(command)\n"
        )
        self.assertIn("Request-derived data reaches a shell command API", self.titles(findings))

    def test_tracks_request_value_to_outbound_url(self):
        findings = self.inspect(
            "def handler(request):\n"
            "    destination = request.args.get('next')\n"
            "    requests.get(destination)\n"
        )
        self.assertIn("Request-derived data may reach an outbound URL", self.titles(findings))

    def test_tracks_request_value_to_file_path(self):
        findings = self.inspect(
            "def handler(request):\n"
            "    name = request.args['file']\n"
            "    open(name)\n"
        )
        self.assertIn("Request-derived data may reach a filesystem path", self.titles(findings))

    def test_does_not_flag_constant_parameterized_query(self):
        findings = self.inspect(
            "def handler(request, db):\n"
            "    value = request.args.get('name')\n"
            "    db.execute('SELECT * FROM users WHERE name = ?', (value,))\n"
        )
        self.assertNotIn("Request-derived data may reach a database query", self.titles(findings))

    def test_does_not_flag_unrelated_constant(self):
        findings = self.inspect(
            "def handler():\n"
            "    value = 'fixed'\n"
            "    os.system('fixed-command')\n"
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
