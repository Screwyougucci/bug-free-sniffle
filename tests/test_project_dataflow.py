import tempfile
import unittest
from pathlib import Path

from darthscanner.project_dataflow import scan_project_cross_function


class CrossLanguageProjectFlowTests(unittest.TestCase):
    def _check(self, suffix, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("sample" + suffix)
            path.write_text(source, encoding="utf-8")
            findings = scan_project_cross_function(path)
            self.assertTrue(any("CWE-89" in item.cwe_ids for item in findings), findings)

    def test_javascript_helper_flow_and_branch_assignment(self):
        self._check(".js", """
function handler(req, db) {
  let value;
  if (req.query.q) {
    value = req.query.q;
  } else {
    value = "safe";
  }
  runQuery(value, db);
}
function runQuery(value, db) {
  db.execute(value);
}
""")

    def test_typescript_typed_helper_parameter(self):
        self._check(".ts", """
function handler(req: Request, db: DB) {
  const value = req.query.q;
  runQuery(value, db);
}
function runQuery(value: string, db: DB) {
  db.execute(value);
}
""")

    def test_php_helper_flow(self):
        self._check(".php", """<?php
function handler($request, $db) {
  $value = $_GET['q'];
  runQuery($value, $db);
}
function runQuery($value, $db) {
  $db->execute($value);
}
""")

    def test_java_helper_flow(self):
        self._check(".java", """
class App {
  public void handler(Request req, DB db) {
    String value = req.getParameter("q");
    runQuery(value, db);
  }
  public void runQuery(String value, DB db) {
    db.execute(value);
  }
}
""")

    def test_go_helper_flow(self):
        self._check(".go", """
func handler(w http.ResponseWriter, r *http.Request, db *DB) {
  value := r.FormValue("q")
  runQuery(value, db)
}
func runQuery(value string, db *DB) {
  db.Exec(value)
}
""")

    def test_constant_argument_is_not_tainted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.js"
            path.write_text("""
function handler(db) {
  runQuery("SELECT 1", db);
}
function runQuery(value, db) {
  db.execute(value);
}
""", encoding="utf-8")
            findings = scan_project_cross_function(path)
            self.assertFalse(any("CWE-89" in item.cwe_ids for item in findings), findings)


if __name__ == "__main__":
    unittest.main()
