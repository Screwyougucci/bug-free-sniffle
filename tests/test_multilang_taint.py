import tempfile
import unittest
from pathlib import Path
from darthscanner.multilang_taint import scan_multilang_taint

class MultiLanguageTaintTests(unittest.TestCase):
    def scan(self,suffix,source):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        path=Path(temp.name)/("app"+suffix); path.write_text(source,encoding="utf-8")
        return scan_multilang_taint(path)
    def test_javascript_request_alias_to_fetch(self):
        findings=self.scan(".js","const target = req.query.url;\nfetch(target);\n")
        self.assertTrue(any(item.cwe_ids==["CWE-918"] for item in findings))
    def test_typescript_alias_to_sql_query(self):
        findings=self.scan(".ts","const term = req.body.term;\nconst query = 'SELECT ' + term;\ndb.execute(query);\n")
        self.assertTrue(any(item.cwe_ids==["CWE-89"] for item in findings))
    def test_php_get_input_to_file_read(self):
        findings=self.scan(".php","$name = $_GET['file'];\n$content = file_get_contents($name);\n")
        self.assertTrue(any(item.cwe_ids==["CWE-22"] for item in findings))
    def test_java_parameter_to_process_builder(self):
        findings=self.scan(".java","String argument = request.getParameter('name');\nnew ProcessBuilder(argument);\n")
        self.assertTrue(any(item.cwe_ids==["CWE-78"] for item in findings))
    def test_go_query_parameter_to_http_request(self):
        findings=self.scan(".go",'target := r.URL.Query().Get("url")\nhttp.Get(target)\n')
        self.assertTrue(any(item.cwe_ids==["CWE-918"] for item in findings))
    def test_constant_operations_not_reported(self):
        findings=self.scan(".js","fetch('https://example.test/status');\ndb.query('SELECT 1');\n")
        self.assertEqual(findings,[])
    def test_unrecognized_extension_ignored(self):
        self.assertEqual(self.scan(".rs","let target = request.query;\nfetch(target);\n"),[])

if __name__=="__main__": unittest.main()
