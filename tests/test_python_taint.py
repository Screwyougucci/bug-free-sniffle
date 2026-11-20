import tempfile
import unittest
from pathlib import Path
from darthscanner.polyglot_audit import audit_source

class PythonTaintResearchTests(unittest.TestCase):
    def audit(self,source):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        path=Path(temp.name)/"app.py"; path.write_text(source,encoding="utf-8")
        return audit_source(path)[0]
    def test_tracks_request_alias_into_sql_query(self):
        findings=self.audit("def search(request, db):\n    term = request.args.get('q')\n    query = 'SELECT * FROM users WHERE name=' + term\n    db.execute(query)\n")
        self.assertTrue(any(item.cwe_ids==["CWE-89"] and "SQL query argument" in item.title for item in findings))
    def test_tracks_request_alias_into_outbound_http_request(self):
        findings=self.audit("def proxy(request):\n    destination = request.args.get('url')\n    requests.get(destination)\n")
        self.assertTrue(any(item.cwe_ids==["CWE-918"] for item in findings))
    def test_tracks_request_alias_into_file_open(self):
        findings=self.audit("def download(request):\n    name = request.GET.get('file')\n    open(name, 'rb')\n")
        self.assertTrue(any(item.cwe_ids==["CWE-22"] for item in findings))
    def test_tracks_request_alias_into_process_api(self):
        findings=self.audit("def run(request):\n    argument = request.form.get('name')\n    subprocess.run(['tool', argument])\n")
        self.assertTrue(any(item.cwe_ids==["CWE-78"] for item in findings))
    def test_tracks_request_input_into_dynamic_template(self):
        findings=self.audit("def render(request):\n    template = request.args.get('template')\n    render_template_string(template)\n")
        self.assertTrue(any(item.cwe_ids==["CWE-94"] for item in findings))
    def test_tracks_request_input_into_unsafe_deserializer(self):
        findings=self.audit("def load(request):\n    blob = request.data\n    pickle.loads(blob)\n")
        self.assertTrue(any(item.cwe_ids==["CWE-502"] and "Request-derived" in item.title for item in findings))
    def test_does_not_flag_constant_sql_or_constant_url(self):
        findings=self.audit("def safe(db):\n    db.execute('SELECT * FROM users WHERE id = ?', (42,))\n    requests.get('https://example.test/status')\n")
        flow_titles={"Request-derived data reaches a SQL query argument","Request-derived data reaches an outbound HTTP request"}
        self.assertFalse(any(item.title in flow_titles for item in findings))

if __name__=="__main__": unittest.main()
