import tempfile
import unittest
from pathlib import Path

from darthscanner.analysis_graph import AnalysisGraph
from darthscanner.graph_adapters import add_multilang_file_to_graph, build_project_graph


class MultiLanguageGraphAdapterTests(unittest.TestCase):
    def write(self, directory, name, source):
        path = Path(directory) / name
        path.write_text(source, encoding="utf-8")
        return path

    def test_javascript_source_alias_to_ssrf_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, "app.js",
                              "const first = req.query.url;\nconst target = first;\nfetch(target);\n")
            graph = AnalysisGraph()
            count = add_multilang_file_to_graph(path, graph, display_path="app.js")
            self.assertEqual(1, count)
            paths = graph.paths()
            self.assertTrue(any(path[-1].cwe == "CWE-918" for path in paths), graph.to_dict())
            self.assertTrue(all(node.path == "app.js" for path in paths for node in path))

    def test_php_input_to_file_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, "app.php",
                              "$name = $_GET['file'];\n$content = file_get_contents($name);\n")
            graph = AnalysisGraph()
            add_multilang_file_to_graph(path, graph)
            self.assertTrue(any(path[-1].cwe == "CWE-22" for path in graph.paths()))

    def test_constant_call_does_not_create_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, "app.ts", "fetch('https://example.test');\n")
            graph = AnalysisGraph()
            self.assertEqual(0, add_multilang_file_to_graph(path, graph))
            self.assertEqual([], graph.paths())

    def test_project_graph_combines_python_and_javascript(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "app.py",
                       "def handler(request, db):\n    value = request.args.get('q')\n    db.execute(value)\n")
            self.write(directory, "app.js",
                       "const url = req.query.url;\nfetch(url);\n")
            graph = build_project_graph(directory)
            languages = {node.language for node in graph.nodes.values()}
            self.assertIn("python", languages)
            self.assertIn("js", languages)
            cwes = {node.cwe for node in graph.nodes.values() if node.kind == "sink"}
            self.assertTrue({"CWE-89", "CWE-918"}.issubset(cwes))

    def test_file_limit_is_reported_as_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "one.js", "const x = req.query.x;\nfetch(x);\n")
            self.write(directory, "two.go", 'x := r.URL.Query().Get("x")\nhttp.Get(x)\n')
            graph = build_project_graph(directory, max_files=1)
            self.assertTrue(graph.truncated)


if __name__ == "__main__":
    unittest.main()
