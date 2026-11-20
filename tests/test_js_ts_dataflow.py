import tempfile
import unittest
from pathlib import Path

from darthscanner.analysis_graph import AnalysisGraph
from darthscanner.graph_adapters import add_multilang_file_to_graph, build_project_graph
from darthscanner.js_ts_dataflow import enrich_js_ts_dataflow


class JsTsDataflowTests(unittest.TestCase):
    def test_parameter_flows_to_sensitive_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.js"
            path.write_text("""
function runQuery(db, value) {
  db.query(value);
}
function handler(req, db) {
  const input = req.query;
  runQuery(db, input);
}
""", encoding="utf-8")
            graph = AnalysisGraph()
            add_multilang_file_to_graph(path, graph, display_path="app.js")
            enrich_js_ts_dataflow(path, graph, display_path="app.js")
            self.assertTrue(any(edge.kind == "parameter-to-sink" for edge in graph.edges))
            self.assertTrue(any(edge.kind == "call-argument" for edge in graph.edges))


    def test_project_graph_integrates_js_ts_enrichment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.ts"
            path.write_text("""
function runQuery(db: any, value: string) {
  db.query(value);
}
function handler(req: any, db: any) {
  const input = req.query;
  runQuery(db, input);
}
""", encoding="utf-8")
            graph = build_project_graph(directory)
            self.assertTrue(any(edge.kind == "parameter-to-sink" for edge in graph.edges))
            self.assertTrue(any(edge.kind == "call-argument" for edge in graph.edges))

    def test_external_function_not_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.ts"
            path.write_text("function handler(value: string) { thirdParty(value); }", encoding="utf-8")
            graph = AnalysisGraph()
            enrich_js_ts_dataflow(path, graph, display_path="app.ts")
            self.assertFalse(any(edge.kind == "call-argument" for edge in graph.edges))


if __name__ == "__main__":
    unittest.main()
