import json
import tempfile
import unittest
from pathlib import Path

from darthscanner.analysis_graph import AnalysisGraph, build_python_graph


class AnalysisGraphTests(unittest.TestCase):
    def test_stable_node_ids_and_deduplicated_edges(self):
        graph = AnalysisGraph()
        a = graph.add_node("source", "request", path="app.py", line=2)
        b = graph.add_node("sink", "execute", path="app.py", line=8, cwe="CWE-89")
        self.assertEqual(a, graph.add_node("source", "request", path="app.py", line=2))
        self.assertTrue(graph.add_edge(a, b))
        self.assertTrue(graph.add_edge(a, b))
        self.assertEqual(1, len(graph.edges))

    def test_bounded_path_and_serialization(self):
        graph = AnalysisGraph(max_nodes=3, max_edges=3)
        a = graph.add_node("source", "input")
        b = graph.add_node("transform", "value")
        c = graph.add_node("sink", "execute", cwe="CWE-89")
        graph.add_edge(a, b)
        graph.add_edge(b, c)
        self.assertEqual(["input", "value", "execute"],
                         [node.label for node in graph.paths()[0]])
        self.assertEqual(1, json.loads(graph.to_json())["schema_version"])
        graph.add_node("extra", "overflow")
        self.assertTrue(graph.truncated)

    def test_python_request_to_sql_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.py"
            path.write_text("""
def handler(request, db):
    value = request.args.get("q")
    db.execute(value)
""", encoding="utf-8")
            graph = build_python_graph(path)
            paths = graph.paths()
            self.assertTrue(any(item[-1].cwe == "CWE-89" for item in paths), graph.to_dict())

    def test_constant_query_does_not_create_source_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.py"
            path.write_text("""
def handler(db):
    value = "SELECT 1"
    db.execute(value)
""", encoding="utf-8")
            self.assertEqual([], build_python_graph(path).paths())

    def test_cycle_does_not_loop(self):
        graph = AnalysisGraph()
        a = graph.add_node("source", "input")
        b = graph.add_node("transform", "alias")
        c = graph.add_node("sink", "sink")
        graph.add_edge(a, b)
        graph.add_edge(b, a)
        graph.add_edge(b, c)
        self.assertEqual(1, len(graph.paths(max_depth=10)))


if __name__ == "__main__":
    unittest.main()
