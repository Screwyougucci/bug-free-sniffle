import tempfile
import unittest
from pathlib import Path

from darthscanner.analysis_graph import AnalysisGraph, build_python_graph
from darthscanner.deep_dataflow import enrich_python_dataflow
from darthscanner.graph_adapters import build_project_graph


class DeepDataflowTests(unittest.TestCase):
    def write(self, root, name, source):
        path = Path(root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_cross_function_argument_and_return_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "app.py", """
def execute_query(db, value):
    db.execute(value)
    return value

def handler(request, db):
    incoming = request.args.get("q")
    result = execute_query(db, incoming)
    return result
""")
            graph = build_project_graph(directory)
            self.assertTrue(any(edge.kind == "call-argument" for edge in graph.edges))
            self.assertTrue(any(edge.kind == "call-return" for edge in graph.edges))

    def test_local_import_alias_is_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "helpers.py", """
def forward(value):
    return value
""")
            self.write(directory, "app.py", """
from helpers import forward as pass_through

def handler(request):
    incoming = request.args.get("q")
    result = pass_through(incoming)
    return result
""")
            graph = build_project_graph(directory)
            self.assertTrue(any(edge.kind == "call-argument" for edge in graph.edges))

    def test_property_write_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "app.py", """
def handler(request, obj):
    incoming = request.args.get("q")
    obj.value = incoming
""")
            graph = AnalysisGraph()
            from darthscanner.analysis_graph import build_python_graph
            build_python_graph(directory)
            graph = build_project_graph(directory)
            self.assertTrue(any(node.metadata.get("analysis") == "object-property"
                                for node in graph.nodes.values()))

    def test_parameter_to_sink_path_is_connected(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "app.py", """
def run_query(db, value):
    db.execute(value)

def handler(request, db):
    incoming = request.args.get("q")
    run_query(db, incoming)
""")
            graph = build_project_graph(directory)
            self.assertTrue(any(edge.kind == "parameter-to-sink" for edge in graph.edges))

    def test_unresolved_external_call_does_not_create_call_edge(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, "app.py", """
def handler(value):
    return third_party(value)
""")
            graph = build_project_graph(directory)
            self.assertFalse(any(edge.kind in {"call-argument", "call-return"}
                                 for edge in graph.edges))


if __name__ == "__main__":
    unittest.main()
